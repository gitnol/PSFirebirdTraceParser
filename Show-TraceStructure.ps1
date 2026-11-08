<#
.SYNOPSIS
    High-Performance Firebird Trace Parser (streaming, Regex Block Mode)

.DESCRIPTION
    Reads a Firebird trace log line by line, groups the lines of each event (a block starts with a
    timestamp line) and writes one object per event to the pipeline as soon as the block is complete.
    Memory use does not grow with the file size (I6).

    Field Mapping:
    - TransactionOptions: From TRA_ line (READ_COMMITTED...)
    - Params: From param0 = ... lines
    - SqlStatement: Stops at separators (^^^^, PLAN, param, records)
    - SqlPlan: PLAN (...) lines; TableStats: table statistics block
    - ErrorSource/ErrorCodes/ErrorMessages: ERROR AT / WARNING AT events
    - ServiceName/ServiceID: *_SERVICE events (log_services); user, address and program go to the usual fields
    - SweepOIT/SweepOAT/SweepOST/SweepNext: transaction counters of SWEEP_START / SWEEP_FINISH (log_sweep)
    - RecordsFetched: "N records fetched" (rows; Fetches are page fetches)
    - TxIsolation/TxReadMode/TxWaitMode/TxLockTimeout/TxAccessMode: parts of TransactionOptions
    - TableCounts: TableStats as one object per table (Table, Natural, Index, Update, Insert, Delete, Backout, Purge, Expunge)
    - RoutineType/RoutineName: procedure, function or trigger of EXECUTE_*/COMPILE_* events
    - TriggerTable/TriggerTime/TriggerEvent: trigger line (Firebird 4 and 5 formats)
    - ConnectionDurationMs: DETACH_DATABASE, time since ATTACH_DATABASE of the same connection in this file

    Status messages go to the verbose stream (-Verbose), not to the console.

.OUTPUTS
    [PSCustomObject] - one per trace event, streamed
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    # Upper limit of lines per block; a longer block is cut to this many lines (warning). Protects memory.
    [ValidateRange(1, 2147483647)]
    [int]$MaxBlockLines = 100000,

    # Time limit per regex evaluation in a block; when reached, the remaining fields stay empty (warning).
    [ValidateRange(0.001, 3600)]
    [double]$RegexTimeoutSeconds = 2,

    # Parser: Auto = C# (FirebirdTraceParser.dll next to the script or in bin/) under PowerShell 7, else PowerShell (ADR-003)
    [ValidateSet('Auto', 'PowerShell', 'CSharp')]
    [string]$Engine = 'Auto'
)

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Error "File not found: $Path"
    return
}

# Contract stub (I19): always the PowerShell parser, -Engine is not evaluated yet
$null = $Engine
Write-Verbose 'Engine: PowerShell'

$sw = [System.Diagnostics.Stopwatch]::StartNew()
# Time limit per match of the block regexes (I13). The chunk splitter below has none: it is anchored and linear.
$script:RegexTimeout = [TimeSpan]::FromSeconds($RegexTimeoutSeconds)
Write-Verbose "Streaming analysis started: $Path"


# 3. Regex Definitions
# Header
# Firebird writes the address with printf("%p"), which is platform dependent:
# Windows (MSVC) "000001A2B3C4D5E0", Linux (glibc) "0x7f3a1c2b4d10". Accept both.
$rxHeader = [System.Text.RegularExpressions.Regex]::new(
    # Action keeps the full event name ("FAILED EXECUTE_STATEMENT_FINISH"); for "ERROR AT <component>" /
    # "WARNING AT <component>" Action is ERROR/WARNING and the component goes to ErrorSource.
    '^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>(?:0x)?[0-9A-Fa-f]+)\)\s+(?<Action>(?:(?:FAILED|UNAUTHORIZED)\s+)?\S+)(?:\s+AT\s+(?<ErrorSource>\S+))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Error/warning lines: "%9lu : <text>" (Firebird TraceStatusVectorImpl::getText)
$rxErrorLine = [System.Text.RegularExpressions.Regex]::new(
    '^\s*(?<Code>\d{1,10})\s:\s(?<Message>.*?)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# DB (Include IP/Port)
# Connection line: "<db path> (ATT_n, USER:ROLE, charset, <protocol info>)"
# Protocol info: "TCPv4:192.0.2.10/50123", "TCPv6:2001:db8::10/50123", "XNET:HOST" (no port) or "<internal>".
# Any database file name/extension and any role (K3).
$rxDb = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DatabasePath>\S.*?)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>[^,]+),\s+(?<Encoding>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>[A-Za-z0-9]+):(?<IPAddress>[^/)]+)(?:/(?<Port>\d+))?|<[^>]+>)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# App (Exclude ATT match)
$rxApp = [System.Text.RegularExpressions.Regex]::new(
    '(?im)^\s+(?!.*\(ATT_)(?<ApplicationPath>(?:[a-z]:|\\\\).+?):(?<ApplicationPID>\d+)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Transaction (TRA_ID, Init, Options)
$rxTx = [System.Text.RegularExpressions.Regex]::new(
    '^\s+\(TRA_(?<TransactionID>\d+)(?:,\s+INIT_(?<InitID>\d+))?,\s+(?<TxOpts>.+?)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# SQL Statement
# Stops at: ^^^^, PLAN (, paramX, records fetched, or X ms
$rxSql = [System.Text.RegularExpressions.Regex]::new(
    'Statement\s+\d+:\s*[\r\n]+(?:-{3,}[\r\n]+)(?<SqlStatement>.+?)(?=(?m)[\r\n]+\s*(\^{4,}|PLAN \(|param\d+|[0-9]+\s+records? fetched|\d+\s+ms|Table\s+Natural))',
    [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# SQL Plan (PLAN ...)
$rxPlan = [System.Text.RegularExpressions.Regex]::new(
    '(?<SqlPlan>(?:^\s*PLAN\b.*[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Table Stats (Treat as part of Plan or separate)
# Matches "Table ... Natural ... ******* ... rows"
$rxTableStats = [System.Text.RegularExpressions.Regex]::new(
    '(?<TableStats>Table\s+Natural.+?[\r\n]+\*+[\r\n]+(?:.+[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)
# Fixed-Width data parsing logic is separate, but regex is needed for detection.

# Service line (log_services): "service_mgr, (Service <address>, <user>, <protocol:address>[, <process>:<pid>])"
# Firebird 5 TracePluginImpl::register_service; the address may be "internal" or a protocol without address.
$rxService = [System.Text.RegularExpressions.Regex]::new(
    '^\s+service_mgr,\s+\(Service\s+(?<ServiceID>(?:0x)?[0-9A-Fa-f]+),\s+(?<User>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>[A-Za-z0-9]+):(?<IPAddress>[^/,)]+)(?:/(?<Port>\d+))?|[^,)]+)(?:,\s+(?<ApplicationPath>.+):(?<ApplicationPID>\d+))?\)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)
# Service name in quotes, e.g. "Backup Database", "Incremental Backup Database". The switches line below it holds
# file paths and is deliberately not read (it would need its own pseudonymization).
$rxServiceName = [System.Text.RegularExpressions.Regex]::new(
    '^\s+"(?<ServiceName>[^"
]+)"\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Sweep transaction counters (log_sweep; only SWEEP_START and SWEEP_FINISH print them)
$rxSweep = [System.Text.RegularExpressions.Regex]::new(
    '^\s*Oldest interesting\s+(?<OIT>\d+)\s*
\s*Oldest active\s+(?<OAT>\d+)\s*
\s*Oldest snapshot\s+(?<OST>\d+)\s*
\s*Next transaction\s+(?<Next>\d+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Procedures and functions: "Procedure <name>:" / "Function <name>:" on a line of their own
# (Firebird 4 logRecordProcFunc, Firebird 5 logRecordProc/logRecordFunc; Firebird 5 may put a plan below it)
$rxRoutine = [System.Text.RegularExpressions.Regex]::new(
    '^(?<Type>Procedure|Function) (?<Name>.+?):[ \t]*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)
# Triggers. Firebird 5 (logRecordTrig): "Trigger[ <name>][ FOR <table>] (<when> <action>):" on a line of its own.
# Firebird 4 (log_event_trigger_execute): "<TAB><name>[ FOR <table>] (<when> <action>) " below the transaction line,
# "<unknown>" when the trigger has no name. <when>: BEFORE, AFTER, ON (database trigger, no table) or <unknown>.
$rxTrigger = [System.Text.RegularExpressions.Regex]::new(
    '^(?:Trigger(?: (?<Name>.+?))?|[ \t]+(?<Name>.+?))(?: FOR (?<Table>.+?))? \((?<Time>BEFORE|AFTER|ON|<unknown>) (?<Event>[^)]+)\):?[ \t]*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# SQL Params (param0 = ...)
$rxParams = [System.Text.RegularExpressions.Regex]::new(
    '(?<Params>(?:^\s*param\d+\s*=\s*.+[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)

# Performance
$rxPerf = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DurationMs>\d+)\s+ms(?:,\s+(?<Reads>\d+)\s+read\(s\))?(?:,\s+(?<Writes>\d+)\s+write\(s\))?(?:,\s+(?<Fetches>\d+)\s+fetch\(es\))?(?:,\s+(?<Marks>\d+)\s+mark\(s\))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled, $script:RegexTimeout
)


# Rows read by the statement: "1234 records fetched" on a line of its own (Firebird prints it for statements always,
# for procedures and functions only when not 0). Not the same as Fetches (page fetches of the performance line).
$script:RECORDS_FETCHED = ' records fetched'
$script:Ordinal = [System.StringComparison]::Ordinal       # type literals resolved once, not per block
$script:DigitsOnly = [System.Globalization.NumberStyles]::None

# Open connections for ConnectionDurationMs: "<database>|<ATT number>" -> time of ATTACH_DATABASE/CREATE_DATABASE.
# Holds only connections without DETACH so far, so memory grows with open connections, not with the file size.
$script:OpenAttach = [System.Collections.Generic.Dictionary[string, datetime]]::new()
$script:Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$script:TIMESTAMP_FORMAT = 'yyyy-MM-ddTHH:mm:ss.FFFFFFF'

$script:TABLE_CELL_WIDTH = 10
$script:Utf8 = [System.Text.UTF8Encoding]::new($false)

# Parts of the transaction line (Firebird TracePluginImpl::register_transaction) -> field; "WAIT <n>" is a lock timeout.
$script:TX_OPTION_FIELD = @{
    'READ_COMMITTED' = 'TxIsolation'; 'CONCURRENCY' = 'TxIsolation'; 'CONSISTENCY' = 'TxIsolation'; '<unknown>' = 'TxIsolation'
    'REC_VERSION' = 'TxReadMode'; 'NO_REC_VERSION' = 'TxReadMode'; 'READ_CONSISTENCY' = 'TxReadMode'
    'WAIT' = 'TxWaitMode'; 'NOWAIT' = 'TxWaitMode'
    'READ_WRITE' = 'TxAccessMode'; 'READ_ONLY' = 'TxAccessMode'
}

function ConvertFrom-TableStat {
    # Table statistics -> one object per table. Firebird (appendTableCounts) pads the name column to
    # max(32, longest name in bytes) (Firebird 3: fixed 31) and writes each counter right-aligned in 10 characters,
    # 0 as blanks. The name column width is read from the header ("Natural" ends 10 characters after it).
    # Non-ASCII names are padded by bytes, so the cells start earlier in characters. A name longer than the
    # column shifts all numbers to the right.
    param([string]$TableStats)
    $lines = $TableStats.Split("`n")
    $nameWidth = $lines[0].IndexOf('Natural') + 'Natural'.Length - $script:TABLE_CELL_WIDTH
    if ($nameWidth -le 0) { return $null }
    $rows = [System.Collections.Generic.List[object]]::new()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Length -eq 0 -or $line[0] -eq '*') { continue }
        $head = $line.Substring(0, [Math]::Min($nameWidth, $line.Length))
        $cellStart = $nameWidth - ($script:Utf8.GetByteCount($head) - $head.Length)
        $space = $line.IndexOf(' ')
        $token = if ($space -lt 0) { $line } else { $line.Substring(0, $space) }
        if ($token.Length -gt $cellStart) {
            # Longer than the column - unless the rest is one full cell (name fills the column, 10-digit number)
            $rest = $token.Substring($cellStart)
            if (-not ($rest.Length -eq $script:TABLE_CELL_WIDTH -and $rest -match '^\d+$')) { $cellStart = $token.Length }
        }
        # 8 cells of 10 characters. Pad once (editors may trim the trailing blanks); a blank cell is 0 ('0' + '', Windows
        # PowerShell 5.1 cannot cast blanks). Unrolled on
        # purpose: a PowerShell loop over the columns was about 6 times slower (measured, 6000 rows).
        $c = $line.PadRight($cellStart + 80)
        try {
            $rows.Add([PSCustomObject]@{
                    Table = $line.Substring(0, [Math]::Min($cellStart, $line.Length)).Trim()
                    Natural = [long]('0' + $c.Substring($cellStart, 10).Trim()); Index = [long]('0' + $c.Substring($cellStart + 10, 10).Trim())
                    Update = [long]('0' + $c.Substring($cellStart + 20, 10).Trim()); Insert = [long]('0' + $c.Substring($cellStart + 30, 10).Trim())
                    Delete = [long]('0' + $c.Substring($cellStart + 40, 10).Trim()); Backout = [long]('0' + $c.Substring($cellStart + 50, 10).Trim())
                    Purge = [long]('0' + $c.Substring($cellStart + 60, 10).Trim()); Expunge = [long]('0' + $c.Substring($cellStart + 70, 10).Trim())
                })
        }
        catch {
            Write-Verbose "Table statistics: row $i not readable, skipped"
        }
    }
    if ($rows.Count -eq 0) { return $null }
    return , $rows.ToArray()
}

# Line numbers for warnings (I13), computed only when a warning is written. $script:LineBase is the line number of
# $text[0]; when lines were dropped from an oversized carry, positions from $script:ShiftFrom on lie $script:Shift lines
# further down in the file. The last result is cached, so many warnings in one chunk stay linear.
$script:LineBase = 1
$script:ShiftFrom = [int]::MaxValue
$script:Shift = 0
$script:LnText = $null; $script:LnIndex = 0; $script:LnCount = 0
$script:WarningCount = 0
$script:ActionCount = @{}

function Measure-Newline([string]$Text, [int]$From, [int]$To) {
    $part = $Text.Substring($From, $To - $From)
    return $part.Length - $part.Replace("`n", '').Length
}

function Get-LineEnd([string]$Text, [int]$Lines) {
    # Index after the n-th line break, or -1 if the text has fewer line breaks
    $pos = -1
    for ($k = 0; $k -lt $Lines; $k++) {
        $pos = $Text.IndexOf("`n", $pos + 1)
        if ($pos -lt 0) { return -1 }
    }
    return $pos + 1
}

function Write-BlockWarning([string]$Text, [int]$Start, [string]$Message) {
    if (-not [object]::ReferenceEquals($Text, $script:LnText) -or $Start -lt $script:LnIndex) {
        $script:LnText = $Text; $script:LnIndex = 0; $script:LnCount = 0
    }
    $script:LnCount += Measure-Newline -Text $Text -From $script:LnIndex -To $Start
    $script:LnIndex = $Start
    $line = $script:LineBase + $script:LnCount
    if ($Start -ge $script:ShiftFrom) { $line += $script:Shift }
    $script:WarningCount++
    Write-Warning "Line ${line}: $Message"
}

function Test-Preamble([string]$Text) {
    # Text before the first event: empty lines and the start line of fbtracemgr are expected, anything else is reported
    $lines = $Text.Split("`n")
    for ($k = 0; $k -lt $lines.Count; $k++) {
        if ($lines[$k].Trim().Length -gt 0 -and $lines[$k] -notmatch '^Trace session ID \d+ started\s*$') {
            $script:WarningCount++
            Write-Warning "Line $($script:LineBase + $k): text before the first event skipped"
            return
        }
    }
}

# 4. Block parsing (one trace event -> one object)
function ConvertFrom-TraceBlock {
    # One block = $Text.Substring($Start, $Length). Writes the object to the pipeline and diagnostics to the warning
    # stream (line number and fixed texts only, never trace content). $Cut: lines of this block were already dropped
    # while it was carried over several chunks.
    param([string]$Text, [int]$Start, [int]$Length, [bool]$Cut)

    $block = $Text.Substring($Start, $Length)
    # Cheap pre-check: a block with more than MaxBlockLines lines has at least that many characters
    if ($Cut -or $Length -gt $MaxBlockLines) {
        $end = Get-LineEnd -Text $block -Lines $MaxBlockLines
        if ($Cut -or ($end -gt 0 -and $end -lt $block.Length)) {
            if ($end -gt 0) { $block = $block.Substring(0, $end) }
            Write-BlockWarning -Text $Text -Start $Start -Message "event has more than $MaxBlockLines lines, only the first $MaxBlockLines read (-MaxBlockLines)"
        }
    }

    # Init Object
    $entry = [ordered]@{
        Timestamp = $null; Action = $null; ProcessID = $null; SessionID = $null;
        DatabasePath = $null; AttachID = $null; User = $null; ProtocolInfo = $null;
        ClientIP = $null; ClientPort = $null;
        ApplicationPath = $null; ApplicationPID = $null;
        TransactionID = $null; RootTxID = "NoTx"; TransactionOptions = $null;
        Params = $null; # SQL Params
        SqlStatement = $null; SqlPlan = $null;
        TableStats = $null; # New field for Table Statistics
        DurationMs = [long]0; Reads = [long]0; Writes = [long]0; Fetches = [long]0; Marks = [long]0;
        ErrorSource = $null; ErrorCodes = $null; ErrorMessages = $null; # ERROR AT / WARNING AT
        ServiceName = $null; ServiceID = $null; # *_SERVICE events
        SweepOIT = $null; SweepOAT = $null; SweepOST = $null; SweepNext = $null; # SWEEP_START / SWEEP_FINISH
        RecordsFetched = [long]0; # "N records fetched" (rows), not the page fetches in Fetches
        TxIsolation = $null; TxReadMode = $null; TxWaitMode = $null; TxLockTimeout = $null; TxAccessMode = $null; # from TransactionOptions
        TableCounts = $null; # TableStats as one object per table
        RoutineType = $null; RoutineName = $null; # EXECUTE_PROCEDURE/FUNCTION/TRIGGER events
        TriggerTable = $null; TriggerTime = $null; TriggerEvent = $null; # trigger line
        ConnectionDurationMs = $null; # DETACH_DATABASE: time since ATTACH_DATABASE of the same connection
    }

    try {
        # --- Header ---
        $m = $rxHeader.Match($block)
        if ($m.Success) {
            $entry.Timestamp = $m.Groups['Timestamp'].Value
            $entry.Action = $m.Groups['Action'].Value
            $entry.ProcessID = $m.Groups['ProcessID'].Value
            $entry.SessionID = $m.Groups['SessionID'].Value
            if ($m.Groups['ErrorSource'].Success) { $entry.ErrorSource = $m.Groups['ErrorSource'].Value }
        }

        # --- Error / warning lines (only for ERROR AT / WARNING AT blocks) ---
        if ($entry.Action -eq 'ERROR' -or $entry.Action -eq 'WARNING') {
            $codes = [System.Collections.Generic.List[string]]::new()
            $messages = [System.Collections.Generic.List[string]]::new()
            foreach ($em in $rxErrorLine.Matches($block)) {
                $codes.Add($em.Groups['Code'].Value)
                $messages.Add($em.Groups['Message'].Value)
            }
            if ($codes.Count -gt 0) {
                $entry.ErrorCodes = $codes -join ', '
                $entry.ErrorMessages = $messages -join ' | '
            }
        }

        # --- DB ---
        $m = $rxDb.Match($block)
        if ($m.Success) {
            $entry.DatabasePath = $m.Groups['DatabasePath'].Value
            $entry.AttachID = $m.Groups['AttachID'].Value
            $entry.User = $m.Groups['User'].Value
            $entry.ProtocolInfo = $m.Groups['ProtocolInfo'].Value
            $entry.ClientIP = $m.Groups['IPAddress'].Value
            $entry.ClientPort = $m.Groups['Port'].Value
        }

        # --- App ---
        $m = $rxApp.Match($block)
        if ($m.Success) {
            $entry.ApplicationPath = $m.Groups['ApplicationPath'].Value
            $entry.ApplicationPID = $m.Groups['ApplicationPID'].Value
        }

        # Statement events (most blocks) carry neither a connection end nor a routine: skip both checks for them
        $hasStatement = $block.Contains('Statement ')
        $action = $entry.Action
        if ($action -and -not $hasStatement) {
            if ($action.EndsWith('_DATABASE')) {
                # --- Connection duration: ATTACH_DATABASE -> DETACH_DATABASE of the same database and ATT number ---
                $stamp = [datetime]::MinValue
                if ($entry.AttachID -and [datetime]::TryParseExact($entry.Timestamp, $script:TIMESTAMP_FORMAT, $script:Invariant, 'None', [ref]$stamp)) {
                    $key = $entry.DatabasePath + '|' + $entry.AttachID
                    if ($action -eq 'ATTACH_DATABASE' -or $action -eq 'CREATE_DATABASE') { $script:OpenAttach[$key] = $stamp }
                    elseif ($action -eq 'DETACH_DATABASE' -and $script:OpenAttach.ContainsKey($key)) {
                        $entry.ConnectionDurationMs = [long][Math]::Round(($stamp - $script:OpenAttach[$key]).TotalMilliseconds)
                        $null = $script:OpenAttach.Remove($key)
                    }
                }
            }
            elseif ($action.Contains('TRIGGER')) {
                # --- Trigger (EXECUTE_TRIGGER_*, COMPILE_TRIGGER, also FAILED/UNAUTHORIZED) ---
                $m = $rxTrigger.Match($block)
                if ($m.Success) {
                    $entry.RoutineType = 'Trigger'
                    $name = $m.Groups['Name'].Value
                    if ($name -and $name -ne '<unknown>') { $entry.RoutineName = $name }
                    if ($m.Groups['Table'].Success) { $entry.TriggerTable = $m.Groups['Table'].Value }
                    $entry.TriggerTime = $m.Groups['Time'].Value
                    $entry.TriggerEvent = $m.Groups['Event'].Value
                }
            }
            elseif ($action.Contains('PROCEDURE') -or $action.Contains('FUNCTION')) {
                # --- Procedure / function ---
                $m = $rxRoutine.Match($block)
                if ($m.Success) {
                    $entry.RoutineType = $m.Groups['Type'].Value
                    $entry.RoutineName = $m.Groups['Name'].Value
                }
            }
        }

        # --- Service (ATTACH/START/QUERY/DETACH_SERVICE): fills the same connection fields as the DB line ---
        if ($entry.Action -and $entry.Action.EndsWith('_SERVICE')) {
            $m = $rxService.Match($block)
            if ($m.Success) {
                $entry.ServiceID = $m.Groups['ServiceID'].Value
                $entry.User = $m.Groups['User'].Value
                $entry.ProtocolInfo = $m.Groups['ProtocolInfo'].Value
                if ($m.Groups['IPAddress'].Success) { $entry.ClientIP = $m.Groups['IPAddress'].Value }
                if ($m.Groups['Port'].Success) { $entry.ClientPort = $m.Groups['Port'].Value }
                if ($m.Groups['ApplicationPath'].Success) {
                    $entry.ApplicationPath = $m.Groups['ApplicationPath'].Value
                    $entry.ApplicationPID = $m.Groups['ApplicationPID'].Value
                }
            }
            $m = $rxServiceName.Match($block)
            if ($m.Success) { $entry.ServiceName = $m.Groups['ServiceName'].Value }
        }

        # --- Sweep counters ---
        if ($block.Contains('Transaction counters')) {
            $m = $rxSweep.Match($block)
            if ($m.Success) {
                $entry.SweepOIT = [long]$m.Groups['OIT'].Value
                $entry.SweepOAT = [long]$m.Groups['OAT'].Value
                $entry.SweepOST = [long]$m.Groups['OST'].Value
                $entry.SweepNext = [long]$m.Groups['Next'].Value
            }
        }

        # --- Tx ---
        $m = $rxTx.Match($block)
        if ($m.Success) {
            $entry.TransactionID = $m.Groups['TransactionID'].Value
            $initID = $m.Groups['InitID'].Value
            $entry.TransactionOptions = $m.Groups['TxOpts'].Value
            # "READ_COMMITTED | REC_VERSION | WAIT 10 | READ_WRITE" -> separate fields (inline: cheaper than a function call)
            foreach ($part in $entry.TransactionOptions.Split('|')) {
                $p = $part.Trim()
                $field = $script:TX_OPTION_FIELD[$p]
                if ($field) { $entry[$field] = $p }
                elseif ($p.StartsWith('WAIT ')) {
                    $timeout = 0
                    if ([int]::TryParse($p.Substring(5), [ref]$timeout)) { $entry.TxWaitMode = 'WAIT'; $entry.TxLockTimeout = $timeout }
                }
            }
        
            if (-not [string]::IsNullOrWhiteSpace($initID)) { $entry.RootTxID = $initID }
            elseif (-not [string]::IsNullOrWhiteSpace($entry.TransactionID)) { $entry.RootTxID = $entry.TransactionID }
        }

        # --- SQL ---
        # Cheap pre-check ($hasStatement above): most events (transactions, attach/detach) have no statement part
        $m = if ($hasStatement) { $rxSql.Match($block) } else { [System.Text.RegularExpressions.Match]::Empty }
        if ($m.Success) {
            # Trim whitespace AND separator lines like --- if they slipped in
            $entry.SqlStatement = $m.Groups['SqlStatement'].Value.Trim()
        }

        # --- Params ---
        $m = if ($block.Contains('param')) { $rxParams.Match($block) } else { [System.Text.RegularExpressions.Match]::Empty }
        if ($m.Success) {
            $entry.Params = $m.Groups['Params'].Value.Trim()
        }

        # --- Plan ---
        $m = if ($block.Contains('PLAN')) { $rxPlan.Match($block) } else { [System.Text.RegularExpressions.Match]::Empty }
        if ($m.Success) {
            $entry.SqlPlan = $m.Groups['SqlPlan'].Value.Trim()
        }
    
        # --- Table Stats (Separate Column) ---
        $m = if ($block.Contains('Natural')) { $rxTableStats.Match($block) } else { [System.Text.RegularExpressions.Match]::Empty }
        if ($m.Success) {
            $entry.TableStats = $m.Groups['TableStats'].Value # NO TRIM to preserve column alignment
            $entry.TableCounts = ConvertFrom-TableStat -TableStats $entry.TableStats
        }

        # --- Records fetched ---
        # Plain string search instead of a regex: the number is the whole line before the marker; an occurrence inside the
        # SQL text (no number-only line) is skipped
        $at = $block.IndexOf($script:RECORDS_FETCHED, $script:Ordinal)
        while ($at -gt 0) {
            $lineStart = $block.LastIndexOf("`n", $at - 1) + 1
            $rows = [long]0
            if ([long]::TryParse($block.Substring($lineStart, $at - $lineStart), $script:DigitsOnly, $null, [ref]$rows)) {
                $entry.RecordsFetched = $rows
                break
            }
            $at = $block.IndexOf($script:RECORDS_FETCHED, $at + 1, $script:Ordinal)
        }

        # --- Perf ---
        $m = if ($block.Contains(' ms')) { $rxPerf.Match($block) } else { [System.Text.RegularExpressions.Match]::Empty }
        if ($m.Success) {
            $entry.DurationMs = [long]$m.Groups['DurationMs'].Value
            if ($m.Groups['Reads'].Success) { $entry.Reads = [long]$m.Groups['Reads'].Value }
            if ($m.Groups['Writes'].Success) { $entry.Writes = [long]$m.Groups['Writes'].Value }
            if ($m.Groups['Fetches'].Success) { $entry.Fetches = [long]$m.Groups['Fetches'].Value }
            if ($m.Groups['Marks'].Success) { $entry.Marks = [long]$m.Groups['Marks'].Value }
        }

    }
    catch {
        if ($_.Exception.GetBaseException() -isnot [System.Text.RegularExpressions.RegexMatchTimeoutException]) { throw }
        Write-BlockWarning -Text $Text -Start $Start -Message "regex time limit ($RegexTimeoutSeconds s) reached, remaining fields left empty (-RegexTimeoutSeconds)"
    }

    # --- Diagnostics: events that cannot be assigned ---
    if (-not $entry.Action) {
        $script:ActionCount['(header not readable)']++
        Write-BlockWarning -Text $Text -Start $Start -Message 'event header not readable, fields left empty'
    }
    else {
        $script:ActionCount[$entry.Action]++
        if ($entry.Action -eq 'Unknown') {
            # Firebird writes fixed texts like "Unknown event in ATTACH_DATABASE" (TracePluginImpl.cpp)
            $line = $block.Substring(0, [Math]::Max(0, $block.IndexOf("`n")))
            Write-BlockWarning -Text $Text -Start $Start -Message ("unknown event '" + $line.Substring($line.IndexOf(') ') + 2) + "'")
        }
    }

    [PSCustomObject]$entry
}

# 5. Streaming loop: read the file in chunks of 4 MB, split each chunk at block starts with one regex call
#    (fast .NET split instead of a PowerShell loop per line), keep the unfinished last block for the next chunk.
#    Memory stays bounded by the chunk size plus the largest single block.
$rxBlockStartMulti = [System.Text.RegularExpressions.Regex]::new(
    '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,}',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)
$reader = [System.IO.StreamReader]::new((Resolve-Path -LiteralPath $Path).ProviderPath, [System.Text.Encoding]::UTF8, $true, 1MB)
$chunk = [char[]]::new(4MB)
$carry = ''
$carryCut = $false     # lines of the carried block were dropped (MaxBlockLines)
$seenBlock = $false
$count = 0
$length = [Math]::Max(1, $reader.BaseStream.Length)
try {
    while (($read = $reader.Read($chunk, 0, $chunk.Length)) -gt 0) {
        # Trace files mix CRLF and LF; blocks are processed with LF only
        $text = $carry + ([string]::new($chunk, 0, $read)).Replace("`r", '')
        $starts = $rxBlockStartMulti.Matches($text)
        $carryStart = 0
        if ($starts.Count -gt 0) {
            # Everything before the first block start (e.g. 'Trace session ID n started') is skipped
            if (-not $seenBlock) {
                $seenBlock = $true
                if ($starts[0].Index -gt 0) { Test-Preamble $text.Substring(0, $starts[0].Index) }
            }
            for ($i = 0; $i -lt $starts.Count - 1; $i++) {
                ConvertFrom-TraceBlock $text $starts[$i].Index ($starts[$i + 1].Index - $starts[$i].Index) ($carryCut -and $i -eq 0)
                $count++
            }
            if ($starts.Count -gt 1) { $carryCut = $false }
            $carryStart = $starts[$starts.Count - 1].Index
        }
        # Line number of the new carry start (only the text before it is finished)
        if ($carryStart -gt 0) {
            $script:LineBase += Measure-Newline -Text $text -From 0 -To $carryStart
            if ($carryStart -ge $script:ShiftFrom) { $script:LineBase += $script:Shift; $script:Shift = 0; $script:ShiftFrom = [int]::MaxValue }
        }
        $carry = $text.Substring($carryStart)
        # Memory guard: a block (or text without any event) longer than MaxBlockLines is cut while it is carried
        if ($carry.Length -gt $MaxBlockLines) {
            $end = Get-LineEnd -Text $carry -Lines $MaxBlockLines
            if ($end -gt 0 -and $end -lt $carry.Length) {
                $script:Shift += Measure-Newline -Text $carry -From $end -To $carry.Length
                $script:ShiftFrom = $end
                $carry = $carry.Substring(0, $end)
                $carryCut = $seenBlock
            }
        }
        Write-Progress -Activity 'Parsing Firebird trace' -Status "$count events" -PercentComplete ([Math]::Min(100, 100 * $reader.BaseStream.Position / $length))
    }
    if ($rxBlockStartMulti.Match($carry).Index -eq 0 -and $rxBlockStartMulti.IsMatch($carry)) {
        ConvertFrom-TraceBlock $carry 0 $carry.Length $carryCut
        $count++
    }
    elseif (-not $seenBlock) { Test-Preamble $carry }
}
finally {
    $reader.Dispose()
    Write-Progress -Activity 'Parsing Firebird trace' -Completed
}

# Summary (I13): verbose stream only, the pipeline output stays the same
$order = @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false }
foreach ($kv in ($script:ActionCount.GetEnumerator() | Sort-Object -Property $order)) {
    Write-Verbose "Summary: $($kv.Key) = $($kv.Value)"
}
Write-Verbose "Summary: $script:WarningCount warning(s)"

$sw.Stop()
Write-Verbose "Parsed $count events in $($sw.Elapsed.TotalSeconds.ToString('N2')) seconds."
