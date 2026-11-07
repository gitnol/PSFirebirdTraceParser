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

    Status messages go to the verbose stream (-Verbose), not to the console.

.OUTPUTS
    [PSCustomObject] - one per trace event, streamed
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Write-Error "File not found: $Path"
    return
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
Write-Verbose "Streaming analysis started: $Path"


# 3. Regex Definitions
# Header
# Firebird writes the address with printf("%p"), which is platform dependent:
# Windows (MSVC) "000001A2B3C4D5E0", Linux (glibc) "0x7f3a1c2b4d10". Accept both.
$rxHeader = [System.Text.RegularExpressions.Regex]::new(
    # Action keeps the full event name ("FAILED EXECUTE_STATEMENT_FINISH"); for "ERROR AT <component>" /
    # "WARNING AT <component>" Action is ERROR/WARNING and the component goes to ErrorSource.
    '^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>(?:0x)?[0-9A-Fa-f]+)\)\s+(?<Action>(?:(?:FAILED|UNAUTHORIZED)\s+)?\S+)(?:\s+AT\s+(?<ErrorSource>\S+))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# Error/warning lines: "%9lu : <text>" (Firebird TraceStatusVectorImpl::getText)
$rxErrorLine = [System.Text.RegularExpressions.Regex]::new(
    '^\s*(?<Code>\d{1,10})\s:\s(?<Message>.*?)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# DB (Include IP/Port)
# Connection line: "<db path> (ATT_n, USER:ROLE, charset, <protocol info>)"
# Protocol info: "TCPv4:192.0.2.10/50123", "TCPv6:2001:db8::10/50123", "XNET:HOST" (no port) or "<internal>".
# Any database file name/extension and any role (K3).
$rxDb = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DatabasePath>\S.*?)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>[^,]+),\s+(?<Encoding>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>[A-Za-z0-9]+):(?<IPAddress>[^/)]+)(?:/(?<Port>\d+))?|<[^>]+>)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# App (Exclude ATT match)
$rxApp = [System.Text.RegularExpressions.Regex]::new(
    '(?im)^\s+(?!.*\(ATT_)(?<ApplicationPath>(?:[a-z]:|\\\\).+?):(?<ApplicationPID>\d+)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# Transaction (TRA_ID, Init, Options)
$rxTx = [System.Text.RegularExpressions.Regex]::new(
    '^\s+\(TRA_(?<TransactionID>\d+)(?:,\s+INIT_(?<InitID>\d+))?,\s+(?<TxOpts>.+?)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# SQL Statement
# Stops at: ^^^^, PLAN (, paramX, records fetched, or X ms
$rxSql = [System.Text.RegularExpressions.Regex]::new(
    'Statement\s+\d+:\s*[\r\n]+(?:-{3,}[\r\n]+)(?<SqlStatement>.+?)(?=(?m)[\r\n]+\s*(\^{4,}|PLAN \(|param\d+|[0-9]+\s+records? fetched|\d+\s+ms|Table\s+Natural))',
    [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# SQL Plan (PLAN ...)
$rxPlan = [System.Text.RegularExpressions.Regex]::new(
    '(?<SqlPlan>(?:^\s*PLAN\b.*[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# Table Stats (Treat as part of Plan or separate)
# Matches "Table ... Natural ... ******* ... rows"
$rxTableStats = [System.Text.RegularExpressions.Regex]::new(
    '(?<TableStats>Table\s+Natural.+?[\r\n]+\*+[\r\n]+(?:.+[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Singleline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)
# Fixed-Width data parsing logic is separate, but regex is needed for detection.

# SQL Params (param0 = ...)
$rxParams = [System.Text.RegularExpressions.Regex]::new(
    '(?<Params>(?:^\s*param\d+\s*=\s*.+[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# Performance
$rxPerf = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DurationMs>\d+)\s+ms(?:,\s+(?<Reads>\d+)\s+read\(s\))?(?:,\s+(?<Writes>\d+)\s+write\(s\))?(?:,\s+(?<Fetches>\d+)\s+fetch\(es\))?(?:,\s+(?<Marks>\d+)\s+mark\(s\))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)


# 4. Block parsing (one trace event -> one object)
function ConvertFrom-TraceBlock {
    param([string]$block)

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
    }

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

    # --- Tx ---
    $m = $rxTx.Match($block)
    if ($m.Success) {
        $entry.TransactionID = $m.Groups['TransactionID'].Value
        $initID = $m.Groups['InitID'].Value
        $entry.TransactionOptions = $m.Groups['TxOpts'].Value
        
        if (-not [string]::IsNullOrWhiteSpace($initID)) { $entry.RootTxID = $initID }
        elseif (-not [string]::IsNullOrWhiteSpace($entry.TransactionID)) { $entry.RootTxID = $entry.TransactionID }
    }

    # --- SQL ---
    # Cheap pre-checks: most events (transactions, attach/detach) have no statement part
    $hasStatement = $block.Contains('Statement ')
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
$count = 0
$length = [Math]::Max(1, $reader.BaseStream.Length)
try {
    while (($read = $reader.Read($chunk, 0, $chunk.Length)) -gt 0) {
        # Trace files mix CRLF and LF; blocks are processed with LF only
        $text = $carry + ([string]::new($chunk, 0, $read)).Replace("`r", '')
        $starts = $rxBlockStartMulti.Matches($text)
        if ($starts.Count -eq 0) { $carry = $text; continue }
        # Everything before the first block start (e.g. 'Trace session ID n started') is skipped
        for ($i = 0; $i -lt $starts.Count - 1; $i++) {
            ConvertFrom-TraceBlock $text.Substring($starts[$i].Index, $starts[$i + 1].Index - $starts[$i].Index)
            $count++
        }
        $carry = $text.Substring($starts[$starts.Count - 1].Index)
        Write-Progress -Activity 'Parsing Firebird trace' -Status "$count events" -PercentComplete ([Math]::Min(100, 100 * $reader.BaseStream.Position / $length))
    }
    if ($rxBlockStartMulti.Match($carry).Index -eq 0 -and $rxBlockStartMulti.IsMatch($carry)) {
        ConvertFrom-TraceBlock $carry
        $count++
    }
}
finally {
    $reader.Dispose()
    Write-Progress -Activity 'Parsing Firebird trace' -Completed
}

$sw.Stop()
Write-Verbose "Parsed $count events in $($sw.Elapsed.TotalSeconds.ToString('N2')) seconds."
