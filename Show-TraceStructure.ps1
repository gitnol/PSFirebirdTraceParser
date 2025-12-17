<#
.SYNOPSIS
    High-Performance Firebird Trace Parser (Regex Block Mode)
    Refined for correctness and robustness.

.DESCRIPTION
    Parses Firebird trace logs by splitting blocks based on Timestamp.
    Uses robust Regex look-aheads to separate fields.
    
    Field Mapping:
    - TransactionOptions: From TRA_ line (READ_COMMITTED...)
    - Params: From param0 = ... lines
    - SqlStatement: Stops at separators (^^^^, PLAN, param, records)
    - SqlPlan: Includes PLAN (...) AND Table Stats logic.

.OUTPUTS
    [System.Collections.Generic.List[PSObject]]
#>
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

Write-Host "--- Fast Analysis Started (Legacy Mode) ---"
Write-Host "Reading (Memory): $Path ..."

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    return
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()

# 1. Read Raw Content (Fastest single-threaded read)
$fileContent = Get-Content -Path $Path -Raw
Write-Host "File read in $($sw.Elapsed.TotalSeconds.ToString("N2"))s. Splitting..."

# 2. Split into Blocks
# Delimiter: Date at start of line
$delimiter = '(?m)(?=^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})'
$logBlocks = $fileContent -split $delimiter | Where-Object { 
    -not [string]::IsNullOrWhiteSpace($_) -and 
    ($_ -match '^\d{4}-\d{2}-\d{2}T')
}

$total = $logBlocks.Count
Write-Host "Processing $($total) blocks..."

# 3. Regex Definitions
# Header
$rxHeader = [System.Text.RegularExpressions.Regex]::new(
    '^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>[0-9A-F]+)\)\s+(?<Action>\S+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Compiled
)

# DB (Include IP/Port)
$rxDb = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DatabasePath>.+?\.FDB)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>.+?:NONE),\s+(?<Encoding>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>TCPv[46]):(?<IPAddress>[^/]+)/(?<Port>\d+))\)',
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


# 4. Processing Loop
$results = [System.Collections.Generic.List[PSObject]]::new($total)
$i = 0

foreach ($block in $logBlocks) {
    $i++
    if ($i % 5000 -eq 0) { Write-Progress -Activity "Parsing Fast..." -Status "$i / $total" -PercentComplete (($i / $total) * 100) }

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
        DurationMs = 0; Reads = 0; Writes = 0; Fetches = 0; Marks = 0;
    }
    
    # --- Header ---
    $m = $rxHeader.Match($block)
    if ($m.Success) {
        $entry.Timestamp = $m.Groups['Timestamp'].Value
        $entry.Action = $m.Groups['Action'].Value
        $entry.ProcessID = $m.Groups['ProcessID'].Value
        $entry.SessionID = $m.Groups['SessionID'].Value
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
    $m = $rxSql.Match($block)
    if ($m.Success) {
        # Trim whitespace AND separator lines like --- if they slipped in
        $entry.SqlStatement = $m.Groups['SqlStatement'].Value.Trim()
    }

    # --- Params ---
    $m = $rxParams.Match($block)
    if ($m.Success) {
        $entry.Params = $m.Groups['Params'].Value.Trim()
    }

    # --- Plan ---
    $m = $rxPlan.Match($block)
    if ($m.Success) {
        $entry.SqlPlan = $m.Groups['SqlPlan'].Value.Trim()
    }
    
    # --- Table Stats (Separate Column) ---
    $m = $rxTableStats.Match($block)
    if ($m.Success) {
        $entry.TableStats = $m.Groups['TableStats'].Value # NO TRIM to preserve column alignment
    }

    # --- Perf ---
    $m = $rxPerf.Match($block)
    if ($m.Success) {
        $entry.DurationMs = [int]$m.Groups['DurationMs'].Value
        if ($m.Groups['Reads'].Success) { $entry.Reads = [int]$m.Groups['Reads'].Value }
        if ($m.Groups['Writes'].Success) { $entry.Writes = [int]$m.Groups['Writes'].Value }
        if ($m.Groups['Fetches'].Success) { $entry.Fetches = [int]$m.Groups['Fetches'].Value }
        if ($m.Groups['Marks'].Success) { $entry.Marks = [int]$m.Groups['Marks'].Value }
    }

    $results.Add([PSCustomObject]$entry)
}

$sw.Stop()
Write-Progress -Activity "Parsing Fast..." -Completed
Write-Host "--- Processing Complete ---"
Write-Host "Parsed $($results.Count) records."
Write-Host "Duration: $($sw.Elapsed.TotalSeconds.ToString("N2")) seconds."

return $results
