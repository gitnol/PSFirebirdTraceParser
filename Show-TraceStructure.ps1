<#
.SYNOPSIS
    Analysiert eine Firebird-Trace-Log-Datei und wandelt die Einträge in PowerShell-Objekte um.

.DESCRIPTION
    Dieses Skript liest eine Firebird-Trace-Log-Datei ein, die mit einem Zeitstempel (z.B. 2025-11-12T...) beginnende
    Log-Blöcke identifiziert und jeden Block in ein [PSCustomObject] parst.
    
    Die Struktur der Log-Einträge wird analysiert, um Metadaten wie Timestamp, Aktion, Benutzer,
    Transaktionsdetails, Performance-Metriken und SQL-Statements zu extrahieren.

.PARAMETER Path
    Der Pfad zur Trace-Log-Datei, die analysiert werden soll.

.EXAMPLE
    # Führt die Analyse durch und speichert die Ergebnisobjekte in der Variablen $erg
    $erg = .\Show-TraceStructure.ps1 -Path "C:\logs\firebird_trace.log"
    
    # Zeigt die 10 langsamsten Abfragen an
    $erg | Sort-Object DurationMs -Descending | Select-Object -First 10
    
    # Gruppiert die Einträge nach Benutzer
    $erg | Group-Object User | Sort-Object Count -Descending

.OUTPUTS
    [System.Management.Automation.PSCustomObject[]]
    Ein Array von Objekten, die die geparsten Log-Einträge repräsentieren.
#>
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [switch]$EnableDebug # Geändert von $Debug, um Konflikt mit CommonParameters zu vermeiden
)

Write-Host "--- Analyse gestartet ---"

# 1. Regex-Definitionen
# Trennzeichen: Ein Zeitstempel am Zeilenanfang.
# (?m) = Multiline-Modus
# KORREKTUR: ^ hinzugefügt, damit nur Zeitstempel am Zeilenanfang als Split gelten.
$delimiter = '(?m)(?=^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})'

# Kopfzeile: Timestamp (aus delimiter), Prozess/Session, Aktion
# $1 ist der Timestamp aus dem Split-Delimiter
$regexHeader = [System.Text.RegularExpressions.Regex]::new(
    '^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>[0-9A-F]+)\)\s+(?<Action>\S+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# DB-Zeile: Pfad (ATT_ID, User:NONE, Encoding, Protokoll:IP/Port)
# Beispiel: D:\DB\LA01_ECHT.FDB (ATT_389512, LEWA-ATTENDORN\H.TILCH:NONE, UTF8, TCPv4:10.0.185.82/56570)
# KORREKTUR: Erweitert um Encoding, Protocol, IP und Port einzeln zu erfassen (Nested Groups)
$regexDb = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DatabasePath>.+?\.FDB)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>.+?:NONE),\s+(?<Encoding>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>TCPv[46]):(?<IPAddress>[^/]+)/(?<Port>\d+))\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# App-Zeile: AppPfad:PID
# Beispiel: C:\Users\H.Tilch\AppData\Roaming\AvERP\AVERP.EXE:8312
# KORREKTUR: Negative Lookahead (?!.*\(ATT_) hinzugefügt.
# Damit wird verhindert, dass die DB-Zeile (die immer "(ATT_" enthält) versehentlich gematcht wird.
$regexApp = [System.Text.RegularExpressions.Regex]::new(
    '(?im)^\s+(?!.*\(ATT_)(?<ApplicationPath>(?:[a-z]:|\\\\).+?):(?<ApplicationPID>\d+)\s*$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# Transaktions-Zeile: (TRA_ID, [Optional_INIT_ID], Parameter)
$regexTra = [System.Text.RegularExpressions.Regex]::new(
    '^\s+\(TRA_(?<TransactionID>\d+)(?:,\s+INIT_(?<InitID>\d+))?,\s+(?<Params>.+?)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# SQL-Statement: Alles zwischen "Statement ...:" und dem nächsten relevanten Marker
$regexSql = [System.Text.RegularExpressions.Regex]::new(
    'Statement\s+\d+:\s*[\r\n]+(?:-{3,}[\r\n]+)(?<SqlStatement>.+?)(?=(?m)[\r\n]+\s*(\^{4,}|PLAN \(|param\d+|[0-9]+\s+records? fetched|\d+\s+ms))',
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

# SQL-Plan: Alle Zeilen, die mit "PLAN (" beginnen
$regexPlan = [System.Text.RegularExpressions.Regex]::new(
    '(?<SqlPlan>(?:^\s*PLAN \(.*\).*[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# Performance-Zeile: Dauer, [writes], [fetches], [marks]
$regexPerf = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DurationMs>\d+)\s+ms(?:,\s+(?<Reads>\d+)\s+read\(s\))?(?:,\s+(?<Writes>\d+)\s+write\(s\))?(?:,\s+(?<Fetches>\d+)\s+fetch\(es\))?(?:,\s+(?<Marks>\d+)\s+mark\(s\))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)


# 2. Datei einlesen und aufteilen
Write-Host "Lese Datei: $Path ..."
$fileContent = Get-Content -Path $Path -Raw

# Aufteilen der Datei an den Zeitstempel-Markern.
Write-Host "Datei wird in Blöcke aufgeteilt..."
$logBlocks = $fileContent -split $delimiter

$totalBlocks = $logBlocks.Count - 1
Write-Host "Log-Datei aufgeteilt in $($totalBlocks) Blöcke."


# 4. Verarbeitungs-Schleife
Write-Host "`n--- Starte Verarbeitung aller Blöcke ---`n"

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$i = 0

$parsedEntries = foreach ($block in $logBlocks | Select-Object -Skip 1) {
    
    # Fortschrittsanzeige
    $i++
    $percent = ($i / $totalBlocks) * 100
    $status = "Verarbeite Block $i von $totalBlocks ($($percent.ToString("N2")) %)"
    Write-Progress -Activity "Log-Blöcke werden geparst" -Status $status -PercentComplete $percent

    # Wir erstellen ein geordnetes Hashtable für das Objekt
    $entry = [ordered]@{
        Timestamp       = $null
        Action          = $null
        ProcessID       = $null
        SessionID       = $null
        DatabasePath    = $null
        AttachID        = $null
        User            = $null
        Encoding        = $null # NEU
        ProtocolInfo    = $null
        ClientIP        = $null # NEU
        ClientPort      = $null # NEU
        ApplicationPath = $null
        ApplicationPID  = $null
        TransactionID   = $null
        InitID          = $null
        RootTxID        = $null
        Params          = $null
        SqlStatement    = $null
        SqlPlan         = $null
        DurationMs      = 0
        Reads           = 0
        Writes          = 0
        Fetches         = 0
        Marks           = 0
    }

    if ($EnableDebug) {
        $entry['RawBlock'] = $block
    }

    # Kopfzeile parsen
    $matchHeader = $regexHeader.Match($block)
    if ($matchHeader.Success) {
        $entry.Timestamp = $matchHeader.Groups['Timestamp'].Value
        $entry.Action = $matchHeader.Groups['Action'].Value
        $entry.ProcessID = $matchHeader.Groups['ProcessID'].Value
        $entry.SessionID = $matchHeader.Groups['SessionID'].Value
    }

    # DB-Zeile parsen (Jetzt mit Encoding, IP, Port)
    $matchDb = $regexDb.Match($block)
    if ($matchDb.Success) {
        $entry.DatabasePath = $matchDb.Groups['DatabasePath'].Value
        $entry.AttachID = $matchDb.Groups['AttachID'].Value
        $entry.User = $matchDb.Groups['User'].Value
        $entry.ProtocolInfo = $matchDb.Groups['ProtocolInfo'].Value # Kompatibilität
        
        # Neue Felder
        $entry.Encoding = $matchDb.Groups['Encoding'].Value
        $entry.ClientIP = $matchDb.Groups['IPAddress'].Value
        $entry.ClientPort = $matchDb.Groups['Port'].Value
    }

    # App-Zeile parsen
    $matchApp = $regexApp.Match($block)
    if ($matchApp.Success) {
        $entry.ApplicationPath = $matchApp.Groups['ApplicationPath'].Value
        $entry.ApplicationPID = $matchApp.Groups['ApplicationPID'].Value
    }

    # Transaktions-Zeile parsen
    $matchTra = $regexTra.Match($block)
    if ($matchTra.Success) {
        $entry.TransactionID = $matchTra.Groups['TransactionID'].Value
        $entry.InitID = $matchTra.Groups['InitID'].Value
        $entry.Params = $matchTra.Groups['Params'].Value
        
        $rootTxID = "NoTx"
        if (-not [string]::IsNullOrWhiteSpace($entry.InitID)) {
            $rootTxID = $entry.InitID
        }
        elseif (-not [string]::IsNullOrWhiteSpace($entry.TransactionID)) {
            $rootTxID = $entry.TransactionID
        }
        $entry.RootTxID = $rootTxID
    }
    
    # SQL-Statement parsen
    $matchSql = $regexSql.Match($block)
    if ($matchSql.Success) {
        $entry.SqlStatement = $matchSql.Groups['SqlStatement'].Value.Trim() -replace '(?m)^\s+', ''
    }

    # SQL-Plan parsen
    $matchPlan = $regexPlan.Match($block)
    if ($matchPlan.Success) {
        $entry.SqlPlan = $matchPlan.Groups['SqlPlan'].Value.Trim()
    }

    # Performance-Zeile parsen
    $matchPerf = $regexPerf.Match($block)
    if ($matchPerf.Success) {
        $entry.DurationMs = [int]$matchPerf.Groups['DurationMs'].Value
        
        if ($matchPerf.Groups['Reads'].Success) {
            $entry.Reads = [int]$matchPerf.Groups['Reads'].Value
        }
        if ($matchPerf.Groups['Writes'].Success) {
            $entry.Writes = [int]$matchPerf.Groups['Writes'].Value
        }
        if ($matchPerf.Groups['Fetches'].Success) {
            $entry.Fetches = [int]$matchPerf.Groups['Fetches'].Value
        }
        if ($matchPerf.Groups['Marks'].Success) {
            $entry.Marks = [int]$matchPerf.Groups['Marks'].Value
        }
    }

    [PSCustomObject]$entry
}

Write-Progress -Activity "Log-Blöcke werden geparst" -Completed
$stopwatch.Stop()
$duration = $stopwatch.Elapsed

Write-Host "`n--- Verarbeitung abgeschlossen ---"
Write-Host "Es wurden $i Log-Einträge geparst."
Write-Host "Dauer der Schleifen-Verarbeitung: $($duration.TotalSeconds.ToString("N2")) Sekunden."

$parsedEntries