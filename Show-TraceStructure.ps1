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
# (?m) = Multiline-Modus, ^ matcht Zeilenanfang
# WICHTIGE ÄNDERUNG: Wir verwenden ein "Lookahead" (?=...), damit der Zeitstempel
# Teil des Blocks bleibt und nicht entfernt wird.
$delimiter = '(?m)(?=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})'

# Kopfzeile: Timestamp (aus delimiter), Prozess/Session, Aktion
# $1 ist der Timestamp aus dem Split-Delimiter
# Beispiel: (2596:00000008DEF31240) COMMIT_RETAINING
# ÄNDERUNG: Wir müssen den Zeitstempel wieder in die Header-Regex aufnehmen.
$regexHeader = [System.Text.RegularExpressions.Regex]::new(
    '^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>[0-9A-F]+)\)\s+(?<Action>\S+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# DB-Zeile: Pfad (ATT_ID, User:NONE, Encoding, Protokoll:IP/Port)
# Beispiel: D:\DB\LA01_ECHT.FDB (ATT_389512, LEWA-ATTENDORN\H.TILCH:NONE, UTF8, TCPv4:10.0.185.82/56570)
$regexDb = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DatabasePath>.+?\.FDB)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>.+?:NONE),\s+.*?,\s+(?<ProtocolInfo>TCPv[46]:.+?)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# App-Zeile: AppPfad:PID
# Beispiel: C:\Users\H.Tilch\AppData\Roaming\AvERP\AVERP.EXE:8312
$regexApp = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<ApplicationPath>.+?):(?<ApplicationPID>\d+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# Transaktions-Zeile: (TRA_ID, [Optional_INIT_ID], Parameter)
# Beispiel: (TRA_33038348, INIT_33038348, READ_COMMITTED | REC_VERSION | NOWAIT | READ_WRITE)
$regexTra = [System.Text.RegularExpressions.Regex]::new(
    '^\s+\(TRA_(?<TransactionID>\d+)(?:,\s+INIT_(?<InitID>\d+))?,\s+(?<Params>.+?)\)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# SQL-Statement: Alles zwischen "Statement ...:" und dem nächsten relevanten Marker (^^^^, PLAN, params, etc.)
# (.+?) = Non-greedy match
# (?=...) = Positive Lookahead, stoppt VOR diesen Mustern, ohne sie zu konsumieren.
# (?m) = Inline Multiline-Modus für ^
$regexSql = [System.Text.RegularExpressions.Regex]::new(
    'Statement\s+\d+:\s*[\r\n]+(?:-{3,}[\r\n]+)(?<SqlStatement>.+?)(?=(?m)[\r\n]+\s*(\^{4,}|PLAN \(|param\d+|[0-9]+\s+records? fetched|\d+\s+ms))',
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

# NEU: SQL-Plan: Alle Zeilen, die mit "PLAN (" beginnen
$regexPlan = [System.Text.RegularExpressions.Regex]::new(
    '(?<SqlPlan>(?:^\s*PLAN \(.*\).*[\r\n]?)+)',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

# HINZUGEFÜGT: Diese Definition hat beim letzten Editieren gefehlt.
# Performance-Zeile: Dauer, [writes], [fetches], [marks]
# Beispiel: 3 ms, 15 write(s), 2 fetch(es), 2 mark(s)
# Beispiel: 242 ms, 2746 fetch(es)
$regexPerf = [System.Text.RegularExpressions.Regex]::new(
    '^\s+(?<DurationMs>\d+)\s+ms(?:,\s+(?<Writes>\d+)\s+write\(s\))?(?:,\s+(?<Fetches>\d+)\s+fetch\(es\))?(?:,\s+(?<Marks>\d+)\s+mark\(s\))?',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)


# 2. Datei einlesen und aufteilen
# Get-Content -Raw liest die gesamte Datei als einen einzigen String ein (schneller)
Write-Host "Lese Datei: $Path ..."
$fileContent = Get-Content -Path $Path -Raw

# Aufteilen der Datei an den Zeitstempel-Markern.
# $delimiter wird in $matches gespeichert (siehe -split-Dokumentation)
Write-Host "Datei wird in Blöcke aufgeteilt..."
$logBlocks = $fileContent -split $delimiter

# Das erste Element ist oft leer oder der "Trace session ID..."-Header
$totalBlocks = $logBlocks.Count - 1
Write-Host "Log-Datei aufgeteilt in $($totalBlocks) Blöcke."


# 4. Verarbeitungs-Schleife
Write-Host "`n--- Starte Verarbeitung aller Blöcke ---`n"

# Zeitmessung für die Schleife
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$i = 0

# Wir fangen die Ausgabe der Schleife direkt in der $parsedEntries-Variablen auf
# Wir überspringen Block 0 (Header) und iterieren über alle Log-Einträge
$parsedEntries = foreach ($block in $logBlocks | Select-Object -Skip 1) {
    
    # Fortschrittsanzeige
    $i++
    $percent = ($i / $totalBlocks) * 100
    # Korrigierte Statuszeile
    $status = "Verarbeite Block $i von $totalBlocks ($($percent.ToString("N2")) %)"
    Write-Progress -Activity "Log-Blöcke werden geparst" -Status $status -PercentComplete $percent

    # Wir erstellen ein geordnetes Hashtable für das Objekt
    # Standardwerte (wichtig für Einträge, die nicht alle Felder haben)
    $entry = [ordered]@{
        Timestamp       = $null
        Action          = $null
        ProcessID       = $null
        SessionID       = $null
        DatabasePath    = $null
        AttachID        = $null
        User            = $null
        ProtocolInfo    = $null
        ApplicationPath = $null
        ApplicationPID  = $null
        TransactionID   = $null
        InitID          = $null
        Params          = $null
        SqlStatement    = $null
        SqlPlan         = $null # NEU
        DurationMs      = 0
        Writes          = 0
        Fetches         = 0
        Marks           = 0
    }

    # NEU: RawBlock nur hinzufügen, wenn -Debug gesetzt ist
    if ($EnableDebug) { # Geändert von $Debug
        $entry['RawBlock'] = $block
    }

    # $matches[0] enthält den Timestamp des *aktuellen* Blocks, da -split ihn abgetrennt hat
    # ÄNDERUNG: Diese Zeile ist fehlerhaft und wird entfernt.
    # $entry.Timestamp = $matches[$i]

    # Kopfzeile (Aktion, Session) parsen
    $matchHeader = $regexHeader.Match($block)
    if ($matchHeader.Success) {
        # ÄNDERUNG: Wir holen den Timestamp jetzt von hier, wie im alten Skript.
        $entry.Timestamp = $matchHeader.Groups['Timestamp'].Value
        $entry.Action = $matchHeader.Groups['Action'].Value
        $entry.ProcessID = $matchHeader.Groups['ProcessID'].Value
        $entry.SessionID = $matchHeader.Groups['SessionID'].Value
    }

    # DB-Zeile parsen
    $matchDb = $regexDb.Match($block)
    if ($matchDb.Success) {
        $entry.DatabasePath = $matchDb.Groups['DatabasePath'].Value
        $entry.AttachID = $matchDb.Groups['AttachID'].Value
        $entry.User = $matchDb.Groups['User'].Value
        $entry.ProtocolInfo = $matchDb.Groups['ProtocolInfo'].Value
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
    }
    
    # SQL-Statement parsen
    $matchSql = $regexSql.Match($block)
    if ($matchSql.Success) {
        # SQL-Code bereinigen (überflüssige Leerzeichen/Tabs am Zeilenanfang entfernen)
        $entry.SqlStatement = $matchSql.Groups['SqlStatement'].Value.Trim() -replace '(?m)^\s+', ''
    }

    # NEU: SQL-Plan parsen
    $matchPlan = $regexPlan.Match($block)
    if ($matchPlan.Success) {
        $entry.SqlPlan = $matchPlan.Groups['SqlPlan'].Value.Trim()
    }

    # Performance-Zeile parsen (kann überall im Block sein)
    $matchPerf = $regexPerf.Match($block)
    if ($matchPerf.Success) {
        $entry.DurationMs = [int]$matchPerf.Groups['DurationMs'].Value
        
        # Sicherstellen, dass die Gruppen existieren, bevor wir sie zuweisen
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

    # Das Objekt in die Pipeline ausgeben
    [PSCustomObject]$entry
}

# Fortschrittsanzeigera abschließen
Write-Progress -Activity "Log-Blöcke werden geparst" -Completed
$stopwatch.Stop()
$duration = $stopwatch.Elapsed

# 5. Zusammenfassung
Write-Host "`n--- Verarbeitung abgeschlossen ---"
Write-Host "Es wurden $i Log-Einträge geparst."
# Korrigierte Ausgabe der Dauer
Write-Host "Dauer der Schleifen-Verarbeitung: $($duration.TotalSeconds.ToString("N2")) Sekunden."

# 6. Rückgabe der Ergebnisse
# Durch das Entfernen von Format-Table/Format-List wird das Array
# direkt an die aufrufende Umgebung (z.B. die Variable $erg) zurückgegeben.
$parsedEntries