<#
.SYNOPSIS
    Analysiert eine Sammlung von geparsten Firebird-Trace-Objekten,
    um Statistiken zu Häufigkeit, Dauer und Performance zu erstellen.

.DESCRIPTION
    Dieses Skript nimmt die Ausgabe von 'Show-TraceStructure.ps1' über die
    Pipeline entgegen. Es berechnet Hashes für SQL-Statements und Pläne,
    ermittelt die Root-Transaktions-ID und gruppiert die Einträge.
    
    Es unterstützt spezielle Modi 'AdrSummary' und 'ProcessSummary', um 
    Netzwerk- und Applikationsstatistiken zu erstellen.

.PARAMETER InputObject
    Die [PSCustomObject]-Einträge, die von 'Show-TraceStructure.ps1'
    generiert wurden. Dieser Parameter wird über die Pipeline befüllt.

.PARAMETER GroupBy
    Definiert, wonach gruppiert werden soll.
    - 'SqlHash': Gruppiert identische SQL-Statements (Standard).
    - 'PlanHash': Gruppiert identische Ausführungspläne.
    - 'RootTxID': Gruppiert nach Transaktions-Ketten.
    - 'User': Gruppiert nach dem Benutzer.
    - 'AdrSummary': Erstellt eine IP-basierte Statistik (Att, Det, Unique Sessions, etc.).
    - 'ProcessSummary': Erstellt eine Applikations-basierte Statistik.

.EXAMPLE
    # Analysiert ein Log und erstellt eine Adress-Zusammenfassung
    .\Show-TraceStructure.ps1 -Path "trace.log" | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary

.OUTPUTS
    [System.Management.Automation.PSCustomObject[]]
    Ein Array von aggregierten Statistik-Objekten.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [psobject]$InputObject,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SqlHash", "PlanHash", "RootTxID", "User", "AdrSummary", "ProcessSummary")]
    [string]$GroupBy = "SqlHash"
)

# Pipeline-Verarbeitung
begin {
    # Helper-Funktion für Hashes
    function Get-StringHash($InputString) {
        if ([string]::IsNullOrEmpty($InputString)) { return $null }
        
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $hashBytes = $sha.ComputeHash($bytes)
        
        return [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    }

    # Wir verwenden eine .NET List für bessere Performance beim Hinzufügen
    $allObjects = [System.Collections.Generic.List[psobject]]::new()
    Write-Host "Starte Analyse. Sammle Einträge aus der Pipeline..."
}

process {
    $allObjects.Add($InputObject)
}

end {
    Write-Host "Alle $($allObjects.Count) Einträge empfangen. Verarbeite Daten..."

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # 1. Vorbereitung: Hashes anreichern
    foreach ($obj in $allObjects) {
        # Standard Hashes
        $sqlHash = Get-StringHash $obj.SqlStatement
        $planHash = Get-StringHash $obj.SqlPlan

        # RootTxID Fallback
        if (-not $obj.psobject.Properties['RootTxID']) {
            $obj.psobject.Properties.Add([System.Management.Automation.PSNoteProperty]::new("RootTxID", "NoTx"))
        }
        
        # Properties hinzufügen
        $props = $obj.psobject.Properties
        if (-not $props['SqlHash']) { $props.Add([System.Management.Automation.PSNoteProperty]::new("SqlHash", $sqlHash)) }
        if (-not $props['PlanHash']) { $props.Add([System.Management.Automation.PSNoteProperty]::new("PlanHash", $planHash)) }
    }

    # 2. Gruppierung festlegen
    $groupProperty = $GroupBy
    
    # Vereinfachung: Wir nutzen direkt die existierende ClientIP Eigenschaft
    if ($GroupBy -eq 'AdrSummary') { $groupProperty = 'ClientIP' }
    if ($GroupBy -eq 'ProcessSummary') { $groupProperty = 'ApplicationPath' }

    Write-Host "Gruppiere nach '$groupProperty'..."

    # Daten filtern und gruppieren
    $groupedData = $allObjects | Where-Object { $_.$groupProperty } | Group-Object -Property $groupProperty

    # 3. Bericht erstellen
    $report = $groupedData | ForEach-Object {
        $groupList = $_.Group
        $groupCount = $_.Count
        $groupName = $_.Name

        # Basis-Metriken
        $totalDuration = ($groupList | Measure-Object DurationMs -Sum).Sum
        $totalFetches = ($groupList | Measure-Object Fetches -Sum).Sum
        $totalWrites = ($groupList | Measure-Object Writes -Sum).Sum
        $totalReads = ($groupList | Measure-Object Reads -Sum).Sum 
        $totalMarks = ($groupList | Measure-Object Marks -Sum).Sum

        # Spezial-Metriken für Summaries
        $attCount = 0
        $detCount = 0
        $uniqueSessions = 0
        $uniquePIDs = 0
        $procInfo = $null
        $sqlSequence = $null

        # Eindeutige SQL-Statements sammeln
        $uniqueSqls = $groupList.SqlStatement | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

        # NEU: Sequenz-Erstellung nur bei RootTxID (wo der Zeitablauf kritisch ist)
        if ($GroupBy -eq 'RootTxID') {
            # Chronologisch sortieren
            $chronologicalOps = $groupList | Sort-Object Timestamp
            
            # Sequenz aufbauen (nur Einträge mit SQL)
            $seqCounter = 1
            $sqlSequence = foreach ($op in $chronologicalOps) {
                if (-not [string]::IsNullOrWhiteSpace($op.SqlStatement)) {
                    [PSCustomObject]@{
                        No         = $seqCounter++
                        Timestamp  = $op.Timestamp
                        DurationMs = $op.DurationMs
                        Sql        = $op.SqlStatement
                    }
                }
            }
        }

        if ($GroupBy -eq 'AdrSummary' -or $GroupBy -eq 'ProcessSummary') {
            # Attach / Detach zählen
            $attCount = ($groupList | Where-Object { $_.Action -eq 'ATTACH_DATABASE' }).Count
            $detCount = ($groupList | Where-Object { $_.Action -eq 'DETACH_DATABASE' }).Count
            
            # Unique Sessions (U.S.)
            $uniqueSessions = ($groupList | Select-Object SessionID -Unique).Count
            
            # Unique Processes (U.P.) - Client PIDs
            $uniquePIDs = ($groupList | Where-Object { $_.ApplicationPID } | Select-Object ApplicationPID -Unique).Count

            # Proc-Liste
            if ($GroupBy -eq 'AdrSummary') {
                $procs = $groupList | Where-Object { $_.ApplicationPath } | Group-Object ApplicationPath
                $procStrings = $procs | Sort-Object Count -Descending | ForEach-Object {
                    $fName = [System.IO.Path]::GetFileName($_.Name)
                    "$($_.Count): $fName"
                }
                $procInfo = ($procStrings | Select-Object -First 5) -join ", "
            }
        }

        # Ergebnis-Objekt bauen
        $outObj = [ordered]@{
            No              = 0
            GroupValue      = $groupName
            Count           = $groupCount
            TotalDurationMs = $totalDuration
            TotalFetches    = $totalFetches
            TotalReads      = $totalReads
            TotalWrites     = $totalWrites
            TotalMarks      = $totalMarks
        }

        # Zusatzspalten für Summary-Tabellen
        if ($GroupBy -eq 'AdrSummary' -or $GroupBy -eq 'ProcessSummary') {
            $outObj.Att = $attCount
            $outObj.Det = $detCount
            $outObj.Conn = $uniqueSessions
            $outObj.US = $uniqueSessions
            $outObj.UP = $uniquePIDs
            
            if ($procInfo) {
                $outObj.Proc = $procInfo
            }
        }
        else {
            # Standard Spalten
            $outObj.AvgDurationMs = if ($groupCount -gt 0) { [Math]::Round($totalDuration / $groupCount, 2) } else { 0 }
            
            # Das erste echte SQL
            $outObj.FirstSqlStatement = $uniqueSqls | Select-Object -First 1
            
            # NEU: Die Sequenz-Liste
            if ($sqlSequence) {
                $outObj.SqlSequence = $sqlSequence
                # SqlStatements lassen wir hier weg, da SqlSequence genauer ist
            }
            else {
                # Fallback: Wenn keine Sequenz da ist (z.B. GroupBy User), zeigen wir die unique Liste
                $outObj.SqlStatements = $uniqueSqls
            }
            
            # Anzahl ist immer interessant
            $outObj.UniqueSqlCount = $uniqueSqls.Count

            $outObj.FirstSqlPlan = ($groupList | Select-Object -First 1).SqlPlan
            $outObj.FirstUser = ($groupList | Select-Object -First 1).User
        }

        [PSCustomObject]$outObj
    }

    # Sortierung und Ranking (No) hinzufügen
    $sortedReport = $report | Sort-Object Count -Descending
    
    $i = 1
    foreach ($row in $sortedReport) {
        $row.No = $i
        $i++
    }

    Write-Host "Analyse abgeschlossen. Gebe $($sortedReport.Count) Gruppen zurück."
    $stopwatch.Stop()
    $duration = $stopwatch.Elapsed
    Write-Host "Dauer der Verarbeitung: $($duration.TotalSeconds.ToString("N2")) Sekunden."
    
    return $sortedReport
}
