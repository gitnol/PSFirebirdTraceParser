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
    
    # HIER ist die Vereinfachung: Wir nutzen direkt die existierende ClientIP Eigenschaft
    if ($GroupBy -eq 'AdrSummary') { $groupProperty = 'ClientIP' }
    if ($GroupBy -eq 'ProcessSummary') { $groupProperty = 'ApplicationPath' }

    Write-Host "Gruppiere nach '$groupProperty'..."

    # Daten filtern und gruppieren (Leere Werte rausfiltern, z.B. Einträge ohne IP)
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

        # Spezial-Metriken für Summaries (Att, Det, U.S., U.P.)
        $attCount = 0
        $detCount = 0
        $uniqueSessions = 0
        $uniquePIDs = 0
        $procInfo = $null

        if ($GroupBy -eq 'AdrSummary' -or $GroupBy -eq 'ProcessSummary') {
            # Attach / Detach zählen
            $attCount = ($groupList | Where-Object { $_.Action -eq 'ATTACH_DATABASE' }).Count
            $detCount = ($groupList | Where-Object { $_.Action -eq 'DETACH_DATABASE' }).Count
            
            # Unique Sessions (U.S.)
            $uniqueSessions = ($groupList | Select-Object SessionID -Unique).Count
            
            # Unique Processes (U.P.) - Client PIDs
            $uniquePIDs = ($groupList | Where-Object { $_.ApplicationPID } | Select-Object ApplicationPID -Unique).Count

            # Proc-Liste (Nur für AdrSummary relevant: Welche Prozesse kamen von dieser IP?)
            if ($GroupBy -eq 'AdrSummary') {
                $procs = $groupList | Where-Object { $_.ApplicationPath } | Group-Object ApplicationPath
                # Formatieren als String: "Anzahl: Name (PID_Beispiel), ..."
                $procStrings = $procs | Sort-Object Count -Descending | ForEach-Object {
                    # Wir holen uns den reinen Dateinamen für die Kürze
                    $fName = [System.IO.Path]::GetFileName($_.Name)
                    "$($_.Count): $fName"
                }
                # Die Top 5 Prozesse zusammenfügen
                $procInfo = ($procStrings | Select-Object -First 5) -join ", "
            }
        }

        # Ergebnis-Objekt bauen (dynamisch je nach Modus)
        $outObj = [ordered]@{
            No              = 0 # Platzhalter für Rank
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
            $outObj.Conn = $uniqueSessions # Conn ist hier Unique Sessions
            $outObj.US = $uniqueSessions
            $outObj.UP = $uniquePIDs
            
            if ($procInfo) {
                $outObj.Proc = $procInfo
            }
        }
        else {
            # Standard Spalten für SQL/Plan Analyse
            $outObj.AvgDurationMs = if ($groupCount -gt 0) { [Math]::Round($totalDuration / $groupCount, 2) } else { 0 }
            $outObj.FirstSqlStatement = ($groupList | Select-Object -First 1).SqlStatement
            $outObj.FirstUser = ($groupList | Select-Object -First 1).User
        }

        [PSCustomObject]$outObj
    }

    # Sortierung und Ranking (No) hinzufügen
    $sortedReport = $report | Sort-Object Count -Descending
    
    # Index 'No' befüllen
    $i = 1
    foreach ($row in $sortedReport) {
        $row.No = $i
        $i++
    }

    Write-Host "Analyse abgeschlossen. Gebe $($sortedReport.Count) Gruppen zurück."
    
    return $sortedReport
}

# Um die 10 langsamsten *individuellen* Abfragen zu finden (wie in deinem RANK-Beispiel),
# brauchst du das Skript nicht. Das machst du direkt mit der Ausgabe des Parsers:
# $erg = .\Show-TraceStructure.ps1 -Path "C:\temp\20251113\trace_output_ib_aid_20251112\trace_output_ib_aid_20251112.log" 
# Kleiner
# $erg = .\Show-TraceStructure.ps1 -Path "C:\temp\20251113\trace_output_ib_aid_20251112\trace_output_ib_aid_20251112_120MB.log"
# $erg | Sort-Object DurationMs -Descending | Select-Object -First 10


# # Führt die Analyse durch und speichert die nach SqlHash gruppierten Ergebnisse:
# $sqlStatsSqlHash = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash
# $sqlStatsPlanHash = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy PlanHash
# $sqlStatsRootTxID = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID
# $sqlStatsUser = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy User
# $sqlStatsAppPath = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ApplicationPath


# Zeigt die 10 häufigsten SQL-Abfragen an
# $sqlStatsSqlHash | Select-Object -First 10 | Format-Table Count, TotalDurationMs, AvgDurationMs, TotalFetches, AvgFetches, TotalWrites, FirstSqlStatement -Wrap

# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property Count, TotalDurationMs, AvgDurationMs, TotalFetches, AvgFetches, TotalWrites, @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Out-GridView
# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property *, @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Out-GridView

# Zeigt die 100 SQL-Abfragen mit dem größten Gesamteinfluss (Count * AvgDurationMs) an.
# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | 
# Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
# Select-Object -First 100 -Property @{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}}, 
# @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}},* | 
# Out-GridView

# Exportiert die 100 SQL-Abfragen mit dem größten Gesamteinfluss (Count * AvgDurationMs) in eine Excel-Datei.
# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | 
# Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
# Select-Object -First 100 -Property 
# @{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}}, 
# @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}},* | 
# Export-Excel


# Zeigt die Quelladressen Zusammenfassung an:
# $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary | Format-Table -AutoSize

# Zeigt die Processzusammenfassung an
# $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ProcessSummary | Format-Table -AutoSize


# # 1. Parsen (falls noch nicht geschehen)
# # $erg = .\Show-TraceStructure.ps1 -Path "DeinLog.log"

# # 2. Transaktions-Analyse durchführen
# $sqlStatsRootTxID = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID

# # 3. Die "teuersten" Ketten bzgl. Schreibzugriffen (Writes) ansehen
# $sqlStatsRootTxID | Select-Object RootTxID, User, TotalWrites, TotalDurationMs, UniqueSqlCount -First 10 | Format-Table

# # 4. Detail-Analyse einer spezifischen Kette (z.B. die teuerste):
# # Hier siehst du endlich, WELCHE SQLs zu den Writes geführt haben!
# $topChain = $sqlStatsRootTxID | Select-Object -First 1
# $topChain.SqlStatements

# Mit `$topChain.SqlStatements` bekommst du jetzt die Antwort auf deine Frage: "Welche SQL-Befehle haben diese Writes verursacht?" (auch wenn die Writes erst beim Commit geloggt wurden).