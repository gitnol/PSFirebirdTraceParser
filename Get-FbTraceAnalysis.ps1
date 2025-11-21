<#
.SYNOPSIS
    Analysiert eine Sammlung von geparsten Firebird-Trace-Objekten,
    um Statistiken zu Häufigkeit, Dauer und Performance zu erstellen.

.DESCRIPTION
    Dieses Skript nimmt die Ausgabe von 'Show-TraceStructure.ps1' über die
    Pipeline entgegen. Es berechnet Hashes für SQL-Statements und Pläne,
    ermittelt die Root-Transaktions-ID und gruppiert die Einträge.
    
    Es liefert aggregierte Statistiken sowie eine Liste der eindeutigen SQL-Statements
    pro Gruppe zurück.

.PARAMETER InputObject
    Die [PSCustomObject]-Einträge, die von 'Show-TraceStructure.ps1'
    generiert wurden. Dieser Parameter wird über die Pipeline befüllt.

.PARAMETER GroupBy
    Definiert, wonach gruppiert werden soll.
    - 'SqlHash': Gruppiert identische SQL-Statements (Standard).
    - 'PlanHash': Gruppiert identische Ausführungspläne.
    - 'RootTxID': Gruppiert nach Transaktions-Ketten.
    - 'User': Gruppiert nach dem Benutzer.
    - 'ApplicationPath': Gruppiert nach dem Pfad der Anwendung.

.EXAMPLE
    # Analysiert ein Log und gruppiert nach identischen SQL-Abfragen
    .\Show-TraceStructure.ps1 -Path "trace.log" | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash

.EXAMPLE
    # Findet die teuersten Transaktions-Ketten und zeigt deren SQLs an
    $res = .\Show-TraceStructure.ps1 -Path "trace.log" | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID 
    $res | Sort-Object TotalWrites -Descending | Select-Object -First 5 | Select-Object RootTxID, TotalWrites, SqlStatements

.OUTPUTS
    [System.Management.Automation.PSCustomObject[]]
    Ein Array von aggregierten Statistik-Objekten.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [psobject]$InputObject,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SqlHash", "PlanHash", "RootTxID", "User", "ApplicationPath")]
    [string]$GroupBy = "SqlHash"
)

# Pipeline-Verarbeitung
begin {
    # Helper-Funktion INNERHALB des begin-Blocks
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
    # Fügt jedes Objekt aus der Pipeline der Liste hinzu
    $allObjects.Add($InputObject)
}

end {
    Write-Host "Alle $($allObjects.Count) Einträge empfangen. Reichere Daten an (Hashes)..."
    
    # 1. Alle Objekte anreichern (In-Place Modifikation für Performance)
    foreach ($obj in $allObjects) {
        # Hashes berechnen
        $sqlHash = Get-StringHash $obj.SqlStatement
        $planHash = Get-StringHash $obj.SqlPlan

        # HINWEIS: RootTxID wird jetzt vom Parser (Show-TraceStructure.ps1) geliefert.
        # Falls alte Parser-Version genutzt wird, Fallback:
        if (-not $obj.psobject.Properties['RootTxID']) {
            $obj.psobject.Properties.Add([System.Management.Automation.PSNoteProperty]::new("RootTxID", "NoTx"))
        }

        # Eigenschaften direkt hinzufügen (schneller als Add-Member)
        $props = $obj.psobject.Properties
        if (-not $props['SqlHash']) {
            $props.Add([System.Management.Automation.PSNoteProperty]::new("SqlHash", $sqlHash))
        }
        if (-not $props['PlanHash']) {
            $props.Add([System.Management.Automation.PSNoteProperty]::new("PlanHash", $planHash))
        }
    }

    Write-Host "Daten angereichert. Gruppiere nach '$GroupBy'..."

    # 2. Filtern und Gruppieren
    $groupedData = $allObjects | Where-Object { $_.$GroupBy } | Group-Object -Property $GroupBy

    # 3. Statistik-Objekte erstellen
    $report = $groupedData | ForEach-Object {
        
        $groupList = $_.Group
        
        # Aggregierte Werte für die Gruppe berechnen
        $totalDuration = ($groupList | Measure-Object DurationMs -Sum).Sum
        $totalFetches = ($groupList | Measure-Object Fetches -Sum).Sum
        $totalWrites = ($groupList | Measure-Object Writes -Sum).Sum
        $totalReads = ($groupList | Measure-Object Reads -Sum).Sum 
        
        # Zeitspanne ermitteln (nur sinnvoll bei RootTxID, aber schadet sonst auch nicht)
        # Wir sortieren kurz die Gruppe nach Zeit, um Start/Ende zu finden
        # (Bei sehr großen Gruppen kann das Zeit kosten, ist aber für die Analyse wertvoll)
        $startTime = $null
        $endTime = $null
        if ($groupList.Count -gt 0) {
            # Wir nehmen an, die Liste ist grob sortiert durch das Einlesen, 
            # aber sicherheitshalber nehmen wir Min/Max wenn nötig. 
            # Da Trace-Logs chronologisch sind, sind First/Last meist korrekt.
            $startTime = ($groupList | Select-Object -First 1).Timestamp
            $endTime = ($groupList | Select-Object -Last 1).Timestamp
        }

        # Eindeutige SQL-Statements sammeln
        # Das ist das Feature aus Get-FbTransactionGrouping.ps1
        $uniqueSqls = $groupList.SqlStatement | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

        [PSCustomObject]@{
            GroupValue        = $_.Name
            GroupBy           = $GroupBy
            Count             = $_.Count
            
            # Summen
            TotalDurationMs   = $totalDuration
            TotalFetches      = $totalFetches
            TotalReads        = $totalReads
            TotalWrites       = $totalWrites
            
            # Durchschnitte
            AvgDurationMs     = if ($_.Count -gt 0) { [Math]::Round($totalDuration / $_.Count, 2) } else { 0 }
            AvgFetches        = if ($_.Count -gt 0) { [Math]::Round($totalFetches / $_.Count, 0) } else { 0 }
            
            # Zeit
            StartTime         = $startTime
            EndTime           = $endTime

            # SQL-Details
            UniqueSqlCount    = $uniqueSqls.Count
            SqlStatements     = $uniqueSqls # Array aller eindeutigen Statements in dieser Gruppe

            # Referenzwerte für Anzeige
            FirstSqlStatement = ($groupList | Select-Object -First 1).SqlStatement
            FirstSqlPlan      = ($groupList | Select-Object -First 1).SqlPlan
            FirstUser         = ($groupList | Select-Object -First 1).User
            FirstRootTxID     = ($groupList | Select-Object -First 1).RootTxID
        }
    }

    Write-Host "Analyse abgeschlossen. Gebe $($report.Count) Gruppen zurück."
    
    # 4. Bericht ausgeben, sortiert nach Häufigkeit (Count)
    $report | Sort-Object Count -Descending
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
#     Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
#     Select-Object -First 100 -Property Count, AvgDurationMs, 
#         @{N="TotalImpact";E={$_.Count * $_.AvgDurationMs}}, 
#         TotalFetches, 
#         @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}} | 
#     Out-GridView

# Exportiert die 100 SQL-Abfragen mit dem größten Gesamteinfluss (Count * AvgDurationMs) in eine Excel-Datei.
# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | 
#     Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
#     Select-Object -First 100 -Property *, 
#         @{N="TotalImpact";E={$_.Count * $_.AvgDurationMs}}, 
#         @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}} | 
#     Export-Excel


# # 1. Parsen (falls noch nicht geschehen)
# # $erg = .\Show-TraceStructure.ps1 -Path "DeinLog.log"

# # 2. Transaktions-Analyse durchführen
# $chains = $erg | .\Get-FbTransactionGrouping.ps1

# # 3. Die "teuersten" Ketten bzgl. Schreibzugriffen (Writes) ansehen
# $chains | Select-Object RootTxID, User, TotalWrites, TotalDurationMs, UniqueSqlCount -First 10 | Format-Table

# # 4. Detail-Analyse einer spezifischen Kette (z.B. die teuerste):
# # Hier siehst du endlich, WELCHE SQLs zu den Writes geführt haben!
# $topChain = $chains | Select-Object -First 1
# $topChain.SqlStatements

# Mit `$topChain.SqlStatements` bekommst du jetzt die Antwort auf deine Frage: "Welche SQL-Befehle haben diese Writes verursacht?" (auch wenn die Writes erst beim Commit geloggt wurden).