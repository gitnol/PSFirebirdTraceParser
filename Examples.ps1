
# Um die 10 langsamsten *individuellen* Abfragen zu finden (wie in deinem RANK-Beispiel),
# brauchst du das Skript nicht. Das machst du direkt mit der Ausgabe des Parsers:
$erg = .\Show-TraceStructure.ps1 -Path "C:\temp\20251113\trace_output_ib_aid_20251112\trace_output_ib_aid_20251112.log" 
# Kleiner
$erg = .\Show-TraceStructure.ps1 -Path "C:\temp\20251113\trace_output_ib_aid_20251112\trace_output_ib_aid_20251112_120MB.log"
$erg | Sort-Object DurationMs -Descending | Select-Object -First 10


# Führt die Analyse durch und speichert die nach SqlHash gruppierten Ergebnisse:
$sqlStatsSqlHash = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash
$sqlStatsPlanHash = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy PlanHash
$sqlStatsRootTxID = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID
$sqlStatsUser = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy User
$sqlStatsAppPath = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ApplicationPath


# Zeigt die 10 häufigsten SQL-Abfragen an
$sqlStatsSqlHash | Select-Object -First 10 | Format-Table Count, TotalDurationMs, AvgDurationMs, TotalFetches, AvgFetches, TotalWrites, FirstSqlStatement -Wrap

# $sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property Count, TotalDurationMs, AvgDurationMs, TotalFetches, AvgFetches, TotalWrites, @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Out-GridView
$sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property *, @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Out-GridView

# Alle nicht JOBS-User Anfragen mit mindestens 2 Ausführungen ... sortiert nach AvgDurationMs * Count = Gesamteinfluss
$sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne "" -and $_.FirstUser -ne 'JOBS:NONE' -and $_.Count -ge 2} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property *,@{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}},  @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Out-GridView
$sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne "" -and $_.FirstUser -ne 'JOBS:NONE' -and $_.Count -ge 2} | Sort-Object -Property AvgDurationMs -Descending | Select-Object -First 100 -Property *,@{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}},  @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}}  | Export-Excel

# Zeigt die 100 SQL-Abfragen mit dem größten Gesamteinfluss (Count * AvgDurationMs) an.
$sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | 
Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
Select-Object -First 100 -Property @{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}}, 
@{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}},* | 
Out-GridView

# Exportiert die 100 SQL-Abfragen mit dem größten Gesamteinfluss (Count * AvgDurationMs) in eine Excel-Datei.
$sqlStatsSqlHash | Where-Object {$_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne ""} | 
Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
Select-Object -First 100 -Property @{N="TotalImpactByDuration";E={$_.Count * $_.AvgDurationMs}}, 
@{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}},* | 
Export-Excel


# Zeigt die Quelladressen Zusammenfassung an:
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary | Format-Table -AutoSize

# Zeigt die Processzusammenfassung an
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ProcessSummary | Format-Table -AutoSize

##########################################################
# Beispiel: Transaktionsanalyse
# Angenommen, du möchtest herausfinden, welche SQL-Befehle in einer Transaktion
# die meisten Schreibzugriffe (Writes) verursacht haben, insbesondere wenn die Writes
# erst beim Commit geloggt wurden.

# 1. Analyse
$sqlStatsRootTxID = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID

# 2a. Die Transaktion mit den meisten Writes suchen
$heavyTx = $sqlStatsRootTxID | Sort-Object TotalWrites -Descending | Select-Object -First 1

# 2b. Alternativ: Die Longest Transaction (by Transaction Elements)
$longestTx = $sqlStatsRootTxID | Sort-Object Count -Descending | Select-Object -First 1

# 3. Die Sequenz ansehen (Was passierte nacheinander?)
$heavyTx.SqlSequence | Format-Table No, DurationMs, @{N='Sql';E={$_.Sql.Substring(0, [Math]::Min(80, $_.Sql.Length))}} -AutoSize
$longestTx.SqlSequence | Format-Table No, DurationMs, @{N='Sql';E={$_.Sql.Substring(0, [Math]::Min(80, $_.Sql.Length))}} -AutoSize

# Alles der SQLSequence inkl TimeStamp
$longestTx.SqlSequence | Out-GridView

# Damit siehst du sofort: "Ah, Eintrag Nr. 1 war ein Insert, Nr. 2 ein Update, und Nr. 3 hat 500ms gedauert."
##########################################################

#########################################################
# 1. Parsen (falls noch nicht geschehen)
# $erg = .\Show-TraceStructure.ps1 -Path "DeinLog.log"

# 2. Transaktions-Analyse durchführen
$sqlStatsRootTxID = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID

# 3. Die "teuersten" Ketten bzgl. Schreibzugriffen (Writes) ansehen
$sqlStatsRootTxID | Select-Object RootTxID, User, TotalWrites, TotalDurationMs, UniqueSqlCount -First 10 | Format-Table

# 4. Detail-Analyse einer spezifischen Kette (z.B. die teuerste):
# Hier siehst du endlich, WELCHE SQLs zu den Writes geführt haben!
$topChain = $sqlStatsRootTxID | Select-Object -First 1
$topChain.SqlStatements

# Mit `$topChain.SqlStatements` bekommst du jetzt die Antwort auf deine Frage: "Welche SQL-Befehle haben diese Writes verursacht?" (auch wenn die Writes erst beim Commit geloggt wurden).

#########################################################