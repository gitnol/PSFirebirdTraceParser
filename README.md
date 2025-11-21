# Firebird Trace Log Parser & Analyzer

Eine Sammlung von PowerShell-Tools zum Parsen, Analysieren und Auswerten von Firebird Trace Logs. Diese Skripte helfen dabei, Performance-Engpässe zu identifizieren, SQL-Abfragen zu gruppieren und Transaktionsketten zu verstehen.

## Inhaltsverzeichnis

- [Firebird Trace Log Parser \& Analyzer](#firebird-trace-log-parser--analyzer)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [Enthaltene Skripte](#enthaltene-skripte)
  - [Nutzung \& Workflow](#nutzung--workflow)
    - [Schritt 1: Log-Datei parsen](#schritt-1-log-datei-parsen)
    - [Schritt 2: Basis-Analyse (Individuelle Abfragen)](#schritt-2-basis-analyse-individuelle-abfragen)
  - [Fortgeschrittene Analyse mit `Get-FbTraceAnalysis`](#fortgeschrittene-analyse-mit-get-fbtraceanalysis)
    - [A. SQL-Statistiken (Grouping by SQL Hash)](#a-sql-statistiken-grouping-by-sql-hash)
    - [B. "Impact"-Analyse](#b-impact-analyse)
    - [C. Transaktions-Ketten Analyse (`RootTxID`)](#c-transaktions-ketten-analyse-roottxid)
  - [Infrastruktur- \& Prozess-Zusammenfassungen](#infrastruktur---prozess-zusammenfassungen)
    - [Adress-Zusammenfassung (Wer verbindet sich?)](#adress-zusammenfassung-wer-verbindet-sich)
    - [Prozess-Zusammenfassung (Welche App macht was?)](#prozess-zusammenfassung-welche-app-macht-was)
  - [Export (Excel)](#export-excel)
  - [Voraussetzungen](#voraussetzungen)

---

## Enthaltene Skripte

1.  **`Show-TraceStructure.ps1`** (Der Parser)
    * Liest die rohe Text-Logdatei ein.
    * Zerlegt sie in strukturierte PowerShell-Objekte (`PSCustomObject`).
    * Extrahiert Metadaten (Timestamp, User, IP, App), SQL-Statements, Pläne und Performance-Metriken (Duration, Reads, Writes, Fetches).

2.  **`Get-FbTraceAnalysis.ps1`** (Der Analysator)
    * Nimmt die geparsten Objekte entgegen.
    * Erstellt SHA256-Hashes von SQL-Statements und Plänen zur Identifizierung.
    * Gruppiert Daten nach verschiedenen Kriterien (SQL, Plan, Transaktionskette, IP, Prozess).
    * Berechnet aggregierte Statistiken (Summen, Durchschnitte).

---

## Nutzung & Workflow

### Schritt 1: Log-Datei parsen

Zuerst muss das Logfile eingelesen werden. Da dies bei großen Dateien (100MB+) einige Sekunden dauern kann, speichern wir das Ergebnis in einer Variablen (`$erg`).

```powershell
# Einlesen einer Log-Datei
$erg = .\Show-TraceStructure.ps1 -Path "C:\Logs\firebird_trace.log"

# Optional: Mit Debug-Informationen (Raw-Block)
# $erg = .\Show-TraceStructure.ps1 -Path "C:\Logs\firebird_trace.log" -EnableDebug
````

### Schritt 2: Basis-Analyse (Individuelle Abfragen)

Die einfachste Analyse erfolgt direkt auf den geparsten Daten, um einzelne Ausreißer zu finden.

```powershell
# Die 10 langsamsten individuellen Abfragen finden
$erg | Sort-Object DurationMs -Descending | Select-Object -First 10 | Format-Table Timestamp, DurationMs, SqlStatement -AutoSize
```

-----

## Fortgeschrittene Analyse mit `Get-FbTraceAnalysis`

Für tiefere Einblicke nutzen wir das Analyse-Skript, um Daten zu gruppieren.

### A. SQL-Statistiken (Grouping by SQL Hash)

Identifiziert Abfragen, die zwar einzeln schnell sein mögen, aber durch ihre Häufigkeit das System belasten.

```powershell
# Gruppieren nach identischem SQL-Statement
$sqlStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash

# 1. Die häufigsten Abfragen (Top 10 nach Anzahl)
$sqlStats | Select-Object -First 10 | Format-Table Count, TotalDurationMs, AvgDurationMs, TotalFetches, FirstSqlStatement -Wrap

# 2. Top 100 Abfragen mit gekürztem SQL-Text im GridView anzeigen
#    Hinweis: Der SQL-Text wird hier auf 100 Zeichen gekürzt für bessere Lesbarkeit im Grid.
$sqlStats | 
    Where-Object { $_.FirstSqlStatement -ne $null -and $_.FirstSqlStatement.Trim() -ne "" } | 
    Sort-Object AvgDurationMs -Descending | 
    Select-Object -First 100 -Property Count, TotalDurationMs, AvgDurationMs, TotalFetches, TotalWrites, @{N="SQLString100";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}} | 
    Out-GridView -Title "Top 100 Langsamste Queries (Avg)"
```

### B. "Impact"-Analyse

Oft sind nicht die langsamsten Abfragen das Problem, sondern die, die in Summe (Häufigkeit \* Dauer) die meiste Serverzeit fressen.

```powershell
# Zeigt die 100 Abfragen mit dem größten Gesamteinfluss (Total Impact)
$sqlStats | 
    Where-Object { $_.FirstSqlStatement -ne $null } | 
    Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
    Select-Object -First 100 -Property @{N="TotalImpactMs";E={$_.Count * $_.AvgDurationMs}}, Count, AvgDurationMs, @{N="SQL";E={$_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length))}} | 
    Out-GridView -Title "High Impact Queries"
```

### C. Transaktions-Ketten Analyse (`RootTxID`)

Firebird schreibt Änderungen oft erst beim `COMMIT` auf die Festplatte. Diese Analyse ordnet die Kosten (Writes) der gesamten Transaktionskette zu und zeigt, welche SQL-Befehle darin enthalten waren.

```powershell
# Gruppieren nach Transaktionsketten
$chainStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID

# Die Transaktionen mit den meisten Schreibzugriffen finden
$expensiveChains = $chainStats | Sort-Object TotalWrites -Descending | Select-Object -First 10 

# Übersicht ausgeben
$expensiveChains | Format-Table RootTxID, TotalWrites, TotalDurationMs, UniqueSqlCount, FirstUser -AutoSize

# Detail-Analyse: Welche SQLs haben die Writes in der teuersten Kette verursacht?
$topChain = $expensiveChains | Select-Object -First 1
Write-Host "Verantwortliche SQLs für $($topChain.TotalWrites) Writes in Tx $($topChain.RootTxID):"
$topChain.SqlStatements
```

-----

## Infrastruktur- & Prozess-Zusammenfassungen

Diese speziellen Modi helfen, Netzwerk-Last und Applikations-Verhalten zu verstehen.

### Adress-Zusammenfassung (Wer verbindet sich?)

Zeigt Statistiken pro IP-Adresse an (Verbindungen, Dauer, Unique Sessions).

```powershell
# Netzwerk-Statistik erstellen
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary | Format-Table -AutoSize
```

**Spalten-Legende:**

  * `Att/Det`: Anzahl Attach/Detach Events.
  * `Conn/US`: Unique Sessions (Anzahl eindeutiger Sitzungen von dieser IP).
  * `UP`: Unique Processes (Anzahl eindeutiger PIDs auf Client-Seite).
  * `Proc`: Liste der Programme, die von dieser IP ausgeführt wurden.

### Prozess-Zusammenfassung (Welche App macht was?)

Zeigt Statistiken pro Applikationspfad (z.B. `averp.exe` vs `jobthread.exe`).

```powershell
# Applikations-Statistik erstellen
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ProcessSummary | Format-Table -AutoSize
```

-----

## Export (Excel)

Falls das PowerShell-Modul `ImportExcel` installiert ist, lassen sich die Daten hervorragend weiterverarbeiten.

```powershell
# Beispiel: Export der High-Impact Queries nach Excel
$sqlStats | 
    Where-Object { $_.FirstSqlStatement } | 
    Sort-Object -Property @{E={$_.Count * $_.AvgDurationMs}} -Descending | 
    Select-Object -First 500 -Property @{N="Impact";E={$_.Count * $_.AvgDurationMs}}, Count, AvgDurationMs, TotalWrites, FirstSqlStatement | 
    Export-Excel -Path "Trace_Analysis_Report.xlsx" -WorksheetName "HighImpactSQL" -AutoSize -AutoFilter
```

## Voraussetzungen

  * PowerShell 5.1 oder höher (PowerShell 7+ empfohlen für Performance).
  * Firebird Trace Log Dateien (Textformat).
