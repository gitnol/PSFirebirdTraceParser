# Firebird Trace Log Parser & Analyzer

PowerShell-Tools zum **Parsen**, **Analysieren** und **Auswerten** von Firebird Trace Logs.
Hilft, Performance-Engpässe, Transaktionsketten und ineffiziente SQLs schnell zu identifizieren.

## Inhaltsverzeichnis

- [Firebird Trace Log Parser \& Analyzer](#firebird-trace-log-parser--analyzer)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [Enthaltene Skripte](#enthaltene-skripte)
    - [**Show-TraceStructure.ps1**](#show-tracestructureps1)
    - [**Get-FbTraceAnalysis.ps1**](#get-fbtraceanalysisps1)
  - [Trace-Konfigurationsdateien und Batch-Tools](#trace-konfigurationsdateien-und-batch-tools)
    - [**fbtrace30.conf**](#fbtrace30conf)
    - [**trace\_start.bat**](#trace_startbat)
    - [**trace\_stop.bat**](#trace_stopbat)
  - [Nutzung \& Workflow](#nutzung--workflow)
    - [**Schritt 1: Log-Datei parsen**](#schritt-1-log-datei-parsen)
    - [**Schritt 2: Basis-Analyse**](#schritt-2-basis-analyse)
  - [Fortgeschrittene Analyse](#fortgeschrittene-analyse)
    - [A. **SQL-Statistiken (Grouping by SQL Hash)**](#a-sql-statistiken-grouping-by-sql-hash)
    - [B. **Impact-Analyse**](#b-impact-analyse)
    - [C. **Transaktions-Ketten Analyse (RootTxID)**](#c-transaktions-ketten-analyse-roottxid)
  - [Infrastruktur- \& Prozess-Zusammenfassungen](#infrastruktur---prozess-zusammenfassungen)
    - [**Adress-Statistik (Wer verbindet sich?)**](#adress-statistik-wer-verbindet-sich)
    - [**Prozess-Statistik (Welche App macht was?)**](#prozess-statistik-welche-app-macht-was)
  - [Excel-Export](#excel-export)
  - [Voraussetzungen](#voraussetzungen)

---

## Enthaltene Skripte

### **Show-TraceStructure.ps1**

Parser für Firebird Trace Logs.

* Liest Textdateien ein
* Wandelt sie in strukturierte *PSCustomObjects* um
* Extrahiert: Timestamp, User, IP, App, SQL, Execution-Plan
* Berechnet: Duration, Reads, Writes, Fetches

### **Get-FbTraceAnalysis.ps1**

Erweitertes Analysewerkzeug.

* Hashing von SQL und Plänen (SHA256)
* Gruppierung nach: SQL, Plan, Transaktionskette, IP, Prozess
* Aggregationen wie TotalDuration, AvgDuration, TotalWrites u.v.m.

---

## Trace-Konfigurationsdateien und Batch-Tools

Diese Dateien befinden sich ebenfalls im Projektordner und werden zur Erzeugung der Firebird-Trace-Logs benötigt.

### **fbtrace30.conf**

Dies ist die Konfigurationsdatei für den Firebird Trace Manager (fbtracemgr).
Sie steuert, welche Events Firebird protokolliert.

Typische Inhalte (vereinfacht):

* Aktivierung von SQL-Statements
* Aktivierung von Transaktionen
* Aktivierung von Timeout-Informationen
* Kontrolle, welche Attachments geloggt werden
* Festlegung der Ausgabedatei

Sie wird benötigt, wenn `trace_start.bat` ausgeführt wird.

### **trace_start.bat**

Startet eine Trace-Session mit dem Firebird-Tool **fbtracemgr**.
Üblicher Aufbau:

* Verweist auf `fbtracemgr.exe`
* Startet die Trace-Konfiguration aus `fbtrace30.conf`
* Leitet die Ausgabe in eine Logdatei (z. B. `firebird_trace.log`)

Sie muss **vor der Analyse** ausgeführt werden, um Logs zu erzeugen.

### **trace_stop.bat**

Beendet eine laufende Trace Session.
Üblicher Aufbau:

* Ruft `fbtracemgr.exe` mit der Option zum Stoppen der Session auf
* Benötigt die Session-ID (steht im Firebird Log oder in der trace_start-Ausgabe)

Wird verwendet, um das Logging sauber zu stoppen, ohne defekte Logdateien zu erzeugen.

---

## Nutzung & Workflow

### **Schritt 1: Log-Datei parsen**

```powershell
$erg = .\Show-TraceStructure.ps1 -Path "C:\Logs\firebird_trace.log"
```

Optional mit Debug-Infos:

```powershell
$erg = .\Show-TraceStructure.ps1 -Path "C:\Logs\firebird_trace.log" -EnableDebug
```

---

### **Schritt 2: Basis-Analyse**

Top 10 langsamste Einzelabfragen:

```powershell
$erg |
    Sort-Object DurationMs -Descending |
    Select-Object -First 10 |
    Format-Table Timestamp, DurationMs, SqlStatement -AutoSize
```

---

## Fortgeschrittene Analyse

### A. **SQL-Statistiken (Grouping by SQL Hash)**

```powershell
$sqlStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash
```

Beispielauswertung:

```powershell
$sqlStats |
    Select-Object -First 10 |
    Format-Table Count, TotalDurationMs, AvgDurationMs, TotalFetches, FirstSqlStatement -Wrap
```

---

### B. **Impact-Analyse**

```powershell
$sqlStats |
    Where-Object { $_.FirstSqlStatement } |
    Sort-Object -Property @{E = { $_.Count * $_.AvgDurationMs }} -Descending |
    Select-Object -First 100 -Property `
        @{N="TotalImpactMs";E={ $_.Count * $_.AvgDurationMs }},
        Count, AvgDurationMs,
        @{N="SQL";E={ $_.FirstSqlStatement.Substring(0, [Math]::Min(100, $_.FirstSqlStatement.Length)) }} |
    Out-GridView -Title "High Impact Queries"
```

---

### C. **Transaktions-Ketten Analyse (RootTxID)**

```powershell
$chainStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy RootTxID
```

Kostenintensivste Transaktionen:

```powershell
$expensiveChains =
    $chainStats |
    Sort-Object TotalWrites -Descending |
    Select-Object -First 10

$expensiveChains | Format-Table RootTxID, TotalWrites, TotalDurationMs, UniqueSqlCount, FirstUser -AutoSize
```

---

## Infrastruktur- & Prozess-Zusammenfassungen

### **Adress-Statistik (Wer verbindet sich?)**

```powershell
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary | Format-Table -AutoSize
```

### **Prozess-Statistik (Welche App macht was?)**

```powershell
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy ProcessSummary | Format-Table -AutoSize
```

---

## Excel-Export

```powershell
$sqlStats |
    Where-Object { $_.FirstSqlStatement } |
    Sort-Object -Property @{E = { $_.Count * $_.AvgDurationMs }} -Descending |
    Select-Object -First 500 -Property `
        @{N="Impact";E={ $_.Count * $_.AvgDurationMs }},
        Count, AvgDurationMs, TotalWrites, FirstSqlStatement |
    Export-Excel -Path "Trace_Analysis_Report.xlsx" -WorksheetName "HighImpactSQL" -AutoSize -AutoFilter
```

---

## Voraussetzungen

* PowerShell 5.1 oder neuer
* Firebird Trace Logdateien
* Optional: *ImportExcel* PowerShell-Modul

