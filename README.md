# Firebird Trace Log Parser & Analyzer

PowerShell-Tools zum **Parsen**, **Analysieren** und **Auswerten** von Firebird Trace Logs.
Hilft, Performance-Engpässe, Transaktionsketten und ineffiziente SQLs schnell zu identifizieren.

---

## Inhaltsverzeichnis

- [Firebird Trace Log Parser \& Analyzer](#firebird-trace-log-parser--analyzer)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [Enthaltene Skripte](#enthaltene-skripte)
    - [Show-TraceStructure.ps1](#show-tracestructureps1)
    - [Get-FbTraceAnalysis.ps1](#get-fbtraceanalysisps1)
  - [Konfiguration](#konfiguration)
    - [config.json](#configjson)
    - [fbtrace30.conf](#fbtrace30conf)
  - [Trace-Session starten und stoppen](#trace-session-starten-und-stoppen)
    - [trace\_start.ps1](#trace_startps1)
    - [trace\_stop.ps1](#trace_stopps1)
  - [Nutzung \& Workflow](#nutzung--workflow)
    - [Schritt 1: Trace starten](#schritt-1-trace-starten)
    - [Schritt 2: Log-Datei parsen](#schritt-2-log-datei-parsen)
    - [Schritt 3: Basis-Analyse](#schritt-3-basis-analyse)
  - [Fortgeschrittene Analyse](#fortgeschrittene-analyse)
    - [A. SQL-Statistiken (Grouping by SQL Hash)](#a-sql-statistiken-grouping-by-sql-hash)
    - [B. Impact-Analyse](#b-impact-analyse)
    - [C. Transaktions-Ketten Analyse (RootTxID)](#c-transaktions-ketten-analyse-roottxid)
  - [Infrastruktur- \& Prozess-Zusammenfassungen](#infrastruktur---prozess-zusammenfassungen)
  - [Excel-Export](#excel-export)
  - [Dateistruktur](#dateistruktur)
  - [Voraussetzungen](#voraussetzungen)

---

## Enthaltene Skripte

### Show-TraceStructure.ps1

Parser für Firebird Trace Logs.

- Liest Textdateien ein
- Wandelt sie in strukturierte _PSCustomObjects_ um
- Extrahiert: Timestamp, User, IP, App, SQL, Execution-Plan
- Berechnet: Duration, Reads, Writes, Fetches

### Get-FbTraceAnalysis.ps1

Erweitertes Analysewerkzeug.

- Hashing von SQL und Plänen (SHA256)
- Gruppierung nach: SQL, Plan, Transaktionskette, IP, Prozess
- Aggregationen wie TotalDuration, AvgDuration, TotalWrites u.v.m.

---

## Konfiguration

### config.json

Die Konfigurationsdatei enthält die Firebird-Zugangsdaten und Pfade. Sie wird von `trace_start.ps1` und `trace_stop.ps1` verwendet.

**Einrichtung:**

```powershell
# Kopiere die Vorlage
Copy-Item config.sample.json config.json

# Bearbeite config.json mit deinen Werten
```

**Struktur:**

```json
{
  "Firebird": {
    "Username": "SYSDBA",
    "Password": "masterkey",
    "FirebirdPath": "C:\\Program Files\\Firebird\\Firebird_4_0_3",
    "TraceConfigFilename": "fbtrace30.conf"
  }
}
```

| Parameter             | Beschreibung                                              |
| :-------------------- | :-------------------------------------------------------- |
| `Username`            | Firebird Benutzername (meist `SYSDBA`)                    |
| `Password`            | Firebird Passwort                                         |
| `FirebirdPath`        | Installationspfad von Firebird (enthält `fbtracemgr.exe`) |
| `TraceConfigFilename` | Name der Trace-Konfigurationsdatei                        |

**Hinweis:** Die `config.json` wird durch `.gitignore` vom Repository ausgeschlossen, um Passwörter zu schützen.

### fbtrace30.conf

Konfigurationsdatei für den Firebird Trace Manager (`fbtracemgr`). Steuert, welche Events protokolliert werden.

Typische Einstellungen:

- Aktivierung von SQL-Statements
- Aktivierung von Transaktionen
- Aktivierung von Timeout-Informationen
- Kontrolle, welche Attachments geloggt werden

---

## Trace-Session starten und stoppen

### trace_start.ps1

Startet eine Trace-Session mit dem Firebird-Tool `fbtracemgr`.

**Funktionsweise:**

1. Lädt Konfiguration aus `config.json`
2. Startet `fbtracemgr.exe` mit der Trace-Konfiguration aus `fbtrace30.conf`
3. Schreibt die Ausgabe in eine Logdatei mit Zeitstempel (z.B. `E:\trace_output_20251125_143000.log`)

**Verwendung:**

```powershell
.\trace_start.ps1
```

**Ausgabe:**

```
Config Pfad: D:\Scripts\config.json
20251125_143000
Bitte ermittle die Trace ID aus dem Kopf der Log Datei unter E:\trace_output_20251125_143000.log
Trace gestartet, Ausgabe in E:\trace_output_20251125_143000.log
Trace stoppen mit D:\Scripts\trace_stop.ps1
```

### trace_stop.ps1

Beendet eine laufende Trace-Session.

**Funktionsweise:**

1. Lädt Konfiguration aus `config.json`
2. Sucht automatisch die neueste Logdatei in `E:\`
3. Extrahiert die Trace-ID aus der ersten Zeile der Logdatei
4. Stoppt die Trace-Session mit `fbtracemgr.exe`

**Verwendung:**

```powershell
.\trace_stop.ps1
```

**Ausgabe:**

```
Config Pfad: D:\Scripts\config.json
Datei: E:\trace_output_20251125_143000.log
Trace-ID: 42
Stoppe Trace...
```

---

## Nutzung & Workflow

### Schritt 1: Trace starten

```powershell
# Konfiguration vorbereiten (einmalig)
Copy-Item config.sample.json config.json
# config.json bearbeiten mit korrekten Pfaden und Passwort

# Trace starten
.\trace_start.ps1
```

Führe nun die Aktionen aus, die du analysieren möchtest.

```powershell
# Trace stoppen
.\trace_stop.ps1
```

### Schritt 2: Log-Datei parsen

```powershell
$erg = .\Show-TraceStructure.ps1 -Path "E:\trace_output_20251125_143000.log"
```

Optional mit Debug-Infos:

```powershell
$erg = .\Show-TraceStructure.ps1 -Path "E:\trace_output_20251125_143000.log" -EnableDebug
```

### Schritt 3: Basis-Analyse

Top 10 langsamste Einzelabfragen:

```powershell
$erg |
    Sort-Object DurationMs -Descending |
    Select-Object -First 10 |
    Format-Table Timestamp, DurationMs, SqlStatement -AutoSize
```

---

## Fortgeschrittene Analyse

### A. SQL-Statistiken (Grouping by SQL Hash)

```powershell
$sqlStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash
```

Beispielauswertung:

```powershell
$sqlStats |
    Select-Object -First 10 |
    Format-Table Count, TotalDurationMs, AvgDurationMs, TotalFetches, FirstSqlStatement -Wrap
```

### B. Impact-Analyse

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

### C. Transaktions-Ketten Analyse (RootTxID)

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

**Adress-Statistik (Wer verbindet sich?)**

```powershell
$erg | .\Get-FbTraceAnalysis.ps1 -GroupBy AdrSummary | Format-Table -AutoSize
```

**Prozess-Statistik (Welche App macht was?)**

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

## Dateistruktur

```
FirebirdTraceAnalyzer/
├── Show-TraceStructure.ps1      # Parser für Trace Logs
├── Get-FbTraceAnalysis.ps1      # Analyse-Tool
├── trace_start.ps1              # Startet Trace-Session
├── trace_stop.ps1               # Stoppt Trace-Session
├── fbtrace30.conf               # Trace-Konfiguration für Firebird
├── config.json                  # Zugangsdaten (git-ignoriert)
├── config.sample.json           # Konfigurationsvorlage
└── .gitignore                   # Schützt config.json und Logs
```

---

## Voraussetzungen

- PowerShell 5.1 oder neuer
- Firebird Installation mit `fbtracemgr.exe`
- Zugriff auf die Firebird-Datenbank (SYSDBA oder entsprechende Rechte)
- Optional: _ImportExcel_ PowerShell-Modul für Excel-Export
