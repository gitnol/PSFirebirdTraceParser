[ 🇬🇧 English ](README.md)

# 🔥 PSFirebirdTraceParser

**High-Performance PowerShell Parser & Pseudonymizer für Firebird Trace Logs.**

> **Hinweis**: Dieses Repository enthält die **Core Parsing Engine** und **Pseudonymisierungs-Tools**. Es generiert strukturierte PowerShell-Objekte, die du weiterverarbeiten, analysieren oder in deine eigenen Reporting-Systeme exportieren kannst.

---

## 📋 Inhaltsverzeichnis
1. [Funktionalität](#functionality)
2. [Schnellstart](#quickstart)
3. [Nutzungsdetails](#usage)
4. [Haftungsausschluss (Disclaimer)](#disclaimer)

---

<a id="functionality"></a>
## ⚡ Funktionalität
Firebird Trace Logs sind textbasiert und durch ihre Blockstruktur schwer programmgesteuert zu parsen. Dieses Projekt löst das Problem:

1.  **Parsen (`Show-TraceStructure.ps1`)**: Liest rohe Trace Logs (auch mehrere GB) und konvertiert sie in strukturierte PowerShell-Objekte (`[PSObject]`).
2.  **Pseudonymisieren (`Pseudonymize-FirebirdTrace.ps1`)**: Hasht sensible Daten (Benutzernamen, IP-Adressen, SQL Strings) sicher, um Logs für externe Analysen teilbar zu machen.

---

<a id="quickstart"></a>
## 🚀 Schnellstart

### 1. Parsen und Anzeigen (GridView)
Analysiere eine Logdatei sofort mit der integrierten PowerShell-Ansicht:

```powershell
.\Show-TraceStructure.ps1 -Path "C:\db\trace.log" | Out-GridView
```

### 2. Export nach CSV (Excel)
Konvertiere das Trace Log in eine CSV-Datei für Excel oder PowerBI:

```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | Export-Csv -Path "trace_export.csv" -NoTypeInformation
```

### 3. Parsen, Bereinigen und Exportieren
Verarbeite ein sensibles Produktions-Log, verstecke spezifische Schlüsselwörter und alle Zeichenfolgen (Strings) und exportiere es dann:

```powershell
.\Show-TraceStructure.ps1 -Path "prod_trace.log" | `
.\Pseudonymize-FirebirdTrace.ps1 -SensitiveKeywords "SecretClient", "Vertraulich" -RedactLiterals | `
Export-Csv "safe_trace.csv"
```

---

<a id="usage"></a>
## 🛠 Nutzungsdetails

### Der Parser: `Show-TraceStructure.ps1`
Liest die Datei Zeile für Zeile (geringer Speicherbedarf) und trennt Einträge basierend auf Zeitstempeln.

**Eigenschaften der Ausgabe-Objekte:**
*   `Timestamp`: Zeitstempel des Events.
*   `DurationMs`: Ausführungsdauer in Millisekunden.
*   `SqlStatement`: Die vollständige SQL-Abfrage.
*   `SqlPlan`: Ausführungsplan (z.B. `NATURAL`, `INDEX`).
*   `Fetches`, `Reads`, `Writes`, `Marks`: E/A-Statistiken.
*   `User`, `IPAddress`, `Application`: Verbindungsdetails.
*   `Action`: Ereignisname, z. B. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `ERROR`, `WARNING`.
*   `ErrorSource`, `ErrorCodes`, `ErrorMessages`: Bei `ERROR AT …` / `WARNING AT …` (z. B. Deadlocks, Sperrkonflikte).

### Der Pseudonymisierer: `Pseudonymize-FirebirdTrace.ps1`
Entwickelt für DSGVO/GDPR-Konformität beim Teilen von Logs.

*   **Hashing**: Verwendet SHA256 (gekürzt), um Werte zu ersetzen.
*   **Kontext-Sensitiv**: Erhält SQL-Operatoren (`LIKE`, `=`, etc.), versteckt aber die Werte.
    *   `SELECT * FROM Users WHERE Name = 'Muster'`
    *   wird zu
    *   `SELECT * FROM Users WHERE Name = '<HASH:8b3e...>'`

**Parameter:**
*   `-SensitiveKeywords "A", "B"`: Liste von Wörtern, die immer gehasht werden sollen.
*   `-RedactLiterals`: Zwingt das Hashen **ALLER** Zeichenfolgen (empfohlen für maximale Sicherheit).
*   `-AnalyzeOnly`: Vorschau, was geschwärzt würde, ohne Daten zu ändern.

> [!WARNING]
> **Sicherheitshinweis**: Dieses Tool nutzt **Pseudonymisierung** (Deterministisches Hashing), keine Anonymisierung. Wörterbuch-Attacken gegen bekannte Werte sind möglich.

---

<a id="disclaimer"></a>
## ⚖ Haftungsausschluss (Disclaimer)

**Firebird ist eine eingetragene Marke der Firebird Foundation.**
Dieses Tool ist Open-Source-Software und ist **nicht** mit der Firebird Foundation verbunden, von ihr unterstützt oder assoziiert.

---

*MIT Lizenz. Frei zum Forken und Bauen eigener Reports!*
