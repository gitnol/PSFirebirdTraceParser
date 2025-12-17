[ 🇩🇪 Deutsch ](README.de.md)

# 🔥 PSFirebirdTraceParser

**High-Performance PowerShell Parser & Pseudonymizer for Firebird Trace Logs.**

> **Note**: This repository contains the **Core Parsing Engine** and **Pseudonymization Tools**. It generates structured PowerShell objects that you can process, analyze, or export to your own reporting systems.

---

## 📋 Table of Contents
1. [Functionality](#functionality)
2. [Quick Start](#quickstart)
3. [Usage Details](#usage)
4. [Disclaimer](#disclaimer)

---

<a id="functionality"></a>
## ⚡ Functionality
Firebird Trace Logs are text-based and difficult to parse programmatically due to their multi-line block structure. This project solves that problem:

1.  **Parse (`Show-TraceStructure.ps1`)**: Reads raw trace logs (GBs in size) and converts them into structured PowerShell Objects (`[PSObject]`).
2.  **Pseudonymize (`Pseudonymize-FirebirdTrace.ps1`)**: Securely hashes sensitive data (Usernames, IP addresses, SQL String Literals) to enable safe sharing of logs for external analysis.

---

<a id="quickstart"></a>
## 🚀 Quick Start

### 1. Parse and View in Grid
Analyze a log file immediately using PowerShell's built-in GridView:

```powershell
.\Show-TraceStructure.ps1 -Path "C:\db\trace.log" | Out-GridView
```

### 2. Export to CSV (Excel)
Convert the trace log into a CSV file for analysis in Excel or PowerBI:

```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | Export-Csv -Path "trace_export.csv" -NoTypeInformation
```

### 3. Parse, Sanitize, and Export
Process a sensitive production log, hide specific keywords and all string literals, then export:

```powershell
.\Show-TraceStructure.ps1 -Path "prod_trace.log" | `
.\Pseudonymize-FirebirdTrace.ps1 -SensitiveKeywords "SecretClient", "Confidential" -RedactLiterals | `
Export-Csv "safe_trace.csv"
```

---

<a id="usage"></a>
## 🛠 Usage Details

### The Parser: `Show-TraceStructure.ps1`
Reads the file line-by-line (low memory) and splits entries based on Timestamps.

**Output Objects Properties:**
*   `Timestamp`: Time of event.
*   `DurationMs`: Execution time in milliseconds.
*   `SqlStatement`: The full SQL query.
*   `SqlPlan`: Execution Plan (e.g. `NATURAL`, `INDEX`).
*   `Fetches`, `Reads`, `Writes`, `Marks`: I/O Statistics.
*   `User`, `IPAddress`, `Application`: Connection details.

### The Pseudonymizer: `Pseudonymize-FirebirdTrace.ps1`
Designed for DSGVO/GDPR compliance when sharing logs.

*   **Hashing**: Uses SHA256 (truncated) to replace values.
*   **Context Aware**: Preserves SQL operators (`LIKE`, `=`, etc.) but hides the values.
    *   `SELECT * FROM Users WHERE Name = 'Muster'`
    *   becomes
    *   `SELECT * FROM Users WHERE Name = '<HASH:8b3e...>'`

**Parameters:**
*   `-SensitiveKeywords "A", "B"`: List of words to always hash.
*   `-RedactLiterals`: Forcefully hash **ALL** string literals (recommended for maximum safety).
*   `-AnalyzeOnly`: Preview what would be redacted without changing data.

> [!WARNING]
> **Security Notice**: This tool uses **Pseudonymization** (Deterministic Hashing), not Anonymization. Dictionary attacks against known values are possible.

---

<a id="disclaimer"></a>
## ⚖ Disclaimer

**Firebird is a registered trademark of the Firebird Foundation.**
This tool is open-source software and is **not** affiliated with, endorsed by, or associated with the Firebird Foundation.

---

*MIT License. Free to fork and build your own reports!*
