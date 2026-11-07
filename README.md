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
Streams the file in 4 MB chunks (memory stays bounded, independent of file size) and writes one object per trace event to the pipeline as soon as the event is complete. Status messages: `-Verbose`.

**Output Objects Properties:**
*   `Timestamp`: Time of event.
*   `DurationMs`: Execution time in milliseconds.
*   `SqlStatement`: The full SQL query.
*   `SqlPlan`: Execution Plan (e.g. `NATURAL`, `INDEX`).
*   `Fetches`, `Reads`, `Writes`, `Marks`: I/O Statistics.
*   `User` (`USER:ROLE`), `ClientIP`, `ClientPort`, `ProtocolInfo`, `DatabasePath`, `AttachID`: Connection details.
*   `ApplicationPath`, `ApplicationPID`: Client application.
*   `TransactionID`, `RootTxID`, `TransactionOptions`: Transaction (`RootTxID` = initial transaction, `NoTx` if none).
*   `Params`: Statement parameters (`param0 = type, "value"`).
*   `TableStats`: Per-table statistics block (`Natural`, `Index`, …), column alignment preserved.
*   `Timestamp`, `ProcessID`, `SessionID`: Header of each trace event.
*   `Action`: Event name, e.g. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `ERROR`, `WARNING`.
*   `ErrorSource`, `ErrorCodes`, `ErrorMessages`: For `ERROR AT …` / `WARNING AT …` events (e.g. deadlocks, lock conflicts).

### The Pseudonymizer: `Pseudonymize-FirebirdTrace.ps1`
Designed for DSGVO/GDPR compliance when sharing logs.

*   **Hashing**: HMAC-SHA256 with a secret key (truncated). Keep the key file (`-KeyFile`) like a password: without it, pseudonyms cannot be checked against guesses; with the same key, pseudonyms stay comparable across runs.
*   **Context Aware**: Preserves SQL operators (`LIKE`, `=`, etc.) but hides the values.
    *   `SELECT * FROM Users WHERE Name = 'Muster'`
    *   becomes
    *   `SELECT * FROM Users WHERE Name = '<HASH:8b3e...>'`

**Parameters:**
*   `-SensitiveKeywords "A", "B"`: List of words to always hash.
*   `-RedactLiterals`: Forcefully hash **ALL** string literals (recommended for maximum safety).
*   `-AnalyzeOnly`: Preview what would be redacted without changing data (report goes to the console only).
*   `-KeyFile <path>`: Secret key (created if missing). Same key = same pseudonyms across runs. Without it, a random key is used for this run only.
*   `-MappingFile <path>`: Optional CSV `Pseudonym;Original` for the data controller to map results back. Contains plaintext.

**Pseudonymized:** `User`, `ClientIP` (also in `ProtocolInfo`), `ApplicationPath`, `DatabasePath`, `Params` values; with `-RedactLiterals` also all string and numeric literals in `SqlStatement` and values in `ErrorMessages`.
**Not pseudonymized:** `SqlPlan`, `TableStats` and table/index names (needed for analysis), technical IDs, timestamps, counters.

> [!WARNING]
> **Security Notice**: This tool uses **Pseudonymization** (keyed hashing, HMAC-SHA256), not Anonymization. Whoever has the key can verify guessed values; the data stays personal data for the data controller (GDPR). Never share the key file or the mapping file (`-MappingFile`).

---

<a id="disclaimer"></a>
## ⚖ Disclaimer

**Firebird is a registered trademark of the Firebird Foundation.**
This tool is open-source software and is **not** affiliated with, endorsed by, or associated with the Firebird Foundation.

---

*MIT License (see [LICENSE](LICENSE)). Free to fork and build your own reports!*
