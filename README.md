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
3.  **Capture (`trace_start.ps1`, `trace_stop.ps1`)**: Starts and stops a named trace session with `fbtracemgr`, without a password on the command line.

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
Streams the file in 4 MB chunks (memory stays bounded, independent of file size) and writes one object per trace event to the pipeline as soon as the event is complete. Status messages: `-Verbose` (at the end also a summary: number of events per `Action` and of warnings).

Events that cannot be assigned (unreadable header, `Unknown event …`, text before the first event) are reported as warnings with the line number; the warning shows no trace content. Protection against very long events: `-MaxBlockLines` (default `100000`; longer events are cut, warning) and `-RegexTimeoutSeconds` (default `2` per field; when reached, the remaining fields stay empty, warning). The objects are the same as before; only these rare cases add a warning.

**Two parsers, same result (`-Engine`):** Since November 2026 the parser also exists in C# (`src/FirebirdTraceParser`,
a binary cmdlet for PowerShell 7.4+). `-Engine Auto` (default) uses it when PowerShell 7 runs and the built
`FirebirdTraceParser.dll` lies next to the script or in `bin/`; otherwise the PowerShell parser runs (always under
Windows PowerShell 5.1). `-Engine PowerShell` / `-Engine CSharp` choose explicitly (`CSharp` without the DLL or under 5.1
is an error). Both give the same objects, warnings and verbose messages — a parity test compares every field. The C#
parser is much faster (measured on a 15 MB synthetic log: 1.6 s instead of 13–14 s, peak memory 196 MB instead of 287 MB). Build it once with the .NET SDK:

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build    # -> bin/FirebirdTraceParser.dll
.\Show-TraceStructure.ps1 -Path trace.log -Verbose        # "Engine: CSharp"
```

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
*   `Action`: Event name, e.g. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `ERROR`, `WARNING`, `SWEEP_FINISH`, `START_SERVICE`.
*   `ErrorSource`, `ErrorCodes`, `ErrorMessages`: For `ERROR AT …` / `WARNING AT …` events (e.g. deadlocks, lock conflicts).
*   `ServiceName`, `ServiceID`: For service events (`ATTACH_SERVICE`, `START_SERVICE`, …), e.g. `Backup Database`; user, address and program of the service are in the connection fields. Needs `log_services` (on in `fbtrace50.conf`).
*   `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext`: Transaction counters of `SWEEP_START` / `SWEEP_FINISH`. Needs `log_sweep` (on in `fbtrace50.conf`).
*   `RecordsFetched`: Rows returned by the statement (`N records fetched`); `Fetches` counts page fetches. `0` if the line is missing (Firebird omits it for procedures with 0 rows).
*   `TxIsolation` (`READ_COMMITTED`, `CONCURRENCY`, `CONSISTENCY`), `TxReadMode` (`REC_VERSION`, `NO_REC_VERSION`, `READ_CONSISTENCY`; only with `READ_COMMITTED`), `TxWaitMode` (`WAIT`, `NOWAIT`), `TxLockTimeout` (seconds of `WAIT <n>`, otherwise empty), `TxAccessMode` (`READ_WRITE`, `READ_ONLY`): the parts of `TransactionOptions`.
*   `TableCounts`: `TableStats` as a list with one object per table (`Table`, `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge`; empty cell = `0`). It is a list: for CSV, expand it (`$_.TableCounts | Select-Object …`) or export `TableStats`.
*   `RoutineType` (`Procedure`, `Function`, `Trigger`), `RoutineName`: For `EXECUTE_PROCEDURE_FINISH`, `EXECUTE_FUNCTION_FINISH`, `EXECUTE_TRIGGER_FINISH` (also `FAILED …`); duration, I/O, parameters and table statistics are in the usual fields. Filter with `Action` or `RoutineType`; statements are unchanged. Needs `log_procedure_finish` / `log_function_finish` / `log_trigger_finish` (off in `fbtrace50.conf`; triggers can produce very many events).
*   `TriggerTable`, `TriggerTime` (`BEFORE`, `AFTER`, `ON` for database triggers), `TriggerEvent` (`INSERT`, `UPDATE`, `DELETE`, `CONNECT`, …): The trigger line; Firebird 4 and 5 write it differently, both are read.
*   `ConnectionDurationMs`: For `DETACH_DATABASE`, the time since `ATTACH_DATABASE` of the same connection in this file; empty if the connection started before the trace.

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
**Not pseudonymized:** `SqlPlan`, `TableStats`, `TableCounts` and table/index names (needed for analysis; `-SensitiveKeywords` does not hide them — leave these fields out if table names must stay private), technical IDs, timestamps, counters (also `RecordsFetched`, `ConnectionDurationMs`), transaction options, `ServiceName`/`ServiceID` and sweep counters, procedure/function/trigger names (`RoutineName`, `TriggerTable`; schema names like table names).

> [!WARNING]
> **Security Notice**: This tool uses **Pseudonymization** (keyed hashing, HMAC-SHA256), not Anonymization. Whoever has the key can verify guessed values; the data stays personal data for the data controller (GDPR). Never share the key file or the mapping file (`-MappingFile`).

---

### Capturing a trace: `trace_start.ps1` / `trace_stop.ps1`
Start and stop a Firebird trace session (Firebird 4.0 / 5.0) with `fbtracemgr`. Requires **PowerShell 7.4+** (the log file is written byte for byte).

1. Copy `config.sample.json` to `config.json` (stays local, git-ignored) and adjust it. No password goes into `config.json`:
   either `PasswordFile` (a file whose first line is the password; `fbtracemgr` reads it itself, the command line only shows the path) or `"UseTrustedAuth": true` (Windows logon).
2. Create the password file and restrict it to your account:
   ```powershell
   $dir = Join-Path $env:LOCALAPPDATA 'PSFirebirdTraceParser'; $null = New-Item -ItemType Directory -Force $dir
   $pw = Read-Host 'Firebird password' -MaskInput
   Set-Content -Path (Join-Path $dir 'firebird-trace.pass') -Value $pw -NoNewline -Encoding ascii; Remove-Variable pw
   icacls (Join-Path $dir 'firebird-trace.pass') /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
   ```
3. Window 1: `pwsh -File .\trace_start.ps1` (stays busy while the trace runs). Window 2: `pwsh -File .\trace_stop.ps1` (or `-Id <n>`).

| Key (`Firebird.…`) | Meaning |
|---|---|
| `FirebirdPath` | Folder with `fbtracemgr.exe` |
| `Username` / `PasswordFile` | Firebird user and password file (`%VAR%` allowed) |
| `UseTrustedAuth` | `true` = Windows logon instead of user and password file |
| `Role` | Optional role with the system privilege `TRACE_ANY_ATTACHMENT` (instead of SYSDBA) |
| `TraceConfigFilename` | Trace rules next to the scripts, e.g. `fbtrace50.conf` (all errors, sweeps, services) |
| `OutputDirectory` | Where the log `trace_output_<timestamp>.log` goes (`%VAR%` allowed) |
| `SessionName` | Prefix of the session name; `trace_stop.ps1` finds the session by this name |

#### Own trace user instead of SYSDBA (Firebird 4/5)
A normal user may trace other connections if a role with the system privilege `TRACE_ANY_ATTACHMENT` is active. As SYSDBA, connected to the database you want to trace (names are examples):

```sql
CREATE USER TRACE_USER PASSWORD '<new password>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Then in `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"` and the password of `TRACE_USER` in the password file (or `"UseTrustedAuth": true`). If the SYSDBA password was ever typed on a command line (for example `fbtracemgr -PASS`), change it. Details: [docs/operations/SETUP.md](docs/operations/SETUP.md) (German).

Exit codes: 0 ok, 1 `config.json` missing, 2 configuration invalid (all errors listed; also when a `Password` key is still there), 3 no session found, 4 several sessions match, 5 `fbtracemgr` error, 6 unexpected error.

---

<a id="disclaimer"></a>
## ⚖ Disclaimer

**Firebird is a registered trademark of the Firebird Foundation.**
This tool is open-source software and is **not** affiliated with, endorsed by, or associated with the Firebird Foundation.

---

*MIT License (see [LICENSE](LICENSE)). Free to fork and build your own reports!*
