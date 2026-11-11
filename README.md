[ 🇩🇪 Deutsch ](README.de.md)

# 🔥 PSFirebirdTraceParser

**High-Performance PowerShell Parser & Pseudonymizer for Firebird Trace Logs.**

> **Note**: This repository contains the **Core Parsing Engine**, the **Pseudonymization Tools** and the scripts to **capture** a trace. It generates structured PowerShell objects that you can process, analyze, or export to your own reporting systems. Charts and recommendations come from the sister project [firebird-trace-report-generator](https://github.com/gitnol/firebird-trace-report-generator).

---

## 📋 Table of Contents
1. [Functionality](#functionality)
2. [Quick Start](#quickstart)
3. [Requirements](#requirements)
4. [Documentation](#documentation)
5. [Reference](#usage)
6. [Disclaimer](#disclaimer)

---

<a id="functionality"></a>
## ⚡ Functionality
Firebird trace logs are text files with a multi-line block per event, which makes them hard to process in a program. This project solves that:

1.  **Parse (`Show-TraceStructure.ps1`)**: Reads raw trace logs (GBs in size, memory stays bounded) and writes one structured PowerShell object (`[PSObject]`, 46 properties) per event.
2.  **Pseudonymize (`Pseudonymize-FirebirdTrace.ps1`)**: Replaces sensitive data (user names, IP addresses, SQL values) with keyed hash pseudonyms so that logs can be shared for external analysis.
3.  **Capture (`trace_start.ps1`, `trace_stop.ps1`)**: Starts and stops a named trace session with `fbtracemgr`, without a password on the command line.

```
trace.log ──► Show-TraceStructure.ps1 ──► objects ──► your analysis / Export-Csv
                                             └──► Pseudonymize-FirebirdTrace.ps1 ──► safe export
                                             └──► New-TraceReport.ps1 (report generator) ──► HTML report
```

---

<a id="quickstart"></a>
## 🚀 Quick Start

### 1. Parse and View in Grid
```powershell
.\Show-TraceStructure.ps1 -Path "C:\db\trace.log" -Verbose | Out-GridView
```
`-Verbose` shows the engine in use, the number of events per `Action`, warnings and the run time.

### 2. Export to CSV (Excel)
```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | Export-Csv -Path "trace_export.csv" -NoTypeInformation
```

### 3. Parse, Sanitize, and Export
Process a sensitive production log, hide specific keywords and all string literals, then export:
```powershell
.\Show-TraceStructure.ps1 -Path "prod_trace.log" | `
.\Pseudonymize-FirebirdTrace.ps1 -SensitiveKeywords "SecretClient", "Confidential" -RedactLiterals -KeyFile "C:\keys\trace.key" | `
Export-Csv "safe_trace.csv"
```

### 4. Build an HTML report
```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | ..\firebird-trace-report-generator\New-TraceReport.ps1 -FilePath "Report.html"
```

---

<a id="requirements"></a>
## 🛠 Requirements
*   **Parser and pseudonymizer:** PowerShell 7.x (7.6 LTS recommended) or Windows PowerShell 5.1; no modules, no network.
*   **Trace capture:** PowerShell **7.4 or later**, `fbtracemgr.exe` of a Firebird 4.0/5.0 installation, access to the local service manager.
*   **C# parser (optional, faster):** .NET SDK to build `FirebirdTraceParser.dll` once (see below); runs in PowerShell 7.4+.
*   Developing: Pester and PSScriptAnalyzer in the versions pinned in `tests/RequiredModules.psd1`.

---

<a id="documentation"></a>
## 📚 Documentation
The documentation in `docs/` is in German.

| For | Document |
|---|---|
| Analysts: parse, read the objects, filter, pseudonymize, hand over | [Benutzerhandbuch](docs/handbuch/BENUTZERHANDBUCH.md) |
| Administrators: install, capture a trace, build the C# parser, keys, updates, troubleshooting | [Adminhandbuch](docs/handbuch/ADMINHANDBUCH.md) |
| Every output field, per event type | [docs/features/TRACE_PARSING.md](docs/features/TRACE_PARSING.md) |
| What is pseudonymized and what is not | [docs/features/PSEUDONYMIZATION.md](docs/features/PSEUDONYMIZATION.md) |
| Capturing a trace, configuration, exit codes | [docs/features/TRACE_CAPTURE.md](docs/features/TRACE_CAPTURE.md) |
| Architecture and decisions | [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md), `docs/architecture/ADR/` |
| Project state, changelog, known issues | [docs/STATE.md](docs/STATE.md), [docs/CHANGELOG.md](docs/CHANGELOG.md), [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) |

---

<a id="usage"></a>
## 🔎 Reference

### The Parser: `Show-TraceStructure.ps1`
Streams the file in 4 MB chunks (memory stays bounded, independent of file size) and writes one object per trace event to the pipeline as soon as the event is complete. Status messages: `-Verbose` (at the end also a summary: number of events per `Action` and of warnings).

Events that cannot be assigned (unreadable header, `Unknown event …`, text before the first event) are reported as warnings with the line number; the warning shows no trace content. Protection against very long events: `-MaxBlockLines` (default `100000`; longer events are cut, warning) and `-RegexTimeoutSeconds` (default `2` per field; when reached, the remaining fields stay empty, warning).

**Two parsers, same result (`-Engine`):** The parser also exists in C# (`src/FirebirdTraceParser`, a binary cmdlet `ConvertFrom-FirebirdTrace` for PowerShell 7.4+). `-Engine Auto` (default) uses it when PowerShell 7 runs and the built `FirebirdTraceParser.dll` lies next to the script or in `bin/`; otherwise the PowerShell parser runs (always under Windows PowerShell 5.1). `-Engine PowerShell` / `-Engine CSharp` choose explicitly (`CSharp` without the DLL or under 5.1 is an error). Both give the same objects, warnings and verbose messages — a parity test compares every field. The C# parser is much faster (measured on a 15 MB synthetic log: 1.6 s instead of 13–14 s, peak memory 196 MB instead of 287 MB). Build it once with the .NET SDK:

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build    # -> bin/FirebirdTraceParser.dll
.\Show-TraceStructure.ps1 -Path trace.log -Verbose        # "Engine: CSharp"
```

**Output objects.** Every object has all 46 properties; those that do not apply to an event are `$null` (counters `0`). Which event fills which fields is listed per `Action` in [docs/features/TRACE_PARSING.md](docs/features/TRACE_PARSING.md).

| Group | Properties |
|---|---|
| Event | `Timestamp` (text), `Action` (e.g. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `START_TRANSACTION`, `ERROR`, `WARNING`, `SWEEP_FINISH`, `START_SERVICE`), `ProcessID`, `SessionID` |
| Connection | `AttachID` (the number of `ATT_<n>`), `User` (`USER:ROLE`), `ClientIP`, `ClientPort`, `ProtocolInfo`, `DatabasePath` |
| Application | `ApplicationPath`, `ApplicationPID` |
| Transaction | `TransactionID`, `RootTxID` (initial transaction, `NoTx` if none), `TransactionOptions` and its parts `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` |
| SQL | `SqlStatement`, `SqlPlan`, `Params` (`param0 = type, "value"`) |
| Performance | `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` (counters, `long`), `RecordsFetched` (rows returned; `Fetches` counts page fetches; `0` if the line is missing) |
| Table statistics | `TableStats` (text, column alignment preserved) and `TableCounts` (list, one object per table: `Table`, `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge`; for CSV expand it or export `TableStats`) |
| Errors | `ErrorSource`, `ErrorCodes`, `ErrorMessages` — for `ERROR AT …` / `WARNING AT …` events (deadlocks, lock conflicts, SQL errors) |
| Routines | `RoutineType` (`Procedure`, `Function`, `Trigger`), `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent`; needs `log_procedure_finish` / `log_function_finish` / `log_trigger_finish` (off in `fbtrace50.conf`; triggers can produce very many events) |
| Other | `ConnectionDurationMs` (on `DETACH_DATABASE`: time since `ATTACH_DATABASE` of the same connection in this file; empty if it started before the trace), `ServiceName`, `ServiceID` (needs `log_services`), `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` (needs `log_sweep`) |

Not every event has every field. The most important cases:

| Event | Contains | Does **not** contain |
|---|---|---|
| `EXECUTE_STATEMENT_FINISH` | SQL, plan, parameters, table statistics, performance, transaction, connection | — |
| `EXECUTE_PROCEDURE/FUNCTION/TRIGGER_FINISH` | routine name, parameters, performance | `SqlStatement` |
| `ERROR`, `WARNING` | connection, source, codes, messages | SQL, transaction, performance — **an error event does not say which statement caused it** |
| `FAILED EXECUTE_STATEMENT_FINISH` | SQL and parameters | the error text (it is in a separate `ERROR` event) |
| `START_/COMMIT_/ROLLBACK_TRANSACTION` | transaction, connection | SQL |

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
*   `-AnalyzeOnly`: Preview what would be redacted without changing data (report goes to the console only, in plain text).
*   `-KeyFile <path>`: Secret key (created if missing). Same key = same pseudonyms across runs. Without it, a random key is used for this run only.
*   `-MappingFile <path>`: Optional CSV `Pseudonym;Original` for the data controller to map results back. Contains plaintext.
*   `-HashLength <8..64>`: Length of the pseudonym (default 12).

**Pseudonymized:** `User`, `ClientIP` (also in `ProtocolInfo`), `ApplicationPath`, `DatabasePath`, `Params` values; with `-RedactLiterals` also all string and numeric literals in `SqlStatement` and values in `ErrorMessages`.
**Not pseudonymized:** `SqlPlan`, `TableStats`, `TableCounts` and table/index names (needed for analysis; `-SensitiveKeywords` does not hide them — leave these fields out if table names must stay private), technical IDs, timestamps, counters (also `RecordsFetched`, `ConnectionDurationMs`), transaction options, `ServiceName`/`ServiceID` and sweep counters, procedure/function/trigger names (`RoutineName`, `TriggerTable`; schema names like table names).

> [!WARNING]
> **Security Notice**: This tool uses **Pseudonymization** (keyed hashing, HMAC-SHA256), not Anonymization. Whoever has the key can verify guessed values; the data stays personal data for the data controller (GDPR). Never share the key file or the mapping file (`-MappingFile`).

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

A trace user with a role instead of SYSDBA (Firebird 4/5; names are examples), as SYSDBA connected to the database you want to trace:

```sql
CREATE USER TRACE_USER PASSWORD '<new password>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Then in `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"` and the password of `TRACE_USER` in the password file (or `"UseTrustedAuth": true`). If the SYSDBA password was ever typed on a command line (for example `fbtracemgr -PASS`), change it. Details: [docs/operations/SETUP.md](docs/operations/SETUP.md) and the [Adminhandbuch](docs/handbuch/ADMINHANDBUCH.md) (German).

Exit codes: 0 ok, 1 `config.json` missing, 2 configuration invalid (all errors listed; also when a `Password` key is still there), 3 no session found, 4 several sessions match, 5 `fbtracemgr` error, 6 unexpected error.

---

<a id="disclaimer"></a>
## ⚖ Disclaimer

**Firebird is a registered trademark of the Firebird Foundation.**
This tool is open-source software and is **not** affiliated with, endorsed by, or associated with the Firebird Foundation.

---

*MIT License (see [LICENSE](LICENSE)). Free to fork and build your own reports!*
