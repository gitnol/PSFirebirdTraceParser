[ 🇬🇧 English ](README.md)

# 🔥 PSFirebirdTraceParser

**High-Performance PowerShell Parser & Pseudonymizer für Firebird Trace Logs.**

> **Hinweis**: Dieses Repository enthält die **Core Parsing Engine**, die **Pseudonymisierungs-Tools** und die Skripte zum **Aufzeichnen** eines Traces. Es generiert strukturierte PowerShell-Objekte, die du weiterverarbeiten, analysieren oder in deine eigenen Reporting-Systeme exportieren kannst. Diagramme und Empfehlungen liefert das Schwesterprojekt [firebird-trace-report-generator](https://github.com/gitnol/firebird-trace-report-generator).

---

## 📋 Inhaltsverzeichnis
1. [Funktionalität](#functionality)
2. [Schnellstart](#quickstart)
3. [Voraussetzungen](#requirements)
4. [Dokumentation](#documentation)
5. [Referenz](#usage)
6. [Haftungsausschluss (Disclaimer)](#disclaimer)

---

<a id="functionality"></a>
## ⚡ Funktionalität
Firebird Trace Logs sind Textdateien mit einem mehrzeiligen Block je Ereignis und deshalb schwer programmgesteuert zu verarbeiten. Dieses Projekt löst das Problem:

1.  **Parsen (`Show-TraceStructure.ps1`)**: Liest rohe Trace Logs (auch mehrere GB, der Speicherbedarf bleibt begrenzt) und gibt je Ereignis ein strukturiertes PowerShell-Objekt (`[PSObject]`, 46 Eigenschaften) aus.
2.  **Pseudonymisieren (`Pseudonymize-FirebirdTrace.ps1`)**: Ersetzt sensible Daten (Benutzernamen, IP-Adressen, SQL-Werte) durch Pseudonyme (Hash mit Schlüssel), um Logs für externe Analysen teilbar zu machen.
3.  **Aufzeichnen (`trace_start.ps1`, `trace_stop.ps1`)**: Startet und stoppt eine benannte Trace-Sitzung mit `fbtracemgr`, ohne Passwort in der Befehlszeile.

```
trace.log ──► Show-TraceStructure.ps1 ──► Objekte ──► deine Auswertung / Export-Csv
                                             └──► Pseudonymize-FirebirdTrace.ps1 ──► sicherer Export
                                             └──► New-TraceReport.ps1 (Report-Generator) ──► HTML-Bericht
```

---

<a id="quickstart"></a>
## 🚀 Schnellstart

### 1. Parsen und Anzeigen (GridView)
```powershell
.\Show-TraceStructure.ps1 -Path "C:\db\trace.log" -Verbose | Out-GridView
```
`-Verbose` zeigt die verwendete Engine, die Zahl der Ereignisse je `Action`, Warnungen und die Laufzeit.

### 2. Export nach CSV (Excel)
```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | Export-Csv -Path "trace_export.csv" -NoTypeInformation
```

### 3. Parsen, Bereinigen und Exportieren
Verarbeite ein sensibles Produktions-Log, verstecke spezifische Schlüsselwörter und alle Zeichenfolgen (Strings) und exportiere es dann:
```powershell
.\Show-TraceStructure.ps1 -Path "prod_trace.log" | `
.\Pseudonymize-FirebirdTrace.ps1 -SensitiveKeywords "SecretClient", "Vertraulich" -RedactLiterals -KeyFile "C:\keys\trace.key" | `
Export-Csv "safe_trace.csv"
```

### 4. HTML-Bericht erzeugen
```powershell
.\Show-TraceStructure.ps1 -Path "trace.log" | ..\firebird-trace-report-generator\New-TraceReport.ps1 -FilePath "Report.html"
```

---

<a id="requirements"></a>
## 🛠 Voraussetzungen
*   **Parser und Pseudonymisierer:** PowerShell 7.x (empfohlen 7.6 LTS) oder Windows PowerShell 5.1; keine Module, kein Netzwerk.
*   **Trace aufzeichnen:** PowerShell **7.4 oder neuer**, `fbtracemgr.exe` einer Firebird-4.0/5.0-Installation, Zugang zum lokalen Service-Manager.
*   **C#-Parser (optional, schneller):** .NET SDK, um `FirebirdTraceParser.dll` einmal zu bauen (siehe unten); läuft in PowerShell 7.4+.
*   Entwicklung: Pester und PSScriptAnalyzer in den Versionen aus `tests/RequiredModules.psd1`.

---

<a id="documentation"></a>
## 📚 Dokumentation
Die Dokumentation in `docs/` ist auf Deutsch.

| Für | Dokument |
|---|---|
| Analysten: parsen, Objekte lesen, filtern, pseudonymisieren, weitergeben | [Benutzerhandbuch](docs/handbuch/BENUTZERHANDBUCH.md) |
| Administratoren: installieren, Trace aufzeichnen, C#-Parser bauen, Schlüssel, Updates, Fehlersuche | [Adminhandbuch](docs/handbuch/ADMINHANDBUCH.md) |
| Jedes Ausgabefeld, je Ereignistyp | [docs/features/TRACE_PARSING.md](docs/features/TRACE_PARSING.md) |
| Was pseudonymisiert wird und was nicht | [docs/features/PSEUDONYMIZATION.md](docs/features/PSEUDONYMIZATION.md) |
| Trace aufzeichnen, Konfiguration, Exit-Codes | [docs/features/TRACE_CAPTURE.md](docs/features/TRACE_CAPTURE.md) |
| Architektur und Entscheidungen | [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md), `docs/architecture/ADR/` |
| Projektstand, Changelog, bekannte Probleme | [docs/STATE.md](docs/STATE.md), [docs/CHANGELOG.md](docs/CHANGELOG.md), [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) |

---

<a id="usage"></a>
## 🔎 Referenz

### Der Parser: `Show-TraceStructure.ps1`
Liest die Datei in 4-MB-Stücken (Speicherbedarf begrenzt, unabhängig von der Dateigröße) und gibt jedes Trace-Ereignis sofort als Objekt in die Pipeline. Statusmeldungen: `-Verbose` (am Ende auch eine Zusammenfassung: Zahl der Ereignisse je `Action` und der Warnungen).

Ereignisse, die sich nicht zuordnen lassen (unlesbare Kopfzeile, `Unknown event …`, Text vor dem ersten Ereignis), meldet der Parser als Warnung mit Zeilennummer; die Warnung zeigt keinen Trace-Inhalt. Schutz vor sehr langen Ereignissen: `-MaxBlockLines` (Standard `100000`; längere Ereignisse werden gekürzt, Warnung) und `-RegexTimeoutSeconds` (Standard `2` je Feld; danach bleiben die restlichen Felder leer, Warnung).

**Zwei Parser, gleiches Ergebnis (`-Engine`):** Den Parser gibt es auch in C# (`src/FirebirdTraceParser`, ein Binär-Cmdlet `ConvertFrom-FirebirdTrace` für PowerShell 7.4+). `-Engine Auto` (Standard) nimmt ihn, wenn PowerShell 7 läuft und die gebaute `FirebirdTraceParser.dll` neben dem Skript oder unter `bin/` liegt; sonst läuft der PowerShell-Parser (unter Windows PowerShell 5.1 immer). `-Engine PowerShell` / `-Engine CSharp` wählen ausdrücklich (`CSharp` ohne DLL oder unter 5.1 ist ein Fehler). Beide liefern dieselben Objekte, Warnungen und Verbose-Meldungen — ein Paritätstest vergleicht jedes Feld. Der C#-Parser ist deutlich schneller (gemessen an einem synthetischen 15-MB-Log: 1,6 s statt 13–14 s, höchster Arbeitsspeicher 196 MB statt 287 MB). Einmal mit dem .NET SDK bauen:

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build    # -> bin/FirebirdTraceParser.dll
.\Show-TraceStructure.ps1 -Path trace.log -Verbose        # "Engine: CSharp"
```

**Ausgabe-Objekte.** Jedes Objekt hat alle 46 Eigenschaften; was zu einem Ereignis nicht passt, ist `$null` (Zähler `0`). Welches Ereignis welche Felder füllt, steht je `Action` in [docs/features/TRACE_PARSING.md](docs/features/TRACE_PARSING.md).

| Gruppe | Eigenschaften |
|---|---|
| Ereignis | `Timestamp` (Text), `Action` (z. B. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `START_TRANSACTION`, `ERROR`, `WARNING`, `SWEEP_FINISH`, `START_SERVICE`), `ProcessID`, `SessionID` |
| Verbindung | `AttachID` (die Nummer aus `ATT_<n>`), `User` (`BENUTZER:ROLLE`), `ClientIP`, `ClientPort`, `ProtocolInfo`, `DatabasePath` |
| Anwendung | `ApplicationPath`, `ApplicationPID` |
| Transaktion | `TransactionID`, `RootTxID` (Ausgangstransaktion, `NoTx` wenn keine), `TransactionOptions` und seine Teile `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` |
| SQL | `SqlStatement`, `SqlPlan`, `Params` (`param0 = typ, "wert"`) |
| Leistung | `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` (Zähler, `long`), `RecordsFetched` (gelieferte Datensätze; `Fetches` zählt Seitenzugriffe; `0`, wenn die Zeile fehlt) |
| Tabellenstatistik | `TableStats` (Text, Spaltenausrichtung bleibt erhalten) und `TableCounts` (Liste, je Tabelle ein Objekt: `Table`, `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge`; für CSV aufklappen oder `TableStats` exportieren) |
| Fehler | `ErrorSource`, `ErrorCodes`, `ErrorMessages` — bei `ERROR AT …` / `WARNING AT …` (Deadlocks, Sperrkonflikte, SQL-Fehler) |
| Routinen | `RoutineType` (`Procedure`, `Function`, `Trigger`), `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent`; braucht `log_procedure_finish` / `log_function_finish` / `log_trigger_finish` (in `fbtrace50.conf` aus; Trigger können sehr viele Ereignisse erzeugen) |
| Sonstiges | `ConnectionDurationMs` (bei `DETACH_DATABASE`: Zeit seit dem `ATTACH_DATABASE` derselben Verbindung in dieser Datei; leer, wenn die Verbindung vor dem Trace begann), `ServiceName`, `ServiceID` (braucht `log_services`), `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` (braucht `log_sweep`) |

Nicht jedes Ereignis hat jedes Feld. Die wichtigsten Fälle:

| Ereignis | Enthält | Enthält **nicht** |
|---|---|---|
| `EXECUTE_STATEMENT_FINISH` | SQL, Plan, Parameter, Tabellenstatistik, Leistung, Transaktion, Verbindung | — |
| `EXECUTE_PROCEDURE/FUNCTION/TRIGGER_FINISH` | Routinenname, Parameter, Leistung | `SqlStatement` |
| `ERROR`, `WARNING` | Verbindung, Quelle, Codes, Meldungen | SQL, Transaktion, Leistung — **ein Fehlerereignis sagt nicht, welches Statement es ausgelöst hat** |
| `FAILED EXECUTE_STATEMENT_FINISH` | SQL und Parameter | den Fehlertext (er steht in einem eigenen `ERROR`-Ereignis) |
| `START_/COMMIT_/ROLLBACK_TRANSACTION` | Transaktion, Verbindung | SQL |

### Der Pseudonymisierer: `Pseudonymize-FirebirdTrace.ps1`
Entwickelt für DSGVO/GDPR-Konformität beim Teilen von Logs.

*   **Hashing**: HMAC-SHA256 mit geheimem Schlüssel (gekürzt). Die Schlüsseldatei (`-KeyFile`) wie ein Passwort behandeln: ohne sie lassen sich Pseudonyme nicht gegen vermutete Werte prüfen; mit gleichem Schlüssel bleiben sie über Läufe vergleichbar.
*   **Kontext-Sensitiv**: Erhält SQL-Operatoren (`LIKE`, `=`, etc.), versteckt aber die Werte.
    *   `SELECT * FROM Users WHERE Name = 'Muster'`
    *   wird zu
    *   `SELECT * FROM Users WHERE Name = '<HASH:8b3e...>'`

**Parameter:**
*   `-SensitiveKeywords "A", "B"`: Liste von Wörtern, die immer gehasht werden sollen.
*   `-RedactLiterals`: Zwingt das Hashen **ALLER** Zeichenfolgen (empfohlen für maximale Sicherheit).
*   `-AnalyzeOnly`: Vorschau, was geschwärzt würde, ohne Daten zu ändern (der Bericht geht nur auf die Konsole, im Klartext).
*   `-KeyFile <pfad>`: Geheimer Schlüssel (wird erzeugt, wenn er fehlt). Gleicher Schlüssel = gleiche Pseudonyme über mehrere Läufe. Ohne ihn gilt ein Zufallsschlüssel nur für diesen Lauf.
*   `-MappingFile <pfad>`: Optionale CSV `Pseudonym;Original`, damit der Verantwortliche Ergebnisse zurückführen kann. Enthält Klartext.
*   `-HashLength <8..64>`: Länge des Pseudonyms (Standard 12).

**Pseudonymisiert:** `User`, `ClientIP` (auch in `ProtocolInfo`), `ApplicationPath`, `DatabasePath`, Werte in `Params`; mit `-RedactLiterals` zusätzlich alle Zeichenketten und Zahlen in `SqlStatement` und Werte in `ErrorMessages`.
**Nicht pseudonymisiert:** `SqlPlan`, `TableStats`, `TableCounts` sowie Tabellen-/Indexnamen (für die Analyse nötig; `-SensitiveKeywords` verbirgt sie nicht — müssen Tabellennamen geheim bleiben, diese Felder weglassen), technische IDs, Zeitstempel, Zähler (auch `RecordsFetched`, `ConnectionDurationMs`), Transaktionsoptionen, `ServiceName`/`ServiceID` und Sweep-Zähler, Namen von Prozeduren, Funktionen und Triggern (`RoutineName`, `TriggerTable`; Schema-Namen wie Tabellennamen).

> [!WARNING]
> **Sicherheitshinweis**: Dieses Werkzeug pseudonymisiert (Hash mit Schlüssel, HMAC-SHA256), es anonymisiert nicht. Wer den Schlüssel hat, kann vermutete Werte prüfen; für den Verantwortlichen bleiben die Daten personenbezogen (DSGVO). Schlüssel- und Zuordnungsdatei (`-MappingFile`) nie weitergeben.

### Trace aufzeichnen: `trace_start.ps1` / `trace_stop.ps1`
Startet und stoppt eine Firebird-Trace-Sitzung (Firebird 4.0 / 5.0) mit `fbtracemgr`. Braucht **PowerShell 7.4+** (die Logdatei wird byte-genau geschrieben).

1. `config.sample.json` nach `config.json` kopieren (bleibt lokal, von git ignoriert) und anpassen. In `config.json` steht kein Passwort:
   entweder `PasswordFile` (Datei, deren erste Zeile das Passwort ist; `fbtracemgr` liest sie selbst, die Befehlszeile zeigt nur den Pfad) oder `"UseTrustedAuth": true` (Windows-Anmeldung).
2. Passwortdatei anlegen und auf das eigene Konto beschränken:
   ```powershell
   $dir = Join-Path $env:LOCALAPPDATA 'PSFirebirdTraceParser'; $null = New-Item -ItemType Directory -Force $dir
   $pw = Read-Host 'Firebird-Passwort' -MaskInput
   Set-Content -Path (Join-Path $dir 'firebird-trace.pass') -Value $pw -NoNewline -Encoding ascii; Remove-Variable pw
   icacls (Join-Path $dir 'firebird-trace.pass') /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
   ```
3. Fenster 1: `pwsh -File .\trace_start.ps1` (bleibt belegt, solange der Trace läuft). Fenster 2: `pwsh -File .\trace_stop.ps1` (oder `-Id <n>`).

| Schlüssel (`Firebird.…`) | Bedeutung |
|---|---|
| `FirebirdPath` | Ordner mit `fbtracemgr.exe` |
| `Username` / `PasswordFile` | Firebird-Benutzer und Passwortdatei (`%VAR%` erlaubt) |
| `UseTrustedAuth` | `true` = Windows-Anmeldung statt Benutzer und Passwortdatei |
| `Role` | Optional: Rolle mit dem Systemrecht `TRACE_ANY_ATTACHMENT` (statt SYSDBA) |
| `TraceConfigFilename` | Trace-Regeln neben den Skripten, z. B. `fbtrace50.conf` (alle Fehler, Sweeps, Services) |
| `OutputDirectory` | Ziel der Logdatei `trace_output_<Zeitstempel>.log` (`%VAR%` erlaubt) |
| `SessionName` | Präfix des Sitzungsnamens; `trace_stop.ps1` findet die Sitzung über diesen Namen |

Ein Trace-Benutzer mit Rolle statt SYSDBA (Firebird 4/5; Namen sind Beispiele), als SYSDBA, verbunden mit der Datenbank, die aufgezeichnet werden soll:

```sql
CREATE USER TRACE_USER PASSWORD '<neues Passwort>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Danach in `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"` und das Passwort von `TRACE_USER` in die Passwortdatei (oder `"UseTrustedAuth": true`). Stand das SYSDBA-Passwort je auf einer Befehlszeile (z. B. `fbtracemgr -PASS`), das Passwort ändern. Ausführlich: [docs/operations/SETUP.md](docs/operations/SETUP.md) und das [Adminhandbuch](docs/handbuch/ADMINHANDBUCH.md).

Exit-Codes: 0 ok, 1 `config.json` fehlt, 2 Konfiguration ungültig (alle Fehler werden genannt; auch, wenn noch ein Schlüssel `Password` drinsteht), 3 keine Sitzung gefunden, 4 mehrere Sitzungen passen, 5 Fehler von `fbtracemgr`, 6 unerwarteter Fehler.

---

<a id="disclaimer"></a>
## ⚖ Haftungsausschluss (Disclaimer)

**Firebird ist eine eingetragene Marke der Firebird Foundation.**
Dieses Tool ist Open-Source-Software und ist **nicht** mit der Firebird Foundation verbunden, von ihr unterstützt oder assoziiert.

---

*MIT Lizenz (siehe [LICENSE](LICENSE)). Frei zum Forken und Bauen eigener Reports!*
