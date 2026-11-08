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
3.  **Aufzeichnen (`trace_start.ps1`, `trace_stop.ps1`)**: Startet und stoppt eine benannte Trace-Sitzung mit `fbtracemgr`, ohne Passwort in der Befehlszeile.

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
Liest die Datei in 4-MB-Stücken (Speicherbedarf begrenzt, unabhängig von der Dateigröße) und gibt jedes Trace-Ereignis sofort als Objekt in die Pipeline. Statusmeldungen: `-Verbose` (am Ende auch eine Zusammenfassung: Zahl der Ereignisse je `Action` und der Warnungen).

Ereignisse, die sich nicht zuordnen lassen (unlesbare Kopfzeile, `Unknown event …`, Text vor dem ersten Ereignis), meldet der Parser als Warnung mit Zeilennummer; die Warnung zeigt keinen Trace-Inhalt. Schutz vor sehr langen Ereignissen: `-MaxBlockLines` (Standard `100000`; längere Ereignisse werden gekürzt, Warnung) und `-RegexTimeoutSeconds` (Standard `2` je Feld; danach bleiben die restlichen Felder leer, Warnung). Die Objekte sind dieselben wie vorher; nur in diesen seltenen Fällen kommt eine Warnung dazu.

**Zwei Parser, gleiches Ergebnis (`-Engine`):** Seit 2026-11 gibt es den Parser auch in C# (`src/FirebirdTraceParser`,
ein Binär-Cmdlet für PowerShell 7.4+). `-Engine Auto` (Standard) nimmt ihn, wenn PowerShell 7 läuft und die gebaute
`FirebirdTraceParser.dll` neben dem Skript oder unter `bin/` liegt; sonst läuft der PowerShell-Parser (unter Windows
PowerShell 5.1 immer). `-Engine PowerShell` / `-Engine CSharp` wählen ausdrücklich (`CSharp` ohne DLL oder unter 5.1
ist ein Fehler). Beide liefern dieselben Objekte, Warnungen und Verbose-Meldungen — ein Paritätstest vergleicht jedes
Feld. Der C#-Parser ist deutlich schneller (gemessen an einem synthetischen 15-MB-Log: 1,6 s statt 13–14 s, höchster Arbeitsspeicher 196 MB statt 287 MB). Einmal mit dem .NET SDK bauen:

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build    # -> bin/FirebirdTraceParser.dll
.\Show-TraceStructure.ps1 -Path trace.log -Verbose        # "Engine: CSharp"
```

**Eigenschaften der Ausgabe-Objekte:**
*   `Timestamp`: Zeitstempel des Events.
*   `DurationMs`: Ausführungsdauer in Millisekunden.
*   `SqlStatement`: Die vollständige SQL-Abfrage.
*   `SqlPlan`: Ausführungsplan (z.B. `NATURAL`, `INDEX`).
*   `Fetches`, `Reads`, `Writes`, `Marks`: E/A-Statistiken.
*   `User` (`BENUTZER:ROLLE`), `ClientIP`, `ClientPort`, `ProtocolInfo`, `DatabasePath`, `AttachID`: Verbindungsdetails.
*   `ApplicationPath`, `ApplicationPID`: Client-Anwendung.
*   `TransactionID`, `RootTxID`, `TransactionOptions`: Transaktion (`RootTxID` = Ausgangstransaktion, `NoTx` wenn keine).
*   `Params`: Statement-Parameter (`param0 = typ, "wert"`).
*   `TableStats`: Tabellenstatistik je Tabelle (`Natural`, `Index`, …), Spaltenausrichtung bleibt erhalten.
*   `Timestamp`, `ProcessID`, `SessionID`: Kopfzeile jedes Trace-Ereignisses.
*   `Action`: Ereignisname, z. B. `EXECUTE_STATEMENT_FINISH`, `FAILED EXECUTE_STATEMENT_FINISH`, `ERROR`, `WARNING`, `SWEEP_FINISH`, `START_SERVICE`.
*   `ErrorSource`, `ErrorCodes`, `ErrorMessages`: Bei `ERROR AT …` / `WARNING AT …` (z. B. Deadlocks, Sperrkonflikte).
*   `ServiceName`, `ServiceID`: Bei Dienst-Ereignissen (`ATTACH_SERVICE`, `START_SERVICE`, …), z. B. `Backup Database`; Benutzer, Adresse und Programm des Dienstes stehen in den Verbindungsfeldern. Braucht `log_services` (in `fbtrace50.conf` an).
*   `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext`: Transaktionszähler bei `SWEEP_START` / `SWEEP_FINISH`. Braucht `log_sweep` (in `fbtrace50.conf` an).
*   `RecordsFetched`: Zahl der gelieferten Datensätze (`N records fetched`); `Fetches` zählt dagegen Seitenzugriffe. `0`, wenn die Zeile fehlt (Firebird lässt sie bei Prozeduren mit 0 Datensätzen weg).
*   `TxIsolation` (`READ_COMMITTED`, `CONCURRENCY`, `CONSISTENCY`), `TxReadMode` (`REC_VERSION`, `NO_REC_VERSION`, `READ_CONSISTENCY`; nur bei `READ_COMMITTED`), `TxWaitMode` (`WAIT`, `NOWAIT`), `TxLockTimeout` (Sekunden bei `WAIT <n>`, sonst leer), `TxAccessMode` (`READ_WRITE`, `READ_ONLY`): die Teile von `TransactionOptions`.
*   `TableCounts`: `TableStats` als Liste mit einem Objekt je Tabelle (`Table`, `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge`; leere Zelle = `0`). Es ist eine Liste: für CSV aufklappen (`$_.TableCounts | Select-Object …`) oder `TableStats` exportieren.
*   `RoutineType` (`Procedure`, `Function`, `Trigger`), `RoutineName`: Bei `EXECUTE_PROCEDURE_FINISH`, `EXECUTE_FUNCTION_FINISH`, `EXECUTE_TRIGGER_FINISH` (auch `FAILED …`); Laufzeit, I/O, Parameter und Tabellenstatistik stehen in den üblichen Feldern. Filtern über `Action` oder `RoutineType`; Statements bleiben unverändert. Braucht `log_procedure_finish` / `log_function_finish` / `log_trigger_finish` (in `fbtrace50.conf` aus; Trigger können sehr viele Ereignisse erzeugen).
*   `TriggerTable`, `TriggerTime` (`BEFORE`, `AFTER`, `ON` bei Datenbank-Triggern), `TriggerEvent` (`INSERT`, `UPDATE`, `DELETE`, `CONNECT`, …): Die Trigger-Zeile; Firebird 4 und 5 schreiben sie verschieden, beide werden gelesen.
*   `ConnectionDurationMs`: Bei `DETACH_DATABASE` die Zeit seit dem `ATTACH_DATABASE` derselben Verbindung in dieser Datei; leer, wenn die Verbindung vor dem Trace begann.

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
*   `-AnalyzeOnly`: Vorschau, was geschwärzt würde, ohne Daten zu ändern.
*   `-KeyFile <pfad>`: Geheimer Schlüssel (wird erzeugt, wenn er fehlt). Gleicher Schlüssel = gleiche Pseudonyme über mehrere Läufe. Ohne ihn gilt ein Zufallsschlüssel nur für diesen Lauf.
*   `-MappingFile <pfad>`: Optionale CSV `Pseudonym;Original`, damit der Verantwortliche Ergebnisse zurückführen kann. Enthält Klartext.

**Pseudonymisiert:** `User`, `ClientIP` (auch in `ProtocolInfo`), `ApplicationPath`, `DatabasePath`, Werte in `Params`; mit `-RedactLiterals` zusätzlich alle Zeichenketten und Zahlen in `SqlStatement` und Werte in `ErrorMessages`.
**Nicht pseudonymisiert:** `SqlPlan`, `TableStats`, `TableCounts` sowie Tabellen-/Indexnamen (für die Analyse nötig; `-SensitiveKeywords` verbirgt sie nicht — müssen Tabellennamen geheim bleiben, diese Felder weglassen), technische IDs, Zeitstempel, Zähler (auch `RecordsFetched`, `ConnectionDurationMs`), Transaktionsoptionen, `ServiceName`/`ServiceID` und Sweep-Zähler, Namen von Prozeduren, Funktionen und Triggern (`RoutineName`, `TriggerTable`; Schema-Namen wie Tabellennamen).

> [!WARNING]
> **Sicherheitshinweis**: Dieses Werkzeug pseudonymisiert (Hash mit Schlüssel, HMAC-SHA256), es anonymisiert nicht. Wer den Schlüssel hat, kann vermutete Werte prüfen; für den Verantwortlichen bleiben die Daten personenbezogen (DSGVO). Schlüssel- und Zuordnungsdatei (`-MappingFile`) nie weitergeben.

---

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

#### Eigener Trace-Benutzer statt SYSDBA (Firebird 4/5)
Ein normaler Benutzer darf fremde Verbindungen tracen, wenn eine Rolle mit dem Systemrecht `TRACE_ANY_ATTACHMENT` aktiv ist. Als SYSDBA, verbunden mit der Datenbank, die aufgezeichnet werden soll (Namen sind Beispiele):

```sql
CREATE USER TRACE_USER PASSWORD '<neues Passwort>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Danach in `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"` und das Passwort von `TRACE_USER` in die Passwortdatei (oder `"UseTrustedAuth": true`). Stand das SYSDBA-Passwort je auf einer Befehlszeile (z. B. `fbtracemgr -PASS`), das Passwort ändern. Ausführlich: [docs/operations/SETUP.md](docs/operations/SETUP.md).

Exit-Codes: 0 ok, 1 `config.json` fehlt, 2 Konfiguration ungültig (alle Fehler werden genannt; auch, wenn noch ein Schlüssel `Password` drinsteht), 3 keine Sitzung gefunden, 4 mehrere Sitzungen passen, 5 Fehler von `fbtracemgr`, 6 unerwarteter Fehler.

---

<a id="disclaimer"></a>
## ⚖ Haftungsausschluss (Disclaimer)

**Firebird ist eine eingetragene Marke der Firebird Foundation.**
Dieses Tool ist Open-Source-Software und ist **nicht** mit der Firebird Foundation verbunden, von ihr unterstützt oder assoziiert.

---

*MIT Lizenz (siehe [LICENSE](LICENSE)). Frei zum Forken und Bauen eigener Reports!*
