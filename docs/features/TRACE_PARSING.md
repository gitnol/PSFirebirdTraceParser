# Feature: Trace-Parsing (`Show-TraceStructure.ps1`)

---

## Zweck

Zerlegt ein Firebird-Trace-Log in Blöcke (ein Block je Zeitstempel-Zeile) und gibt je Block ein
`PSCustomObject` mit Verbindungs-, Transaktions-, SQL- und Performance-Feldern aus.

---

## Technologie / Abhängigkeiten

- PowerShell 5.1 / 7, .NET-Regex (kompiliert), `Get-Content -Raw`
- Lokales Dateisystem (Trace-Datei); keine Module, kein Netz

---

## Parameter

| Parameter | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `-Path` | `[string]` | Ja (Position 0) | — | keine (nur `Test-Path` im Rumpf) | Pfad zur Trace-Datei |

Kein `-WhatIf` (das Skript schreibt nichts). `[CmdletBinding()]` seit I6 → Statusmeldungen mit `-Verbose`.

---

## Ablauf (Ist)

1. Datei in Stücken von 4 MB lesen (`StreamReader`), `\r` entfernen (seit I6).
2. Jedes Stück vor jeder Zeile teilen, die mit `JJJJ-MM-TTThh:mm:ss.ffff` beginnt; der unfertige letzte Block wandert ins
   nächste Stück. Text vor dem ersten Zeitstempel wird übersprungen.
3. Je Block die kompilierten Regex anwenden (Header, Fehlerzeilen, Datenbank/Verbindung, Anwendung, Transaktion, SQL, Parameter,
   Plan, Tabellenstatistik, Performance); fehlende Treffer lassen das Feld leer bzw. auf dem Default.
4. Jedes Objekt sofort in die Pipeline geben (seit I6, vorher gesammelt am Ende).
5. Status über `Write-Verbose`, Fortschritt je Stück über `Write-Progress`.

## Ausgabe-Vertrag (Properties, Reihenfolge wie im Code)

| Property | Typ | Default | Quelle im Block |
|---|---|---|---|
| `Timestamp` | string | `$null` | Zeitstempel der Kopfzeile (nicht als `[datetime]`) |
| `Action` | string | `$null` | Ereignisname der Kopfzeile (z. B. Statement-, Transaktions-, Verbindungsereignis); `FAILED …`/`UNAUTHORIZED …` vollständig (seit I10); bei `ERROR AT …`/`WARNING AT …` nur `ERROR`/`WARNING` |
| `ProcessID`, `SessionID` | string | `$null` | `(PID:Adresse)` der Kopfzeile; die Adresse ist plattformabhängig: Windows `000001A2B3C4D5E0`, Linux `0x7f3a1c2b4d10` (beide werden erkannt, unverändert übernommen) |
| `DatabasePath` | string | `$null` | Verbindungszeile, Pfad bis `.FDB`; jede Endung, jede Rolle, auch `<internal>` und Protokolle ohne Port (seit K3-Fix 2026-11-07) |
| `AttachID` | string | `$null` | `ATT_<n>` |
| `User` | string | `$null` | Benutzer **inklusive** `:NONE` (Rolle) |
| `ProtocolInfo` | string | `$null` | z. B. `TCPv4:<ip>/<port>` |
| `ClientIP`, `ClientPort` | string | `$null` | aus `ProtocolInfo` |
| `ApplicationPath`, `ApplicationPID` | string | `$null` | Zeile `<Laufwerk-/UNC-Pfad>:<pid>` |
| `TransactionID` | string | `$null` | `TRA_<n>` |
| `RootTxID` | string | `"NoTx"` | `INIT_<n>`, sonst `TransactionID` |
| `TransactionOptions` | string | `$null` | Optionen in der Transaktionszeile |
| `Params` | string | `$null` | zusammenhängende `paramN = …`-Zeilen |
| `SqlStatement` | string | `$null` | Text nach `Statement <n>:` und Trennlinie bis Plan/Parameter/Statistik |
| `SqlPlan` | string | `$null` | zusammenhängende `PLAN …`-Zeilen |
| `TableStats` | string | `$null` | Tabellenstatistik ab `Table … Natural`, **ungetrimmt** (Spaltenausrichtung) |
| `ErrorSource` | string | `$null` | Komponente aus `ERROR AT <Komponente>` bzw. `WARNING AT …` (seit I10) |
| `ErrorCodes` | string | `$null` | Fehlercodes der Zeilen `%9lu : <Text>`, mit `, ` verbunden (nur bei `ERROR`/`WARNING`) |
| `ErrorMessages` | string | `$null` | Fehlertexte derselben Zeilen, mit ` \| ` verbunden; können Werte enthalten (`Problematic key value is (…)`) |
| `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` | int | `0` | Performance-Zeile `<n> ms, … read(s), … write(s), … fetch(es), … mark(s)` (auch bei `SWEEP_PROGRESS/FINISH/FAILED`) |
| `ServiceName` | string | `$null` | seit I15: Dienstname in Anführungszeichen bei `START_SERVICE`/`QUERY_SERVICE`, z. B. `Backup Database`, `Incremental Backup Database`, `Restore Database`, `Validate Database` (Liste in Firebird `src/jrd/svc.cpp`) |
| `ServiceID` | string | `$null` | seit I15: Adresse aus `(Service <Adresse>, …)` bei allen `*_SERVICE`-Ereignissen; Benutzer, Adresse und Programm der Dienstzeile stehen in `User`, `ProtocolInfo`/`ClientIP`/`ClientPort`, `ApplicationPath`/`ApplicationPID` |
| `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` | long | `$null` | seit I15: Block `Transaction counters:` bei `SWEEP_START` und `SWEEP_FINISH` (Oldest interesting/active/snapshot, Next transaction); bei `SWEEP_PROGRESS`/`SWEEP_FAILED` leer |

Die Schalterzeile von `START_SERVICE` (z. B. `-VERBOSE <Datenbank> <Sicherungsdatei>`) wird bewusst **nicht** gelesen:
sie enthält Dateipfade, für die es keine Pseudonymisierung gibt. Voraussetzung im Trace: `log_sweep = true` (Abschnitt
`database`) bzw. `log_services = true` (Abschnitt `services`) — beides ist in `fbtrace50.conf` eingeschaltet (seit I4/I5),
in `fbtrace30.conf` nicht.

Die Property-Namen sind Eingabe von `Pseudonymize-FirebirdTrace.ps1` und von Nutzer-Exporten — Änderungen nur
gemeinsam (`CONVENTIONS.md` §8). Die READMEs nennen seit I7 dieselben Namen (K1 behoben), seit 2026-11-08 auch die Felder aus I15.

---

## Kritische Patterns

- Regex-Objekte einmal vor der Schleife bauen (`Compiled`) — nicht pro Block.
- Fehlende Felder sind kein Fehler: ein Objekt wird immer ausgegeben (auch für unbekannte Ereignisarten).
- `TableStats` bewusst nicht trimmen.

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| `Timestamp` ist Text, kein `[datetime]` | Regex-Gruppe ohne Konvertierung | Akzeptiert (BACKLOG) |

---

## Bekannte Fallstricke

- Ein Block ohne `Statement`-Abschnitt (z. B. Verbindungs- oder Transaktionsereignis) liefert `SqlStatement = $null` — beim Gruppieren berücksichtigen.

---

## Teststrategie

- Zugehörige Testdatei: `tests/Show-TraceStructure.Tests.ps1` (I6)
- Pester-Beschreibung: `Describe 'Show-TraceStructure' { ... }`
- Fixture: synthetische Trace-Datei mit **fiktiven** Werten unter `tests/fixtures/` (je Ereignisart mindestens ein Block)
- Kritische Testfälle: jede Property aus der Tabelle oben mit exaktem Wert; Block ohne SQL; Rolle ≠ `NONE`;
  fehlende Datei → Fehler; Zähler > Int32; leere Datei → keine Objekte
