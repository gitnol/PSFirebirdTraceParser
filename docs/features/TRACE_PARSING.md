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
| `-Engine` | `[string]` | Nein | `Auto` | `[ValidateSet('Auto', 'PowerShell', 'CSharp')]` | seit I19 (ADR-003): `Auto` nimmt den C#-Parser (`ConvertFrom-FirebirdTrace` aus `FirebirdTraceParser.dll` neben dem Skript, sonst `bin/`), wenn PowerShell 7 läuft und die DLL da ist, sonst den PowerShell-Parser; `CSharp` ohne DLL oder unter 5.1 ist ein Fehler (kein Objekt). `-Verbose` schreibt `Engine: <Name>` |
| `-MaxBlockLines` | `[int]` | Nein | `100000` | `[ValidateRange(1, 2147483647)]` | seit I13: Obergrenze Zeilen je Ereignis; längere Ereignisse werden auf diese Zahl gekürzt (Warnung). Begrenzt auch den Speicher, wenn eine Datei lange keinen Zeitstempel hat |
| `-RegexTimeoutSeconds` | `[double]` | Nein | `2` | `[ValidateRange(0.001, 3600)]` | seit I13: Zeitlimit je Regex-Auswertung in einem Ereignis; danach bleiben die restlichen Felder leer (Warnung), der Parser liest das nächste Ereignis |

Kein `-WhatIf` (das Skript schreibt nichts). `[CmdletBinding()]` seit I6 → Statusmeldungen mit `-Verbose`.
Die Standardwerte ändern bei echten Traces voraussichtlich nichts: Firebird kürzt SQL (`max_sql_length`) und Parameter,
ein Ereignis hat kaum mehr als einige tausend Zeilen, und die Regex brauchen je Ereignis Millisekunden.

---

## Ablauf (Ist)

Seit I19 wählt das Skript zuerst die Engine (`-Engine`) und meldet `Engine: …` mit `-Verbose`. Der C#-Parser macht
dieselben Schritte wie unten, mit denselben Regex und Texten (ADR-003); das Skript ruft dann nur das Cmdlet auf.

1. Datei in Stücken von 4 MB lesen (`StreamReader`), `\r` entfernen (seit I6).
2. Jedes Stück vor jeder Zeile teilen, die mit `JJJJ-MM-TTThh:mm:ss.ffff` beginnt; der unfertige letzte Block wandert ins
   nächste Stück. Text vor dem ersten Zeitstempel wird übersprungen; außer Leerzeilen und `Trace session ID <n> started`
   meldet der Parser ihn als Warnung (seit I13). Wächst der unfertige Block über `-MaxBlockLines` Zeilen, wird er schon
   beim Weitertragen gekürzt (Speicher).
3. Je Block die kompilierten Regex anwenden (Header, Fehlerzeilen, Datenbank/Verbindung, Anwendung, Transaktion, SQL, Parameter,
   Plan, Tabellenstatistik, Performance); fehlende Treffer lassen das Feld leer bzw. auf dem Default.
4. Jedes Objekt sofort in die Pipeline geben (seit I6, vorher gesammelt am Ende).
5. Status über `Write-Verbose`, Fortschritt je Stück über `Write-Progress`.
6. Seit I13: Warnungen (`Write-Warning`, `Line <n>: <fester Text>`) für unlesbare Kopfzeilen, `Unknown event …`, Text vor
   dem ersten Ereignis, gekürzte Ereignisse und Zeitlimit. Die Zeilennummer wird nur beim Schreiben einer Warnung
   gezählt. Am Ende mit `-Verbose` je `Action` eine Zeile `Summary: <Action> = <Anzahl>` (unlesbare Kopfzeile als
   `(header not readable)`) und `Summary: <n> warning(s)`. Die Pipeline-Ausgabe bleibt gleich.

## Ausgabe-Vertrag (46 Properties, Reihenfolge wie im Code)

Jedes Objekt hat immer alle 46 Properties (`src/FirebirdTraceParser/TraceField.cs`; ein Probelauf mit beiden Engines
zählt 46). Nicht zutreffende Felder sind `$null`, Zähler `0` (Spalte „Default“). Welche Felder bei welchem Ereignis
gefüllt sind, steht im Abschnitt „Felder je Ereignistyp“ darunter.

| Property | Typ | Default | Quelle im Block |
|---|---|---|---|
| `Timestamp` | string | `$null` | Zeitstempel der Kopfzeile (nicht als `[datetime]`) |
| `Action` | string | `$null` | Ereignisname der Kopfzeile (z. B. Statement-, Transaktions-, Verbindungsereignis); `FAILED …`/`UNAUTHORIZED …` vollständig (seit I10); bei `ERROR AT …`/`WARNING AT …` nur `ERROR`/`WARNING` |
| `ProcessID`, `SessionID` | string | `$null` | `(PID:Adresse)` der Kopfzeile; die Adresse ist plattformabhängig: Windows `000001A2B3C4D5E0`, Linux `0x7f3a1c2b4d10` (beide werden erkannt, unverändert übernommen) |
| `DatabasePath` | string | `$null` | Verbindungszeile, Pfad bis `.FDB`; jede Endung, jede Rolle, auch `<internal>` und Protokolle ohne Port (seit K3-Fix 2026-11-07) |
| `AttachID` | string | `$null` | die Nummer aus `ATT_<n>`, **ohne** Präfix (`ATT_399921` → `399921`) |
| `User` | string | `$null` | Benutzer **inklusive** `:NONE` (Rolle) |
| `ProtocolInfo` | string | `$null` | z. B. `TCPv4:<ip>/<port>` |
| `ClientIP`, `ClientPort` | string | `$null` | aus `ProtocolInfo` |
| `ApplicationPath`, `ApplicationPID` | string | `$null` | Zeile `<Laufwerk-/UNC-Pfad>:<pid>` |
| `TransactionID` | string | `$null` | die Nummer aus `TRA_<n>`, ohne Präfix |
| `RootTxID` | string | `"NoTx"` | die Nummer aus `INIT_<n>` (ohne Präfix), sonst `TransactionID`, sonst `NoTx` |
| `TransactionOptions` | string | `$null` | Optionen in der Transaktionszeile |
| `Params` | string | `$null` | zusammenhängende `paramN = …`-Zeilen |
| `SqlStatement` | string | `$null` | Text nach `Statement <n>:` und Trennlinie bis Plan/Parameter/Statistik |
| `SqlPlan` | string | `$null` | zusammenhängende `PLAN …`-Zeilen |
| `TableStats` | string | `$null` | Tabellenstatistik ab `Table … Natural`, **ungetrimmt** (Spaltenausrichtung) |
| `ErrorSource` | string | `$null` | Komponente aus `ERROR AT <Komponente>` bzw. `WARNING AT …` (seit I10) |
| `ErrorCodes` | string | `$null` | Fehlercodes der Zeilen `%9lu : <Text>`, mit `, ` verbunden (nur bei `ERROR`/`WARNING`) |
| `ErrorMessages` | string | `$null` | Fehlertexte derselben Zeilen, mit ` \| ` verbunden; können Werte enthalten (`Problematic key value is (…)`) |
| `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` | long (`Int64`) | `0` | Performance-Zeile `<n> ms, … read(s), … write(s), … fetch(es), … mark(s)` (auch bei `SWEEP_PROGRESS/FINISH/FAILED`) |
| `ServiceName` | string | `$null` | seit I15: Dienstname in Anführungszeichen bei `START_SERVICE`/`QUERY_SERVICE`, z. B. `Backup Database`, `Incremental Backup Database`, `Restore Database`, `Validate Database` (Liste in Firebird `src/jrd/svc.cpp`) |
| `ServiceID` | string | `$null` | seit I15: Adresse aus `(Service <Adresse>, …)` bei allen `*_SERVICE`-Ereignissen; Benutzer, Adresse und Programm der Dienstzeile stehen in `User`, `ProtocolInfo`/`ClientIP`/`ClientPort`, `ApplicationPath`/`ApplicationPID` |
| `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` | long | `$null` | seit I15: Block `Transaction counters:` bei `SWEEP_START` und `SWEEP_FINISH` (Oldest interesting/active/snapshot, Next transaction); bei `SWEEP_PROGRESS`/`SWEEP_FAILED` leer |
| `RecordsFetched` | long | `0` | seit I11: Zeile `<n> records fetched` (gelieferte Datensätze, nicht die Seiten-Fetches in `Fetches`). Firebird schreibt sie bei Statements immer, bei Prozeduren und Funktionen nur, wenn die Zahl nicht 0 ist; deshalb wie die anderen Zähler `0` ohne Zeile — „0" heißt also auch „nicht zutreffend" (z. B. Transaktionsereignis) |
| `TxIsolation` | string | `$null` | seit I11: aus `TransactionOptions`: `READ_COMMITTED`, `CONCURRENCY`, `CONSISTENCY` (oder `<unknown>`) |
| `TxReadMode` | string | `$null` | seit I11: nur bei `READ_COMMITTED`: `REC_VERSION`, `NO_REC_VERSION`, `READ_CONSISTENCY` |
| `TxWaitMode` | string | `$null` | seit I11: `WAIT` oder `NOWAIT`; `WAIT <n>` ergibt `WAIT` |
| `TxLockTimeout` | int | `$null` | seit I11: Sekunden aus `WAIT <n>`; leer bei `NOWAIT` und bei unbegrenztem `WAIT` |
| `TxAccessMode` | string | `$null` | seit I11: `READ_WRITE` oder `READ_ONLY` |
| `TableCounts` | object[] | `$null` | seit I11: `TableStats` als Liste, je Tabelle ein Objekt `Table`, `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge` (long, leere Zelle = 0), Reihenfolge wie im Log |
| `RoutineType` | string | `$null` | seit I12: `Procedure`, `Function` oder `Trigger` bei Ereignissen mit `PROCEDURE`, `FUNCTION` bzw. `TRIGGER` im Namen (`EXECUTE_…_FINISH`, `…_START`, `FAILED …`, `UNAUTHORIZED …`) |
| `RoutineName` | string | `$null` | seit I12: Name aus `Procedure <Name>:` / `Function <Name>:` bzw. der Trigger-Zeile; leer, wenn Firebird keinen Namen kennt (Firebird 4 schreibt dann `<unknown>`) |
| `TriggerTable` | string | `$null` | seit I12: Tabelle aus `FOR <Tabelle>`; leer bei Datenbank-Triggern |
| `TriggerTime` | string | `$null` | seit I12: `BEFORE`, `AFTER`, `ON` (Datenbank-Trigger) oder `<unknown>` |
| `TriggerEvent` | string | `$null` | seit I12: `INSERT`, `UPDATE`, `DELETE`, `CONNECT`, `DISCONNECT`, `TRANSACTION_START`, `TRANSACTION_COMMIT`, `TRANSACTION_ROLLBACK`, `DDL` |
| `ConnectionDurationMs` | long | `$null` | seit I12: nur bei `DETACH_DATABASE`: Millisekunden seit `ATTACH_DATABASE`/`CREATE_DATABASE` derselben Verbindung (Datenbankpfad + `AttachID`) in dieser Datei; leer, wenn die Verbindung vor dem Trace begann |

### Felder je Ereignistyp

Der Parser gibt für **jeden** Block ein Objekt mit allen 46 Properties aus; gefüllt ist nur, was der Block enthält.
Die Tabelle fasst zusammen, welche Felder bei welcher `Action` gefüllt sind. Quelle: Probelauf beider Engines
(`-Engine PowerShell` und `-Engine CSharp`, gleiches Ergebnis) über die synthetischen Fixtures in `tests/fixtures/` und
einen kleinen eigens erzeugten synthetischen Trace mit fiktiven Werten; Stand 2026-11-11. Ereignisse, die in keinem
dieser Dateien vorkommen, sind nicht aufgeführt (Firebird kennt weitere, z. B. `EXECUTE_STATEMENT_START`).

Bausteine (kurz, in der Tabelle verwendet):

| Baustein | Felder |
|---|---|
| **Kopf** | `Timestamp`, `Action`, `ProcessID`, `SessionID` — immer gefüllt |
| **Verbindung** | `DatabasePath`, `AttachID`, `User`, `ProtocolInfo`, `ClientIP`, `ClientPort` |
| **Programm** | `ApplicationPath`, `ApplicationPID` — nur wenn der Block die Programmzeile hat (sie kann fehlen, z. B. bei internen Verbindungen) |
| **Transaktion** | `TransactionID`, `RootTxID`, `TransactionOptions`, `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` (`TxReadMode` nur bei `READ_COMMITTED`, `TxLockTimeout` nur bei `WAIT <n>`) |
| **Leistung** | `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` — nur die Zähler, die die Zeile `… ms, … read(s), …` nennt; sonst `0` |

| `Action` | Zusätzlich zu Kopf gefüllt |
|---|---|
| `ATTACH_DATABASE` | Verbindung, Programm |
| `DETACH_DATABASE` | Verbindung, Programm (falls vorhanden), `ConnectionDurationMs` (nur wenn der `ATTACH_DATABASE` derselben Verbindung in dieser Datei steht) |
| `START_TRANSACTION` | Verbindung, Programm, Transaktion (`RootTxID` = `TransactionID`) |
| `COMMIT_TRANSACTION`, `ROLLBACK_TRANSACTION` | Verbindung, Programm, Transaktion (`RootTxID` aus `INIT_<n>`, falls vorhanden), `Fetches`, `Marks`; `Writes` und `DurationMs`, wenn die Leistungszeile sie nennt |
| `COMMIT_RETAINING` | wie `COMMIT_TRANSACTION`; die Zeile `New number <n>` wird nicht gelesen (kein Feld dafür) |
| `EXECUTE_STATEMENT_FINISH` | Verbindung, Programm, Transaktion, `SqlStatement`, `SqlPlan` (mit `print_plan`), `Params`, `TableStats` und `TableCounts` (mit `print_perf`), `RecordsFetched`, Leistung |
| `FAILED EXECUTE_STATEMENT_FINISH` | wie oben, in den Fixtures ohne `SqlPlan`, `TableStats`, `RecordsFetched`. **Enthält keinen Fehlertext:** `ErrorSource`, `ErrorCodes` und `ErrorMessages` bleiben leer; der Fehler steht in einem eigenen `ERROR`-Ereignis |
| `EXECUTE_PROCEDURE_FINISH` | Verbindung, Programm, Transaktion, `RoutineType`, `RoutineName`, `Params`, `SqlPlan`, `TableStats`, `RecordsFetched` (nur wenn ≠ 0), Leistung; **kein** `SqlStatement` |
| `EXECUTE_FUNCTION_FINISH` | Verbindung, Programm, Transaktion, `RoutineType`, `RoutineName`, `Params`, `DurationMs`, `Fetches` |
| `EXECUTE_TRIGGER_FINISH` (auch `FAILED …`) | Verbindung, Programm, Transaktion, `RoutineType`, `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent`, Leistung; mit Plan/Statistik auch `SqlPlan`, `TableStats`, `TableCounts` |
| `ERROR`, `WARNING` | Verbindung, Programm, `ErrorSource`, `ErrorCodes`, `ErrorMessages`. **Kein** SQL, **keine** Transaktion, **keine** Leistung: ein Fehlerereignis sagt nicht, welches Statement ihn ausgelöst hat |
| `START_SERVICE`, `ATTACH_SERVICE`, `DETACH_SERVICE` | `User`, `ProtocolInfo`, `ClientIP`, `ClientPort`, Programm, `ServiceID`; `ServiceName` nur bei `START_SERVICE`/`QUERY_SERVICE`; kein `DatabasePath`, keine `AttachID` |
| `UNAUTHORIZED START_SERVICE` | `User`, `ProtocolInfo`, `ClientIP`, `ClientPort`, `ServiceID`, `ServiceName` (ohne Programm) |
| `SWEEP_START` | Verbindung, Programm, `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` |
| `SWEEP_PROGRESS` | Verbindung, Programm, `DurationMs`, `Reads`, `Fetches`, `TableStats` |
| `SWEEP_FINISH` | Verbindung, Programm, `SweepOIT`/`OAT`/`OST`/`Next`, Leistung, `TableStats`, `TableCounts` |
| `SWEEP_FAILED` | Verbindung, Programm, `DurationMs`, `Fetches` |

Daraus folgt für Auswertungen: Felder wie `SqlStatement`, `Params` oder `RecordsFetched` nur über die passenden
`Action`-Werte filtern (`$_.Action -eq 'EXECUTE_STATEMENT_FINISH'`); `0` bei Zählern heißt „nicht angegeben“ oder „null“,
nicht immer „gemessen null“. Die Zuordnung eines Fehlers zu dem Statement, das ihn ausgelöst hat, ist **nicht** Sache des
Parsers (kein Verweis im Trace); der Report-Generator leitet sie über Verbindung und Zeit ab (`README.md`, Schwester-Repo).
Wie sich `ErrorSource` dafür lesen lässt, steht im Benutzerhandbuch (`handbuch/BENUTZERHANDBUCH.md`).

**Tabellenstatistik lesen (seit I11):** Firebird (`appendTableCounts`) füllt die Namensspalte auf
max(32, längster Name in Bytes) auf (Firebird 3: fest 31) und schreibt jede Zahl rechtsbündig in 10 Zeichen, 0 als
Leerzeichen. Der Parser liest die Breite der Namensspalte aus der Kopfzeile (`Natural` endet 10 Zeichen dahinter) und
die Zahlen relativ dazu. Zwei Sonderfälle: Namen mit Umlauten füllt Firebird nach Bytes auf, die Zahlen beginnen dann
um die Zahl der Zusatzbytes früher; ist ein Name länger als die Spalte, verschieben sich alle Zahlen nach rechts
(Ausnahme: der Rest des Namens ist genau eine zehnstellige Zahl — dann füllt der Name die Spalte genau). Unlesbare
Zeilen werden übersprungen (Meldung mit `-Verbose`). Die Transaktionsoptionen zerlegt der Parser an ` | `
(Firebird `register_transaction`, gleich in 3, 4 und 5; die Wartezeit steht dort als `WAIT <n>`, nicht als `LOCK_TIMEOUT`).

**Prozeduren, Funktionen, Trigger (seit I12):** Laufzeit, I/O, `RecordsFetched`, Parameter, Plan und Tabellenstatistik
stehen in den bestehenden Feldern; Auswertungen nur über Statements filtern wie bisher über `Action`. Firebird 4 und 5
schreiben die Trigger-Zeile verschieden (geprüft an `TracePluginImpl.cpp`, Zweige `v4.0-release` und `v5.0-release`):
Firebird 5 `Trigger <Name> FOR <Tabelle> (<Zeitpunkt> <Aktion>):` auf eigener Zeile (ggf. mit Plan darunter), Firebird 4
`<TAB><Name> FOR <Tabelle> (<Zeitpunkt> <Aktion>) ` direkt unter der Transaktionszeile. Prozedur und Funktion stehen in
beiden als `Procedure <Name>:` bzw. `Function <Name>:`; Firebird 5 schreibt darunter den Plan (mit `print_plan`, nur beim
ersten Auftreten je Routine), Firebird 4 nie.
Voraussetzung im Trace: `log_procedure_finish`, `log_function_finish`, `log_trigger_finish` (Firebird-Standard `false`;
in `fbtrace50.conf` als auskommentierte Option, weil Trigger je Datensatz feuern und das Log sehr groß machen können).

**Verbindungsdauer (seit I12):** Der Parser merkt sich je offener Verbindung (Datenbankpfad + `AttachID`) die Zeit des
`ATTACH_DATABASE` und rechnet beim `DETACH_DATABASE`; danach fällt der Eintrag weg. Das passt zum Streaming: der Speicher
wächst mit der Zahl gleichzeitig offener Verbindungen, nicht mit der Dateigröße. Grenzen: Verbindungen, die vor dem Trace
begannen, bleiben leer; wer eine Datei in Teilen liest, verliert Paare über die Teilgrenze. Die Datenbank gehört zum
Schlüssel, weil jede Datenbank ihre `ATT`-Nummern selbst zählt.

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
- Einziger Zustand über Blöcke hinweg (seit I12): die offenen Verbindungen für `ConnectionDurationMs`; alle anderen Felder
  kommen nur aus dem eigenen Block.
- Warnungen enthalten nur Zeilennummer und feste Texte, nie Trace-Inhalt (personenbezogen); einzige Ausnahme ist der
  feste Firebird-Text bei `Unknown event in <Ereignis>`.
- Zeitlimit (seit I13) für alle Regex je Ereignis, nicht für das Zerlegen der Stücke (verankert, linear).
- Teure Teile nur bei Bedarf: erst `Contains`/`IndexOf`, dann Regex oder Zerlegen. Tabellenzeilen ohne
  PowerShell-Schleife über die Spalten lesen (eine Schleife war etwa sechsmal langsamer); leere Zellen über
  `'0' + Text` lesen — Windows PowerShell 5.1 wandelt Leerzeichen nicht in eine Zahl.

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| `Timestamp` ist Text, kein `[datetime]` | Regex-Gruppe ohne Konvertierung | Akzeptiert (BACKLOG) |
| Ein gekürztes Ereignis (über `-MaxBlockLines`) hat nur die Felder aus den ersten Zeilen, meist ohne Laufzeit | Schutz des Speichers | Akzeptiert, Warnung mit Zeilennummer |
| Nach dem Zeitlimit bleiben die restlichen Felder des Ereignisses leer, auch einfache wie die Laufzeit | ein `try` je Ereignis (Laufzeit) | Akzeptiert, Warnung mit Zeilennummer |

---

## Bekannte Fallstricke

- `AttachID`, `TransactionID` und `RootTxID` enthalten nur die Nummer, nicht `ATT_`/`TRA_`/`INIT_`; Werte sind Texte
  (nicht `[int]`), auch `ProcessID`, `ApplicationPID`, `ClientPort`.
- Ein `ERROR`-Ereignis hat kein `SqlStatement` und keine Transaktion (Tabelle „Felder je Ereignistyp“); wer Fehler mit
  Statements verknüpfen will, tut das über `AttachID` und `Timestamp` — und weiß dabei, dass es dafür keine Garantie gibt
  (Beobachtung je `ErrorSource` im Benutzerhandbuch).
- Ein Block ohne `Statement`-Abschnitt (z. B. Verbindungs- oder Transaktionsereignis) liefert `SqlStatement = $null` — beim Gruppieren berücksichtigen.
- `TableCounts` ist eine Liste: `Export-Csv` schreibt dafür nur `System.Object[]`. Für CSV die Liste aufklappen oder
  `TableStats` exportieren.
- `ConnectionDurationMs` steht am `DETACH_DATABASE`-Objekt, nicht am `ATTACH_DATABASE`-Objekt (Streaming: beim Attach ist das
  Ende noch unbekannt).
- Ruft eine Prozedur weitere Prozeduren auf oder löst Trigger aus, steckt deren Zeit vermutlich auch in ihrer Laufzeit
  (nicht geprüft). Summen über `RoutineType` können deshalb doppelt zählen.
- `RecordsFetched = 0` heißt nicht immer „0 Datensätze": ohne die Zeile (Transaktionsereignis, Prozedur mit 0) ist der
  Wert ebenfalls 0. Für „viel gelesen, wenig geliefert" nur Statement-Ereignisse auswerten.

---

## Teststrategie

- Zugehörige Testdatei: `tests/Show-TraceStructure.Tests.ps1` (I6)
- Pester-Beschreibung: `Describe 'Show-TraceStructure' { ... }`
- Fixture: synthetische Trace-Datei mit **fiktiven** Werten unter `tests/fixtures/` (je Ereignisart mindestens ein Block);
  seit I11 `trace_fb5_counts.log` mit `tests/Show-TraceStructure.Counts.Tests.ps1` (RecordsFetched, Transaktionsoptionen,
  Tabellenstatistik mit breiter Namensspalte, Umlauten, Firebird-3-Kopf); seit I12 `trace_fb5_routines.log` und
  `trace_fb4_routines.log` mit `tests/Show-TraceStructure.Routines.Tests.ps1` (Prozeduren, Funktionen, Trigger in beiden
  Formaten, Verbindungsdauer); seit I13 `tests/Show-TraceStructure.Diagnostics.Tests.ps1` (Warnungen mit Zeilennummer,
  auch über 4-MB-Stücke, Zusammenfassung, Kürzen, Zeitlimit; Eingaben im TestDrive)
- Seit I16/I17 C#-Parser (ADR-003): `tests/FirebirdTraceParser.Engine.Tests.ps1` (Laden, Parameter, Feldliste) und
  `tests/FirebirdTraceParser.Parity.Tests.ps1` — beide Parser über jedes Fixture und erzeugte Grenzfälle (Tabellen mit
  überlangen, unlesbaren und seltsamen Zellen wie `1e3`/`x1F`, Fehlerzeilen, IPv6/XNET/`<internal>`, Linux-Adresse,
  Transaktionsoptionen klein geschrieben, Dienste, Verbindungsdauer mit `CREATE_DATABASE` und doppeltem Detach); jedes
  Feld muss gleich sein (Name, Reihenfolge, Typ, Wert, `$null` gegen leer). Seit I18 auch Warnungen und
  Verbose-Meldungen (ohne Zeitangabe), dazu `tests/FirebirdTraceParser.Diagnostics.Parity.Tests.ps1`: die Eingaben der
  Diagnose-Tests, alle Fixtures mit CRLF und mit gemischten Zeilenenden, Kürzen über Stückgrenzen (auch ohne
  Zeitstempel), Zeitlimit (0,5 s gegen eine Suche, die viel länger braucht — bei 1 ms laufen auch kleine Blöcke
  zufällig ins Limit). Nur PowerShell 7. Eine Parsing-Änderung
  ist erst fertig, wenn sie in beiden Parsern steht.
- Kritische Testfälle: jede Property aus der Tabelle oben mit exaktem Wert; Block ohne SQL; Rolle ≠ `NONE`;
  fehlende Datei → Fehler; Zähler > Int32; leere Datei → keine Objekte
