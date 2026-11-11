# Glossar – PSFirebirdTraceParser

Ubiquitous Language für dieses Projekt. Jeder Begriff hat genau eine Bedeutung.
Synonyme oder doppelt belegte Begriffe schaffen Drift und werden vermieden.

LLM-Agenten konsultieren dieses Glossar, **bevor** sie Begriffe im Code, in
Commit-Messages oder in Doku verwenden.

---

## Begriffe

| Begriff | Bedeutung | Wo verwendet | Nicht zu verwechseln mit |
|---|---|---|---|
| Engine | Welcher Parser die Trace-Datei liest: `PowerShell` (im Skript) oder `CSharp` (Cmdlet `ConvertFrom-FirebirdTrace` aus `FirebirdTraceParser.dll`, ADR-003); `-Engine Auto` wählt | `Show-TraceStructure.ps1 -Engine` (seit I19) | Firebird-Server, `fbtracemgr` |
| Parität | Beide Engines liefern für dieselbe Datei dieselben Objekte (jedes Feld, Typ, Reihenfolge), Warnungen und Verbose-Meldungen; geprüft von den Paritätstests | `tests/FirebirdTraceParser.*Parity.Tests.ps1`, `tests/TraceParity.ps1` | „gleiche Felder" ohne Typ- und Wertvergleich |
| Trace-Session | Vom Firebird-Server geführte Protokollierung, gestartet per `fbtracemgr -START -NAME <sitzungsname>`, identifiziert durch die Trace-Session-ID | `trace_start.ps1`, `trace_stop.ps1` | Datenbankverbindung (Attachment); Property `SessionID` |
| Trace-Session-ID | Nummer der Sitzung beim Server (erste Zeile der Ausgabe `Trace session ID <n> started`, auch in `fbtracemgr -LIST`), nötig für `-STOP -ID` | `Stop-TraceSession` (`TraceCommon.ps1`) | Property `SessionID` der Trace-Objekte |
| Sitzungsname | Name der Trace-Session, `<SessionName>_<yyyyMMdd_HHmmss>`; darüber findet der Stopp die Sitzung | `config.json` → `SessionName`, `trace_session.json` | Trace-Session-ID |
| Zustandsdatei | `trace_session.json` neben den Skripten: Sitzungsname, Logdatei und Startzeit der laufenden Sitzung | `Start-TraceSession`, `Stop-TraceSession` | `config.json` |
| Passwortdatei | Datei mit dem Firebird-Passwort in der ersten Zeile; `fbtracemgr` liest sie selbst (`-FETCH_PASSWORD`) | `config.json` → `PasswordFile` | Schlüsseldatei (`-KeyFile`) des Pseudonymisierers |
| Trace-Konfiguration | Datei mit Regeln, was der Server protokolliert (`fbtrace50.conf`, älter `fbtrace30.conf`) | `config.json` → `TraceConfigFilename` | `config.json` (Skript-Konfiguration) |
| Trace-Log | Textdatei mit der Ausgabe einer Trace-Session (Rohdaten, vertraulich) | `<OutputDirectory>\trace_output_*.log`, Parameter `-Path` | Konsolenmeldungen der Skripte |
| Trace-Block | Abschnitt eines Trace-Logs von einer Zeitstempel-Zeile bis vor die nächste; ein Ereignis | `Show-TraceStructure.ps1` (`$logBlocks`) | Zeile; Statement |
| Trace-Objekt | `PSCustomObject`, das der Parser je Trace-Block ausgibt; Property-Namen sind Vertrag | `features/TRACE_PARSING.md` | Rohtext des Blocks |
| Action | Ereignisname der Kopfzeile eines Blocks (z. B. Ende eines Statements, Transaktionsstart) | Property `Action` | Skript-Aktion (Start/Stopp) |
| `SessionID` (Property) | Zweiter, hexadezimaler Wert in der Klammer der Kopfzeile `(PID:…)` | Property `SessionID` | Trace-Session-ID |
| Fehlerereignis | Trace-Block der Art `ERROR AT …` oder `WARNING AT …` (`Action` `ERROR`/`WARNING`): Verbindung, Quelle, Codes, Meldungen; enthält **kein** SQL und keine Transaktion | `features/TRACE_PARSING.md` → „Felder je Ereignistyp“ | `FAILED EXECUTE_STATEMENT_FINISH` (Statement-Ereignis ohne Fehlertext) |
| Fehlerquelle | Komponente, die den Fehler meldet, aus `ERROR AT <Komponente>` (z. B. `JStatement::prepare`); Property `ErrorSource` | Property `ErrorSource` | Fehlercode (`ErrorCodes`) |
| Attachment | Datenbankverbindung eines Clients (`ATT_<n>` im Log; die Property `AttachID` trägt nur die Nummer `<n>`) | Property `AttachID` | Trace-Session |
| RootTxID | Ursprungs-Transaktion: die Nummer aus `INIT_<n>` falls vorhanden, sonst die eigene Nummer (`TransactionID`), sonst `NoTx` | Property `RootTxID` | `TransactionID` |
| Pseudonym | Gekürzter Hex-Hash, der einen Klartextwert ersetzt (`<HASH:…>` in SQL, sonst nur der Hex-Wert) | `Pseudonymize-FirebirdTrace.ps1` (`Get-ShortHash`) | Anonymisierung |
| Pseudonymisierung | Ersetzen identifizierender Werte durch Pseudonyme; Ergebnis bleibt personenbezogen | `Pseudonymize-FirebirdTrace.ps1`, README | Anonymisierung |
| Literal | In einfache Anführungszeichen gesetzter Wert in einem SQL-Statement (`'…'`); numerische Werte zählen im Bestand nicht dazu | `$RxStringLiteral` | Parameter (`paramN = …`) |
| Bulk-Redaktion | Ersetzen der (letzten) WHERE/HAVING-Klausel durch `<REDACTED_CLAUSE:…>`, wenn ein sensibles Schlüsselwort vorkommt | `-SensitiveKeywords` | Literal-Pseudonymisierung |
| Tabellenstatistik | Block `Table … Natural Index …` eines Ereignisses (Firebird `print_perf`): je Tabelle Lesezugriffe ohne (`Natural`) und mit Index sowie Änderungen und Aufräumarbeit; im Parser als Text `TableStats` und als Liste `TableCounts` | Properties `TableStats`, `TableCounts` | Performance-Zeile (`Reads`, `Fetches` …) |
| RecordsFetched | Zahl der Datensätze, die ein Statement geliefert hat (`N records fetched`) | Property `RecordsFetched` | `Fetches` (Seitenzugriffe im Cache) |
| Routine | Prozedur, Funktion oder Trigger mit eigenem Trace-Ereignis (`EXECUTE_PROCEDURE_FINISH`, `EXECUTE_FUNCTION_FINISH`, `EXECUTE_TRIGGER_FINISH`) | Properties `RoutineType`, `RoutineName` | Statement (`EXECUTE_STATEMENT_FINISH`) |
| Verbindungsdauer | Zeit zwischen `ATTACH_DATABASE` und `DETACH_DATABASE` derselben Verbindung (Datenbankpfad + `ATT_<n>`) in einer Trace-Datei | Property `ConnectionDurationMs` | `DurationMs` (Laufzeit eines Ereignisses) |
| Feldabdeckung | Liste, welche Property wie pseudonymisiert wird bzw. bewusst im Klartext bleibt | `features/PSEUDONYMIZATION.md` | — |
| Service-Manager | Firebird-Services-API-Endpunkt (`service_mgr`), über den `fbtracemgr` Traces verwaltet | Trace-Skripte | Datenbankdatei |

---

## Verbotene Synonyme

Begriffe, die im Projekt-Kontext **nicht** mehr verwendet werden dürfen,
auch wenn sie umgangssprachlich gleichbedeutend wirken:

| Verbotener Begriff | Korrekt | Grund |
|---|---|---|
| Anonymisierung / anonymisiert | Pseudonymisierung / pseudonymisiert | Das Verfahren ist deterministisch und (ohne Schlüssel) umkehrbar; „anonym" würde eine falsche Datenschutz-Zusage machen |
| Session (ohne Zusatz) | Trace-Session **oder** Attachment **oder** Property `SessionID` | drei verschiedene Dinge |
| Log (ohne Zusatz) | Trace-Log | im Projekt gibt es kein Anwendungs-Log; „Log" verwischt die Sensitivität der Rohdaten |

---

## Pflege

- Neuer Domänenbegriff im Code → **vor dem Commit** hier ergänzen.
- Begriff wird umbenannt → alter Eintrag bleibt mit Vermerk „ersetzt durch …"
  stehen (mindestens eine Inkrement-Generation als Übergangsphase).
- Begriff entfällt → Eintrag mit „deprecated" und Datum markieren, nicht löschen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
