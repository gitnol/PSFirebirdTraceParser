# Fehlerbehandlung – PSFirebirdTraceParser

Wo und wie Fehler erkannt, propagiert, behandelt und gemeldet werden.
Konsolidiert Regeln, die sonst in `CONVENTIONS.md`, `principles/FAIL_FAST.md`,
`principles/CONTRACTS.md` und `principles/LOGGING.md` verstreut sind.

---

## Fehlerarten im Projekt

Eine eigene Exception-Klasse: `TraceException` (in `TraceCommon.ps1`, Feld `ExitCode`). PowerShell-Regel für dieses Projekt:

- **Pipeline-Skripte** (`Show-TraceStructure.ps1`, `Pseudonymize-FirebirdTrace.ps1`) melden Fehler über `throw`
  (terminierend, klare `Message`) bzw. `Write-Error` mit passender `ErrorCategory` — **nie** über `exit`, weil sie auch
  per Dot-Sourcing oder aus anderen Skripten aufgerufen werden.
- **Prozess-Skripte** (`trace_start.ps1`, `trace_stop.ps1`) übersetzen Fehler an ihrer Boundary in Exit-Codes (Tabelle
  unten): Die Funktionen in `TraceCommon.ps1` werfen `TraceException` mit dem Code, nur die Skripte rufen `exit`
  (`Resolve-TraceExitCode`); andere Ausnahmen werden Exit 6.
- **Externe Programme** (`fbtracemgr.exe`): `Invoke-FbTraceMgr` liefert `$LASTEXITCODE` mit; jeder Aufruf wertet ihn aus
  (Exit 5). Stopp: zusätzlich der Text `Trace session ID <n> stopped` — fremdes Programm ohne anderen Status, der
  Vergleich steht an genau einer Stelle (`Stop-TraceSession`), getestet nur gegen ein Ersatzprogramm.

- **Nie über Meldungstexte verzweigen.** Eine Schicht ordnet Fehler einer anderen Schicht über **Typ** (Unterklasse)
  oder **Code** (Enum, Feld) zu, nie über den Wortlaut (Textanfang, Teilzeichenkette, Vergleich mit festem Text) —
  auch nicht bei Fehlern externer Programme, wenn diese einen Exit-Code oder Status liefern. Wortlaut ändert sich
  durch Umformulieren oder Übersetzen; die Zuordnung fällt dann still auf den allgemeinen Fall, und Tests mit dem alten
  Wortlaut bleiben grün. Bestehende Kopplungen per Suche finden (in Python z. B. `startswith(`, `in str(exc)`) und als
  eigenen Schritt lösen — vor jeder Übersetzung oder Textüberarbeitung — mit einem Test, der absichtlich fremden
  Wortlaut verwendet und trotzdem die richtige Zuordnung verlangt. Bleibt nur der Text (fremdes Programm ohne Code),
  liegt der Vergleich an genau einer Stelle im Adapter, mit Test gegen die echte Ausgabe.

---

## Boundary vs. interne Fehler

| Ebene | Verhalten |
|---|---|
| **Boundary** (Skript-Parameter, `config.json`, Aufruf von `fbtracemgr`) | Fehler in eine verständliche Meldung + Exit-Code (Prozess-Skripte) bzw. terminierenden Fehler (Pipeline-Skripte) übersetzen. Keine Trace-Inhalte, keine Passwörter in der Meldung. |
| **Verarbeitung** (Regex-Mapping, Hashing) | Fehler nicht abfangen; an die Boundary durchreichen. Ein unparsbarer Block ist **kein** Fehler, sondern ein Objekt mit leeren Feldern (heutiges Verhalten, siehe `features/TRACE_PARSING.md`). |

---

## Was geloggt und was gerethrowt wird

- Es gibt kein Log-Ziel; Meldungen gehen an die Konsole (`Write-Verbose`, `Write-Error`, `Write-Progress`; `Write-Host` nur
  in den Trace-Skripten und im `-AnalyzeOnly`-Bericht).
  Level-Semantik: `docs/principles/LOGGING.md`.
- **Unerwartet** (Programmierfehler, `fbtracemgr` fehlt) → terminierender Fehler mit Stacktrace in `$Error[0]`.
- **Erwartet, fachlich** (Datei fehlt, keine Session-ID gefunden) → klare Meldung ohne Stacktrace.
- **Niemals leeres `catch {}`.** Der Bestand hat zwei `catch`-Blöcke (JSON-Fehler in beiden Trace-Skripten); beide
  verwerfen die Original-Ausnahme — künftig deren `Message` mit ausgeben.

---

## Retry-Strategien

Keine Retries im Projekt. `fbtracemgr -START`/`-STOP` werden nicht automatisch wiederholt: ein zweiter Start
erzeugt eine **zusätzliche** Session (nicht idempotent).

---

## Feindliche Eingaben — kein Absturz an Systemgrenzen

Alles, was von außen kommt, ist feindlich: vor allem die **Trace-Datei** (beliebige SQL-Texte aller Clients des
Servers, sehr große Dateien, abgeschnittene Blöcke), außerdem Parameter und `config.json`.

> Abgrenzung zu [[FAIL_FAST]]: Fail Fast bricht die **Operation** früh und laut ab.
> Diese Regel sorgt dafür, dass dabei nicht der **Prozess** oder die Arbeit des Nutzers
> mitgerissen wird. Abgrenzung zu [[UNTRUSTED_DOCUMENT_CONTENT]]: dort geht es um fremden
> Inhalt im LLM-Prompt (Injection/Fälschung), hier um die Robustheit des Prozesses.

- **Größen begrenzen:** Der Parser liest seit I6 in 4-MB-Stücken (K2 behoben); ein einzelner sehr großer Block bleibt
  ganz im Speicher (Obergrenze je Block: I13).
- **Eingabe-abgeleitete Zahlen prüfen:** Zähler (`DurationMs`, `Reads`, `Fetches` …) sind seit I6 `[long]`; Werte über
  `Int32.MaxValue` sind getestet.
- **Regex auf untrusted Text:** Muster ohne verschachtelte, nicht verankerte Quantoren mit Fehlpfad; bei neuen
  Mustern Laufzeit gegen große synthetische Blöcke testen.
- **Schreiben atomar:** Das Projekt schreibt selbst nur die Trace-Ausgabe (Umleitung von `fbtracemgr`) und die kleine
  Zustandsdatei `trace_session.json`; Exporte schreibt der Nutzer.
- **Jeder Crash-Fix bringt einen kleinen synthetischen Regressionstest mit**, der vor dem
  Fix nachweislich abgestürzt ist (behaviorales Rot, `KICKOFF.md` Phase 2).

---

## Konvertierungstabelle (Pflicht ausfüllen)

| Situation | Skript | Exit-Code / Verhalten | Meldung | Bemerkung |
|---|---|---|---|---|
| `config.json` fehlt | `trace_start.ps1`, `trace_stop.ps1` | `1` | `FEHLER: config.json fehlt: <pfad>` | Fail-Fast vor jedem Aufruf |
| `config.json` kein gültiges JSON | beide | `2` | `FEHLER: config.json ist kein gueltiges JSON: <ursache>` | Ursache wird mitgegeben |
| Schlüssel fehlt/falsch, Pfad fehlt, `Password` vorhanden | beide | `2` | eine `FEHLER:`-Zeile je Befund, alle zusammen | Passwortwert wird nie genannt |
| Sitzung noch gemerkt (`trace_session.json`) | `trace_start.ps1` | `2` | `Es gibt noch eine gemerkte Sitzung …` | kein zweiter Start |
| Keine passende Sitzung | `trace_stop.ps1` | `3` | `Keine laufende Trace-Sitzung mit Namen '…*' gefunden` | Zustandsdatei wird gelöscht |
| Mehrere passende Sitzungen | `trace_stop.ps1` | `4` | `Mehrere passende Sitzungen: <id name>, …` | dann `-Id` |
| `fbtracemgr` Exit-Code ≠ 0 oder Stopp nicht bestätigt | beide | `5` | `fbtracemgr endete mit Exit-Code …` bzw. `Stoppen nicht bestaetigt …` | Zustandsdatei bleibt beim Stopp |
| Andere Ausnahme | beide | `6` | `Unerwarteter Fehler: <meldung>` | |
| Trace-Datei fehlt | `Show-TraceStructure.ps1` | nicht-terminierender Fehler, Rückkehr ohne Objekte | `File not found: <Pfad>` | Soll: terminierender Fehler (I6) |
| Block ohne passende Felder | `Show-TraceStructure.ps1` | Objekt mit leeren Feldern | — | kein Fehler, still |
| `-HashLength` außerhalb 8–64 | `Pseudonymize-FirebirdTrace.ps1` | Parameterbindungsfehler | PowerShell-Standardmeldung | `[ValidateRange(8, 64)]` |

---

## Anti-Pattern

- **`catch` ohne Weitergabe der Ursache** — Diagnose wird unmöglich (früher: JSON-Fehler der Trace-Skripte).
- **`exit` in Pipeline-Skripten** — beendet die aufrufende Sitzung.
- **Trace-Inhalte in Fehlermeldungen** (seit I5 gibt `trace_stop.ps1` keine Zeile der Trace-Datei mehr aus).
- **Stilles Wegfangen** in der Mitte des Aufruf-Stacks — Fail-Fast wird ausgehebelt.
- **Zuordnung über Meldungstext** (Vergleich mit dem Wortlaut einer Fehlermeldung) statt über Typ oder Code — siehe oben.

---

## Pflege

Trigger (siehe `KICKOFF.md` Phase 3a): neuer Exit-Code / neue Boundary / neue Fehlermeldung → diese Datei +
Konvertierungstabelle aktualisieren.
