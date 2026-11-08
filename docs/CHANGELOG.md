# Changelog – PSFirebirdTraceParser

Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/).
Einträge chronologisch absteigend (neueste oben). Jeder Eintrag entspricht
genau einem Inkrement (= einem Commit oder einer eng zusammengehörigen
Commit-Serie). Roadmap-Änderungen (KICKOFF Phase 1 Punkt 2a), Reflexions-Refreshs und
Post-Mortems erhalten einen kurzen Eintrag ohne I#.

Nicht alle Sektionen sind in jedem Eintrag nötig — leere Sektionen weglassen.

Ältere Einträge (I1–I10, K3, Reflexion nach I3): `changelog/ARCHIVE-CHANGELOG-I01-I10.md`.

---

## 2026-11-08 Reflexion nach I13

Kein Inkrement (KICKOFF Phase 1c, `REFLECTION.md`). Begutachtet: I11, I12, I13 (drittes abgeschlossenes Inkrement
nach I5).

### Advocatus Diaboli
- **Positiv:** Formate aus dem Quellcode belegt statt geraten (I11 `appendTableCounts`, I12 Trigger-Zeile in
  `TracePluginImpl.cpp` `v4.0-release` und `v5.0-release` verglichen — der alte Kommentar „Format 4.0 = 5.0" in
  `fbtrace50.conf` war falsch). Die Mutationsproben fanden in jedem der drei Inkremente echte Testlücken (I11
  Umlaut-Korrektur, I12 `CREATE_DATABASE`, I13 drei Wege der Zeilenzählung/Kürzung). Streaming bleibt; Laufzeit je
  Inkrement gemessen (I11 etwa +15 %, I12 +4 %, I13 +2 % auf 9,7 MB).
- **Negativ:** `Show-TraceStructure.ps1` hat jetzt 594 Zeilen, `ConvertFrom-TraceBlock` allein 242 Zeilen in einem
  `try` (`wc -l`, awk-Zählung) — über der Grenze aus `CONVENTIONS.md` §3 (Funktionen im Skript nur unter 300 Zeilen) →
  Refactoring-Kandidat in `BACKLOG.md`. I12 hat noch keinen End-to-End-Konsumenten: `fbtrace50.conf` schaltet
  `log_procedure_finish`/`log_trigger_finish` nicht ein, echte Daten gibt es erst nach einer Entscheidung des Owners.
  I13 baut `-RegexTimeoutSeconds` und `-MaxBlockLines` gegen ein angenommenes Risiko; die Standardwerte sind geschätzt.
  Belegt ist nur der Speicherfehler beim Rest ohne Zeitstempel (aus dem Code gelesen: `$carry = $text` ohne Grenze),
  nicht gemessen. Ein Kontrolllauf der I13-Mutationsprobe war einmal ohne erkennbaren Grund rot (Vermutung:
  Zeitlimit-Test).
- **Lehren-Filter:** L8 ist ein Fall in einem Projekt (so vermerkt). L3 hat zwei weitere Fälle im selben Projekt
  (I11, I12) — weiter nur ein Projekt. L4–L7 unverändert offen.

### Changed
- `BACKLOG.md`: Refactoring-Kandidat `Show-TraceStructure.ps1` (Hotspot); `Timestamp` als `[datetime]` ist seit I12
  billiger (das Parsen gibt es schon für die Verbindungsdauer).
- `LESSONS_LEARNED.md`: L3 um I11/I12 ergänzt.
- `STATE.md`: Reflexions-Marker auf das dritte Inkrement nach I13; Nächster Schritt gekürzt.

### Confidence / Ungeprüft
- Health-Check (Grep auf offene Verweise): 0 Treffer; Validator OK. Bestehende Hinweise unverändert: toter Verweis auf `testing/INTEGRATION_TESTS.md` in `CONVENTIONS_COMMON.md` (Template-Datei) und Dubletten zwischen `README.md`/`README.de.md`/`SETUP.md` (gewollt: zwei Sprachen). Fakten-Drift gesucht („Format 4.0 = 5.0",
  „Obergrenze je Block", „ganz im Speicher"): in I12/I13 schon umgestellt. Interna-Scan gegen `.internal-terms` über alle
  versionierten Dateien: 0 Treffer; Suche mit Wortgrenzen für kurze Namen nicht gemacht.
- Hotspots seit `6da250b`: `Show-TraceStructure.ps1` 5 Commits / 594 Zeilen (Kandidat); READMEs und Tests sind keine
  Kandidaten.
- Testgüte: Mutationsproben in I11 (19, 1 äquivalent), I12 (21, 2 äquivalent), I13 (22, alle rot nach Testergänzung).
- Roadmap: offen ist nur I8 (Rest, mit dem Security-Sweep am 2026-11-21). Vorschlag für danach, nicht in `TODO.md`
  übernommen (Entscheidung Owner): Refactoring `Show-TraceStructure.ps1`, dann `Timestamp` als `[datetime]`.

## 2026-11-08 I13 – Parser: Robustheit und Diagnose

Commits `4df3e6c` (Tests rot, Stub mit Vertrag), `30b4b43` (Umsetzung). Kein Split: 2 Code-/Testdateien, ~420 Zeilen
(davon ~190 Tests; ~120 Zeilen sind nur neu eingerückt, `git diff -w` zeigt ~160 im Skript).

**Trigger-Matrix:** neue Parameter → `README.md`, `README.de.md`, `features/TRACE_PARSING.md`,
`architecture/CONFIGURATION.md` (Konfig-Tabelle); neue Boundary (Zeitlimit gefangen, Warnungen) →
`architecture/ERROR_HANDLING.md` (Regeln und Tabelle); Security (Ressourcenverbrauch, Warnungen ohne Inhalt) →
`security/THREAT_MODEL.md` Bedrohung 6; Lehre → `LESSONS_LEARNED.md` L8; `STATE.md`, `TODO.md`. Neue Hilfsfunktionen
liegen im Skript (kein Modul) → `architecture/OVERVIEW.md` nicht ausgelöst.

### Added
- Warnungen `Line <n>: <fester Text>` für unlesbare Kopfzeilen, `Unknown event …`, Text vor dem ersten Ereignis
  (Leerzeilen und `Trace session ID <n> started` ausgenommen), gekürzte Ereignisse und Zeitlimit. Kein Trace-Inhalt in
  der Warnung. Das Objekt wird weiter ausgegeben (Vertrag: immer ein Objekt je Block).
- Zusammenfassung mit `-Verbose`: `Summary: <Action> = <n>` je Action (unlesbare Kopfzeile als `(header not readable)`)
  und `Summary: <n> warning(s)`. Opt-in über `-Verbose` statt eigenem Schalter; Pipeline-Ausgabe gleich (Test vergleicht
  die JSON-Form mit und ohne `-Verbose`).
- `-RegexTimeoutSeconds` (Standard 2) und `-MaxBlockLines` (Standard 100000).

### Fixed
- Eine Datei ohne Zeitstempel (oder ein riesiger Block) wurde bisher als Rest von Stück zu Stück ganz mitgenommen:
  Speicher und Laufzeit wuchsen mit der Dateigröße. Jetzt wird der Rest ab `-MaxBlockLines` Zeilen gekürzt.

### Confidence / Ungeprüft
- Gate grün: PSScriptAnalyzer ohne Befund, Pester 150/150 unter PowerShell 7.6, 149 grün + 1 übersprungen unter
  Windows PowerShell 5.1 (auch der Zeitlimit-Test). Rot gegen den Stub: 9 von 13 Tests mit scheiternder Assertion.
- Mutationsprobe: 22 Mutanten; zuerst 19 rot, 3 überlebten (Kürzen im Block, Zeilenversatz nach gekürztem Rest,
  Zwischenspeicher der Zeilenzählung) → drei Tests ergänzt, danach auch diese drei rot. Ein Kontrolllauf (ohne Mutation) war
  einmal rot und ließ sich in 7 weiteren Läufen nicht nachstellen — Ursache unbekannt, Verdacht Zeitlimit-Test (1 ms
  auf 3 MB) oder Last; beobachten (CI).
- Laufzeit (21000 Ereignisse, 9,7 MB, je 3×3 Läufe abwechselnd): I12-Stand ~6,9 s, nachher ~7,0–7,1 s (etwa +2 %).
  Gegenüber dem Stand vor I12 (~6,7 s) zusammen etwa +5 %.
- Die Standardwerte (100000 Zeilen, 2 s) sind geschätzt, nicht an echten Traces gemessen; sie sollen nur Ausreißer
  abfangen.
- Der Zeitlimit-Test hängt an der Rechnergeschwindigkeit (1 ms für 3 MB Text); auf sehr schnellen Rechnern könnte er
  ausnahmsweise grün statt rot laufen, bricht aber nicht ab (Prüfung „mindestens eine Warnung").
- Nach einem Zeitlimit bleiben auch einfache Felder (Laufzeit) leer, weil ein `try` den ganzen Block umfasst — bewusst
  (Laufzeit), dokumentiert in `TRACE_PARSING.md`.
- Struktur-Check mit dem Template-Validator; Interna-Prüfung über den Hook.

### Lessons Learned
- Streaming mit Restübertrag: Ein Testfall am Dateiende prüft nur den Weg über den Rest, nicht den über die Schleife.
  Zwei Mutanten überlebten, weil der gekürzte Block der letzte war und schon beim Weitertragen gekürzt wurde → L8.

## 2026-11-08 I12 – Parser: Prozeduren, Funktionen und Trigger als Ereignisse, Verbindungsdauer

Commits `c4c2dde` (Tests rot, Stub mit Vertrag), `263b43d` (Umsetzung). Kein Split: 5 Code-/Test-/Fixture-Dateien plus
`fbtrace50.conf`, ~420 Zeilen, davon ~270 Tests und Fixtures. Funktionen mitgenommen: gleiches Format wie Prozeduren, kein
Mehraufwand.

**Trigger-Matrix:** neue Felder im Ausgabe-Vertrag → `features/TRACE_PARSING.md`, `README.md`, `README.de.md`;
Feldabdeckung → `features/PSEUDONYMIZATION.md`; Security (Schema-Namen im Klartext) → `security/THREAT_MODEL.md`;
neue Begriffe → `GLOSSARY.md`; `STATE.md`, `TODO.md`. Kein neuer Parameter, keine neue Funktion, keine Abhängigkeit →
`architecture/OVERVIEW.md` nicht ausgelöst; der neue Zustand über Blöcke hinweg steht in `TRACE_PARSING.md`.

### Added
- `RoutineType` (`Procedure`/`Function`/`Trigger`), `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent` am Ende
  des Vertrags (nach `TableCounts`). Laufzeit, I/O, Parameter, Plan und Tabellenstatistik über die bestehenden Felder.
- Trigger-Zeile in beiden Formaten, geprüft an `TracePluginImpl.cpp` `v4.0-release` (`	%s (%s) ` unter der
  Transaktionszeile, Name `<unknown>` ohne Namen) und `v5.0-release` (`Trigger %s (%s):` auf eigener Zeile, ohne Namen
  nur `Trigger (…):`). Prozedur/Funktion: in beiden `Procedure <Name>:`, Firebird 5 ggf. mit Plan darunter.
- `ConnectionDurationMs` bei `DETACH_DATABASE`: passt zum Streaming (Tabelle nur der offenen Verbindungen, Schlüssel
  Datenbankpfad + `AttachID`); leer, wenn das `ATTACH_DATABASE` nicht in der Datei steht.
- Fixtures `trace_fb5_routines.log`, `trace_fb4_routines.log` (synthetisch, IPs aus 192.0.2.0/24) und
  `tests/Show-TraceStructure.Routines.Tests.ps1` (16 Tests).

### Changed
- `fbtrace50.conf`: `log_procedure_finish`/`log_function_finish`/`log_trigger_finish` als auskommentierte Option mit
  Hinweis auf die Log-Größe; Kopfkommentar „Format 4.0 = 5.0" korrigiert (Trigger-Zeile unterscheidet sich).
- I11-Test zur Feldreihenfolge prüft relativ zu `SweepNext` statt am Ende.

### Confidence / Ungeprüft
- Gate grün: PSScriptAnalyzer ohne Befund, Pester 136/136 unter PowerShell 7.6, 135 grün + 1 übersprungen (bestehender
  7.4+-Test) unter Windows PowerShell 5.1. Rot gegen den Stub: 12 von 16 neuen Tests mit scheiternder Assertion; die 4
  grünen prüfen Defaults (Blockzahl, leere Felder, leere Dauer, Reihenfolge) und sind über die Mutationsprobe belegt.
- Mutationsprobe: 21 Mutanten, 19 rot, 2 äquivalent (Vorprüfung „kein Statement" ist reine Laufzeit; Leerzeichen am
  Zeilenende nach `Procedure <Name>:` schreibt Firebird nicht). Ein Mutant (`CREATE_DATABASE` entfernt) überlebte zuerst
  → Test ergänzt.
- Laufzeit (21000 Ereignisse, 9,7 MB, je 3×3 Läufe abwechselnd): vorher ~6,6–6,8 s, nachher ~6,9–7,1 s (etwa +4 %);
  die sechs Felder allein kosten nichts Messbares, die Prüfungen je Block den Rest. Erste Fassung ohne Vorprüfung ~+6 %.
- Format nur aus dem Quellcode, kein echtes Log mit Prozedur- oder Trigger-Ereignissen: die Vorlage schaltet sie nicht ein.
  Firebird 3 (`fbtrace30.conf`) nicht getestet; der Quellcode 3.0 schreibt Prozeduren und Trigger wie Firebird 4.
- `COMPILE_PROCEDURE`/`COMPILE_TRIGGER` (nur Firebird 5) füllen dieselben Felder, sind aber nicht getestet.
- Ob die Laufzeit einer Prozedur die aufgerufener Prozeduren und Trigger enthält, ist nicht geprüft (Fallstrick in
  `TRACE_PARSING.md` als „vermutlich“).
- Struktur-Check mit dem Template-Validator; Interna-Prüfung über den Hook.

## 2026-11-08 Trace-Benutzer in den READMEs, Entscheidung zur Git-History

Kein Inkrement; zwei Ergänzungen des Owners (2026-11-08).

**Trigger-Matrix:** Einrichtung → `README.md`, `README.de.md` (neuer Abschnitt Trace-Benutzer), `operations/SETUP.md`;
Risiko entschieden → `STATE.md` („akzeptiert“), `security/THREAT_MODEL.md` (Bedrohung 5), `TODO.md` (Owner-Aufgabe
entfernt). Kein Entscheidungslog (`architecture/ADR/DECISIONS.md`) vorhanden; Betriebsentscheidung ohne eigenes ADR.

### Changed
- READMEs: eigener Trace-Benutzer mit Rolle statt SYSDBA (`CREATE USER`, `CREATE ROLE … TRACE_ANY_ATTACHMENT`,
  `GRANT DEFAULT`), Passwortdatei bzw. `UseTrustedAuth`, Hinweis zum Ändern des SYSDBA-Passworts, Verweis auf `SETUP.md`.
- `SETUP.md`: `CREATE USER` ergänzt, `GRANT TRACER TO TRACE_USER` → `GRANT DEFAULT TRACER TO USER TRACE_USER`,
  Erklärung (Rolle je Datenbank, Standardrolle), Befehl zum Ändern des SYSDBA-Passworts.
- Git-History wird nicht bereinigt (Begründung in `STATE.md` → Risiken); Owner-Aufgabe in `TODO.md` entfernt.

### Confidence / Ungeprüft
- Befehle mit den Firebird-QA-Tests abgeglichen (`test_trace_any_attachment.py`, ab 4.0: Rolle in der Testdatenbank,
  `grant default`, Trace mit Benutzer und Rolle), nicht gegen einen echten Server mit diesen Skripten.
- Dass die Rolle in der aufgezeichneten Datenbank (nicht in der Sicherheitsdatenbank) liegen muss, folgt nur aus dem
  QA-Test; mehrere Datenbanken ungeprüft.
- History-Befund vom Owner übernommen, hier nicht erneut geprüft.

## 2026-11-08 I11 – Parser: RecordsFetched, Transaktionsoptionen, Tabellenstatistik je Tabelle

Commits `3d58b3f` (Tests rot, Stub mit Vertrag), `6450b79` (Umsetzung). Freigabe des Owners 2026-11-08; Zweck: der
Bericht im Schwesterprojekt braucht `RecordsFetched` für die Prüfung „viel lesen für wenig Ergebnis“. Ein Inkrement
statt Split: 4 Code-/Testdateien, ~330 Zeilen inkl. Tests; die drei Teile berühren dieselbe Funktion.

**Trigger-Matrix:** neue Felder im Ausgabe-Vertrag → `features/TRACE_PARSING.md`, `README.md`, `README.de.md`;
Feldabdeckung → `features/PSEUDONYMIZATION.md`; Security (Klartext-Felder, Hinweis zu `-SensitiveKeywords`) →
`security/THREAT_MODEL.md`; neue Begriffe → `GLOSSARY.md`; `STATE.md`, `TODO.md`. Neue Hilfsfunktion
`ConvertFrom-TableStat` liegt im Skript (kein neues Modul) → `architecture/OVERVIEW.md` nicht ausgelöst. Kein neuer
Parameter, keine Abhängigkeit.

### Added
- `RecordsFetched` [long] aus `<n> records fetched` (Firebird 3/4/5 `TracePluginImpl.cpp`, immer Plural „records“),
  getrennt von `Fetches` (Seitenzugriffe). Default `0` wie die anderen Zähler: Firebird schreibt die Zeile bei
  Statements immer, bei Prozeduren/Funktionen nur, wenn die Zahl nicht 0 ist.
- `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` aus `TransactionOptions` (Text bleibt).
  Die Wartezeit steht im Trace als `WAIT <n>` (nicht `LOCK_TIMEOUT`, wie `TODO.md` vermutete).
- `TableCounts`: je Tabelle ein Objekt mit acht Zählern; Spalten relativ zur Kopfzeile, Namen mit Umlauten (Firebird
  füllt nach Bytes auf) und überlange Namen (Zahlen nach rechts verschoben, Regel wie im Schwesterprojekt) richtig.
  `TableStats` bleibt unverändert.
- Fixture `tests/fixtures/trace_fb5_counts.log` (synthetisch, Werte ausgedacht, IPs aus 192.0.2.0/24) und
  `tests/Show-TraceStructure.Counts.Tests.ps1` (21 Tests).

### Changed
- `Pseudonymize-FirebirdTrace.ps1`: `TableCounts` als eigene Kopie (`Select-Object *` kopiert nur die erste Ebene);
  Tabellennamen bleiben Klartext wie `TableStats` (Entscheidung I2).
- I15-Test zur Feldreihenfolge prüft die Sweep-/Service-Felder jetzt relativ zu `ErrorMessages` statt am Ende.
- `PSEUDONYMIZATION.md`/READMEs: der Hinweis „Tabellennamen verbergen mit `-SensitiveKeywords`“ war falsch — der
  Schalter wirkt nur auf `SqlStatement` (Probelauf 2026-11-08); jetzt: Felder vor der Weitergabe weglassen.

### Confidence / Ungeprüft
- Gate grün: PSScriptAnalyzer ohne Befund, Pester 120/120 unter PowerShell 7.6, 119 grün + 1 übersprungen (bestehender
  7.4+-Test) unter Windows PowerShell 5.1. Rot gegen den Stub: 11 Tests mit scheiternder Assertion; der
  Pseudonymisierer-Block lief nur unter dem Gate (Strict Mode) wegen unvollständiger Testeingabe in einen Fehler statt
  in eine Assertion — im feat-Commit korrigiert.
- Mutationsprobe: 19 Mutanten, 18 rot, 1 äquivalent (`return @()` statt `$null` — eine leere Rückgabe ist in
  PowerShell ebenfalls `$null`). Die Byte-Korrektur für Umlaute überlebte zuerst (eine Verschiebung um 1 Zeichen fällt
  bei kurzen Zahlen nicht auf); erst mit zwei Umlauten und einer neunstelligen Zahl im Fixture erkannt.
- Laufzeit (21000 Ereignisse, 9,7 MB, 3 Läufe je Stand, abwechselnd): vorher ~5,5–5,9 s, nachher ~6,5–6,9 s
  (etwa +15 %); das Fixture allein ~54 ms vorher und nachher. Hauptkosten: `TableCounts` (PowerShell-Arbeit je
  Tabellenzeile) und sieben Felder mehr je Objekt. Erste Fassung mit Spalten-Schleife war ~+30 %.
- Format nur aus dem Quellcode (v3.0, v4.0, v5.0-release), nicht an einem echten Trace geprüft: weder Umlaut-Namen
  noch überlange Namen noch `WAIT <n>` sind in einem echten Log belegt. Überlange Namen kann Firebird 4/5 laut Quellcode
  gar nicht erzeugen (Spalte = längster Name); die Regel stammt aus dem Schwesterprojekt.
- Grenze: Ein überlanger Name, dessen Rest genau eine zehnstellige Zahl ist, wird als „füllt die Spalte genau“ gelesen.
- Struktur-Check mit dem Template-Validator; Interna-Prüfung über den Hook.

## 2026-11-08 Reflexion nach I5

Kein Inkrement (KICKOFF Phase 1c, `REFLECTION.md`). Begutachtet: I15, I14, I4/I5 (drittes abgeschlossenes Inkrement
nach I3). Vorher im selben Lauf: Doku-Abgleich mit dem Code-Stand (`30d3522`).

### Advocatus Diaboli
- **Positiv:** CI-Gate rot/grün belegt (Exit 1 mit 21 Befunden auf dem Code vor `ca1edc9`, Exit 2 mit absichtlich
  falschem Test); kein Passwort in den Argumenten an `fbtracemgr` (Test und Ersatzprogramm-Protokoll); Tests laufen
  jetzt auch unter 5.1 — vorher war die Zusage „5.1" unbelegt (L5).
- **Negativ:** I4/I5 hat die Größengrenze gerissen (7 Dateien, ~800 Zeilen) — begründet, aber die Grenze war vor
  Phase 2 bekannt. `-Gate All` lief in `c26fb8b` mit einem Fehler aus (Pester nach dem Linter nicht ladbar), gefunden
  erst durch die neuen Tests mit `Mock` (`ada07b5`). `SupportsShouldProcess` an `Start-`/`Stop-TraceSession` dient nur
  der Analyzer-Regel; die Skripte bieten kein `-WhatIf` an. Stopp-Bestätigung über den Meldungstext und das Format
  von `-LIST` sind nur gegen Ersatzprogramme getestet. Vermutung ohne Beleg: Kürzt `fbtracemgr -LIST` lange Namen,
  findet der Stopp die Sitzung nicht und löscht die Zustandsdatei (Exit 3) — beim ersten echten Lauf prüfen.
- **Lehren-Filter:** L5, L6, L7 sind je ein Fall in einem Projekt (so vermerkt); L6 betrifft nur Pester. L3, L4 bleiben offen.

### Changed
- `BACKLOG.md`: Datenbankfilter-Idee zusammengeführt (zwei Einträge zu `include_filter`), Passwortdatei-Prüfung zu
  den Ideen, neuer Refactoring-Kandidat `TraceCommon.ps1`/`Read-TraceConfig` (Hotspot), `#Requires` angepasst.
- `STATE.md`: Reflexions-Marker auf das dritte Inkrement nach I5; Nächster Schritt I11.

### Confidence / Ungeprüft
- Health-Check, Struktur-Checks: Validator OK. Interna-Scan gegen `.internal-terms` über alle versionierten Dateien:
  0 Treffer; Suche mit Wortgrenzen für kurze Namen nicht gemacht (keine Liste in `docs/local/` geprüft).
- Hotspots seit `5305266`: keine Datei mit mehr als 2 Commits; einziger Kandidat nach Größe `TraceCommon.ps1`.
- Testgüte der seit `5305266` geänderten Kern-Dateien: Mutationsproben in I15 (6/6), I14 (3/3), I4/I5 (16/16).
- Roadmap: I11, I12, I13 in dieser Reihenfolge (Parser, bauen aufeinander nicht auf; I13 zuletzt, weil seine
  Zusammenfassung die Ereignisarten aus I12 mitzählen soll); I8-Rest zum Security-Sweep (2026-11-21), weil beide
  dieselben Quellen lesen. Keine Änderung an `TODO.md` nötig außer dem Hinweis bei I8 (eigener Commit).

## 2026-11-08 I4 + I5 – Trace-Skripte für Firebird 5 ohne Klartext-Passwort

Commits `266d6a4` (Tests rot, Stub mit Vertrag), `d9a2a8b` (Umsetzung), dazu `ada07b5` (Gate-Fix aus I14, beim Lauf
gefunden). Freigabe des Owners 2026-11-08. Gebündelt, weil beide Punkte dieselben drei Dateien neu schreiben; die
Größengrenze (~5 Dateien, ~400 Zeilen) ist damit überschritten (7 Dateien, ~800 Zeilen inkl. Tests) — bewusst, ein
Split hätte die Skripte zweimal umgebaut. Grundlage ist der Entwurf des Owners für Firebird 5.0.4, mit dem drei echte
Traces aufgezeichnet wurden (nur gezählt: jede Datei beginnt mit `Trace session ID … started`; Anmeldung dort per
Passwortdatei mit SYSDBA, ohne Rolle). Übernommen ohne Umgebungswerte: `config.json` des Entwurfs nur als Struktur.

**Trigger-Matrix:** Architekturentscheidung → `architecture/ADR/ADR-002-trace-anmeldung.md`; neue Konfiguration →
`README.md`, `README.de.md`, `features/TRACE_CAPTURE.md`, `architecture/CONFIGURATION.md`; neue Funktionen/Datei →
`architecture/OVERVIEW.md` (Datenfluss, Module), `architecture/PROJECT_LAYOUT.md`, `KICKOFF.md` (Dateitabelle);
Auth/Secrets → `security/AUTHENTICATION.md`, `architecture/CREDENTIAL_STRATEGY.md`, `operations/SECRETS_MANAGEMENT.md`,
`security/THREAT_MODEL.md` (Bedrohung 3 und 4), `security/DATA_HANDLING.md`; neue Exception/Exit-Codes →
`architecture/ERROR_HANDLING.md`, `operations/MONITORING.md`, `operations/RUNBOOK.md`; Einrichtung →
`operations/SETUP.md`; Binary-Nutzung → `architecture/DEPENDENCIES.md`; Begriffe → `GLOSSARY.md`; K4 behoben →
`KNOWN_ISSUES.md`; Bestand-Hinweise → `CONVENTIONS.md`, `principles/LOGGING.md`, `testing/UNIT_TESTS.md`; Reste →
`BACKLOG.md`; Risiko → `STATE.md`; Lesson → `LESSONS_LEARNED.md` L7. Keine neue Abhängigkeit (Security-Currency:
kein Ereignis; Kadenz-Sweep erst 2026-11-21 fällig).

### Added
- `TraceCommon.ps1`: `Read-TraceConfig`, `Get-TraceAuthArgumentList`, `Start-TraceSession`, `Stop-TraceSession`,
  `Get-TraceSessionList`, `Invoke-FbTraceMgr` (einziger Aufruf von `fbtracemgr`), `Resolve-TraceExitCode`,
  Klasse `TraceException`.
- `fbtrace50.conf`: Firebird 4.0/5.0, ohne `include_gds_codes` (alle Fehler), mit `log_sweep` und Abschnitt `services`
  (`log_services`) — passend zu den Sweep- und Service-Feldern des Parsers (I15). `fbtrace30.conf` bleibt unverändert.
- `config.json`-Schlüssel `PasswordFile`, `UseTrustedAuth`, `Role`, `OutputDirectory`, `SessionName`; `%VAR%` in Pfaden.
- `trace_stop.ps1 -Id <n>`.
- 32 Tests (`tests/TraceCommon.Tests.ps1`).

### Changed
- `trace_start.ps1`/`trace_stop.ps1` neu: PowerShell 7.4+, `[CmdletBinding()]`, `Stop` + Strict Mode, ASCII, Status
  über `Write-Information`, Exit-Codes 0–6 (vorher 1–4, `fbtracemgr`-Fehler nicht ausgewertet).
- Stopp findet die Sitzung über `trace_session.json` und den Sitzungsnamen statt über die neueste `*.log` auf `E:\`.
- `config.sample.json`: kein Passwort, `TRACE_USER`/`TRACER` statt SYSDBA, `Firebird_5_0` statt `Firebird_4_0_3`
  (I8, erster Punkt).

### Fixed
- K4: falsche Logdatei beim Stopp; Hinweis nannte `trace-stop.ps1`.

### Security
- Kein Passwort mehr in Befehlszeile und `config.json`; ein verbliebener `Password`-Schlüssel bricht ab (Test).
- Test: `config.json` ist nicht in git (Schicht 3 aus `CONVENTIONS.md` 6.1.1), `trace_session.json` wird ignoriert.

### Confidence / Ungeprüft
- **Kein Lauf gegen einen echten Server mit diesen Skripten.** Geprüft: 99 Tests grün unter PowerShell 7.6.9, unter
  5.1 98 grün + 1 übersprungen (byte-genaue Datei nur ab 7.4); Mutationsprobe 16 Mutanten, 15 erkannt, nach einem
  zusätzlichen Test 16/16; Lauf mit einem selbst kompilierten Ersatz-`fbtracemgr` (Start, Zweitstart abgelehnt mit
  Exit 2, Stopp über `-LIST` und über `-Id`, Logdatei byte-genau mit UTF-8-Umlaut, Parser liest sie, Passwort in keinem
  Argument).
- Ungeprüft übernommen: Format von `fbtracemgr -LIST` (`Session ID:` / `name:`) und die Stopp-Bestätigung
  `Trace session ID <n> stopped` — aus dem Entwurf, nur gegen Ersatzprogramme getestet. `-TRUSTED` und `-ROLE` gegen
  keinen Server geprüft. Ob `log_sweep`/`services` unter Firebird 4.0 genauso wirken, nicht geprüft.
- Beim Lauf mit dem Ersatzprogramm war die Logdatei während der Aufzeichnung leer (gepuffert); der Weg über die erste
  Logzeile greift deshalb selten, `-LIST` ist der Normalfall (`features/TRACE_CAPTURE.md`).
- Die Entwurfsdateien wurden gelesen (Skripte, README, `fbtrace50.conf`); von `config.json` des Owners nur Schlüssel und
  drei Ja/Nein-Werte, von den Logs nur Zeilenzahl und ob die erste Zeile passt.
- Abweichung von `CONVENTIONS.md` §3 (gemeinsame Logik als Modul): `TraceCommon.ps1` per Dot-Sourcing, in ADR-002 und
  `PROJECT_LAYOUT.md` begründet.

### Lessons Learned
- Ersatzprogramm statt nur Mock deckte die Pufferung der Logdatei auf → L7.

## 2026-11-08 I14 – CI mit PSScriptAnalyzer und Pester

Commits `8c75645` (Tests: Charakterisierung `-AnalyzeOnly`, lauffähig unter 5.1), `ca1edc9` (Analyzer-Befunde
beseitigt), `c26fb8b` (Workflow, Settings, Gate-Skript). Freigabe des Owners 2026-11-08.

**Trigger-Matrix:** Build-/Prüfpfad geändert → `operations/DEPLOYMENT.md`; neue Abhängigkeit (`actions/checkout`,
Runner, PSGallery in CI) → `architecture/DEPENDENCIES.md` + `security/DEPENDENCY_AUDIT.md` (Ereignis-Abgleich); neue
Dateien → `architecture/PROJECT_LAYOUT.md`; Gate-Befehle → `CONVENTIONS.md` §9; Fehler beseitigt (K5) → `KNOWN_ISSUES.md`;
Risiko → `STATE.md`; Lessons → `LESSONS_LEARNED.md` L5, L6; erledigte Schuld → `BACKLOG.md`. README unverändert (keine
Nutzerfunktion; kein Badge, solange der Workflow nie lief).

### Added
- `.github/workflows/ci.yml`: bei Push und Pull Request zwei Jobs auf `windows-latest` — PowerShell 7 (Lint und Tests)
  und Windows PowerShell 5.1 (Tests). `actions/checkout` auf Commit-SHA gepinnt (v7.0.1), Workflow nur mit Leserecht.
- `PSScriptAnalyzerSettings.psd1`: Stufen ParseError, Error, Warning; keine Regel ausgeschlossen. Entscheidung:
  `Information` (z. B. Leerzeichen am Zeilenende, 34 Hinweise) ist kein Gate; Ausnahmen nur im Code mit Begründung.
- `tools/Invoke-QualityGate.ps1`: dieselben Befehle lokal und in CI; lädt genau die gepinnten Versionen.
- Charakterisierungstest für den `-AnalyzeOnly`-Bericht (67 Tests).

### Changed
- Tests laufen jetzt auch unter Windows PowerShell 5.1 (vorher scheiterten dort alle am Aufbau).
- `-AnalyzeOnly`-Bericht in eigene Funktion mit begründeter `Write-Host`-Ausnahme; Verhalten gleich.

### Fixed
- K5: `trace_start.ps1`/`trace_stop.ps1` als UTF-8 mit BOM.

### Confidence / Ungeprüft
- **Der Workflow ist nie auf GitHub gelaufen** (kein Push erlaubt). Geprüft: YAML mit `python yaml` lesbar; die
  Befehle des Workflows lokal unter PowerShell 7.6.9 und 5.1 ausgeführt, auch in einem frischen Klon (Zeilenenden wie
  im CI-Checkout). Ungeprüft: `Install-Module` auf dem Runner (vor allem unter 5.1: PowerShellGet-Version, NuGet-Provider),
  Laufzeit, kein `actionlint` verfügbar.
- Gate lokal: grün (0 Befunde, 67/67 unter beiden Versionen); rot mit Exit 1 auf dem Code vor `ca1edc9` (21 Befunde),
  rot mit Exit 2 bei absichtlich falschem Test.
- Mutationsprobe am verschobenen Bericht: 3 Mutanten, 3 erkannt.
- Der Interna-Hook prüft weiter nur Begriffe; das Gate ist **nicht** im pre-commit-Hook (bewusst: Laufzeit ~10 s je Commit).

### Lessons Learned
- Zugesagte Laufzeit (5.1) war ohne Tests darunter nicht belegt → L5.
- `Stop` im Gate-Skript änderte das Verhalten der getesteten Skripte → L6.

## 2026-11-08 I15 – Sweep- und Service-Ereignisse lesen

Commits `0492e4d` (Tests rot, Vertrag mit leeren Feldern), `bb82165` (Umsetzung). Zustimmung des Owners (2026-11-07)
für genau diese zwei Erweiterungen; sonst keine Parser-Änderung.

**Trigger-Matrix:** neue Felder im Ausgabe-Vertrag → `features/TRACE_PARSING.md`; Feldabdeckung → `features/PSEUDONYMIZATION.md`;
`STATE.md`. Keine neue Abhängigkeit, kein neuer Parameter.

### Added
- `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` aus dem Block `Transaction counters:` (`SWEEP_START`, `SWEEP_FINISH`);
  Laufzeit, Zähler und Tabellenstatistik des Sweeps kommen über die bestehenden Felder.
- `ServiceName` und `ServiceID` für `*_SERVICE`-Ereignisse; Benutzer, Adresse und Programm der Dienstzeile in den
  bestehenden Verbindungsfeldern (damit pseudonymisiert). Schalterzeile mit Dateipfaden bewusst nicht gelesen.
- Fixture `tests/fixtures/trace_fb5_sweep_service.log`, synthetisch nach `TracePluginImpl.cpp`, `tra.cpp`, `svc.cpp`
  (Firebird v5.0-release), alle Werte ausgedacht.

### Confidence / Ungeprüft
- 13 neue Tests (davon 1 Pseudonymisierung), 66 grün; Mutationsprobe 6 Mutanten, alle erkannt (einer erst nach
  unterschiedlichen Werten für OAT und OST im Fixture).
- Format nur aus dem Quellcode, nicht an einem echten Trace geprüft: die vorhandenen echten Logs enthalten keine Sweep-
  oder Service-Ereignisse (nur gezählt; dort war weder `log_sweep` noch `log_services` eingeschaltet).
- `.gitignore` schließt `*.log` aus: das neue Fixture ist mit `git add -f` aufgenommen; Git normalisiert seine
  Zeilenenden. Das ältere Fixture `trace_fb5_windows.log` ist **nicht** im Repo (Tests scheitern im frischen Klon) —
  Owner-Entscheidung, nicht Teil dieser Zustimmung.
- Interna-Prüfung nur von Hand (`.internal-terms` fehlt im Klon): keine internen Begriffe, Adressen aus 192.0.2.0/24.
