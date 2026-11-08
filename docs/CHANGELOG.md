# Changelog – PSFirebirdTraceParser

Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/).
Einträge chronologisch absteigend (neueste oben). Jeder Eintrag entspricht
genau einem Inkrement (= einem Commit oder einer eng zusammengehörigen
Commit-Serie). Roadmap-Änderungen (KICKOFF Phase 1 Punkt 2a), Reflexions-Refreshs und
Post-Mortems erhalten einen kurzen Eintrag ohne I#.

Nicht alle Sektionen sind in jedem Eintrag nötig — leere Sektionen weglassen.

Ältere Einträge (I1–I10, K3, Reflexion nach I3): `changelog/ARCHIVE-CHANGELOG-I01-I10.md`; I4/I5, I11, I12, I14, I15
und Reflexion nach I5: `changelog/ARCHIVE-CHANGELOG-I11-I15.md`.

---

## 2026-11-08 I19 – `Show-TraceStructure.ps1 -Engine Auto|PowerShell|CSharp`, Standard Auto

Commits `b7063da` (Tests rot, Stub nimmt immer PowerShell), `9965aad` (Umsetzung). Klein: Skript ~30 Zeilen,
Tests ~110 Zeilen.

**Trigger-Matrix:** neuer Parameter → `README.md`, `README.de.md`, `features/TRACE_PARSING.md` (Parameter, Ablauf),
`architecture/CONFIGURATION.md`; Datenfluss → `architecture/OVERVIEW.md` (Mermaid mit Engine-Wahl,
Modul-Verantwortung); neue Begriffe → `GLOSSARY.md` (Engine, Parität); neues Problem gefunden →
`KNOWN_ISSUES.md` K8, `TODO.md` I21.

### Added
- `-Engine` (`[ValidateSet('Auto', 'PowerShell', 'CSharp')]`, Standard `Auto`): Auto nimmt den C#-Parser, wenn
  PowerShell 7 läuft und `FirebirdTraceParser.dll` neben dem Skript oder unter `bin/` liegt, sonst den PowerShell-Parser.
  `-Engine CSharp` unter 5.1 oder ohne DLL ist ein Fehler ohne Ausgabe. `-Verbose` schreibt `Engine: <Name>`.
  Gleiche Parameter, gleiche Startmeldung; Warnungen und Verbose kommen aus dem Cmdlet über die Streams des Skripts.
- `tests/Show-TraceStructure.Engine.Tests.ps1` (11 Tests): Werteprüfung, Wahl unter 7 und 5.1, ohne DLL, DLL neben dem
  Skript (eigener Prozess, geprüft wird auch der Ladepfad), Pseudonymisierer mit beiden Parsern auf jedem Fixture
  (gleicher Schlüssel, `-RedactLiterals`, jedes Feld gleich).
- Paritätstests laufen jetzt über das Skript (`-Engine PowerShell` gegen `-Engine CSharp`) und prüfen, dass wirklich die
  verlangte Engine lief (sonst würde ein Parser mit sich selbst verglichen).

### Changed
- Unter PowerShell 7 mit gebauter DLL laufen jetzt **alle** bestehenden Parser-Tests gegen den C#-Parser (Standard
  Auto); unter Windows PowerShell 5.1 gegen den PowerShell-Parser. Beide Läufe grün.

### Messung (kleine Dateien, je frischer `pwsh`-Prozess, Zeit inkl. Zählen in der Pipeline)

| Datei | Größe | Ereignisse | PowerShell | C# | Speicher (Spitze) PowerShell / C# |
|---|---|---|---|---|---|
| synthetisch (Fixtures wiederholt) | 15 MB | 35 779 | 13,9 s / 12,8 s | 1,57 s / 1,58 s | 287 / 196 MB |
| echtes Log (nur gezählt) | 3,1 MB | 9 424 | 3,37 s / 3,36 s | 0,44 s / 0,49 s | 203 / 132 MB |

Parität auf beiden Dateien: 0 Unterschiede (nur Anzahl ausgegeben, kein Inhalt). Etwa 8-mal schneller über das Skript;
der Versuch vom 2026-11-07 maß das Cmdlet direkt (Faktor ~30) — die Pipeline in PowerShell kostet mit.

### Confidence / Ungeprüft
- RED: 23 von 26 Tests rot gegen den Stub (z. B. `Expected engine CSharp, the script reported [Engine: PowerShell]`).
  Die 5 Pseudonymisierer-Tests waren zuerst auch gegen den Stub grün (beide Läufe PowerShell) — deshalb prüfen sie jetzt
  zusätzlich, dass `-Engine CSharp` wirklich C# nimmt.
- Gate: Build ✓, PSScriptAnalyzer ✓ 0, Pester 7.6.9: 216 passed, 1 skipped (5.1-Test); Windows PowerShell 5.1:
  153 passed, 64 skipped.
- Mutationsprobe (Skript, Kindprozess, Kontrolle 0): 8 Mutanten, alle rot. Einer nur unter 5.1 erkennbar
  (`$isCore` in der Wahl entfernt: unter 5.1 24 rot), einer durch Aufhängen (ohne `-MaxBlockLines` an das Cmdlet lief
  der Test über 10 Minuten, abgebrochen) — dabei gefunden: K8.
- **Gefunden: K8** — `Get-LineEnd` sucht mit kulturabhängigem `IndexOf("`n", start)`; das kostet je Aufruf Zeit
  proportional zum Rest des Textes (gemessen: 2000 Aufrufe auf 6 MB 6,6 s, mit `[char]` 14 ms). Ein Ereignis mit
  sehr vielen Zeilen wird damit quadratisch langsam — in **beiden** Parsern gleich (wörtliche Übertragung). Nicht in
  I19 behoben (Verhaltensänderung in beiden Parsern, eigener Test): `TODO.md` I21.
- Nicht geprüft: PowerShell 7.4/7.5 (nicht installiert); Laden einer zweiten DLL-Kopie im selben Prozess (anderer Pfad,
  gleicher Name) — der Test dafür läuft bewusst in einem eigenen Prozess.

## 2026-11-08 Reflexion nach I18

Kein Inkrement (KICKOFF Phase 1c, `REFLECTION.md`). Begutachtet: I16, I17, I18 (drittes abgeschlossenes Inkrement nach
I13).

### Advocatus Diaboli
- **Positiv:** Die Gleichheit ist geprüft, nicht behauptet: Paritätstests über 5 Fixtures, 10 Feld-Grenzfälle und
  24 Diagnose-Fälle (Objekte, Warnungen, Verbose); Mutationsproben je Inkrement (I16 16, I17 35, I18 23 Mutanten),
  überlebende Mutanten führten jedes Mal zu neuen Grenzfällen (I17 5, I18 3). Die Korrektur des Owners (Priorität
  PowerShell 7) kam mitten in I16 und wurde sofort umgesetzt (`net8.0`, Tests unter 5.1 übersprungen, ADR-003).
- **Negativ:** I17 lag mit ~520 Zeilen über der Faustgrenze (im CHANGELOG begründet). Der C#-Code überträgt das Skript
  wörtlich, auch Eigenheiten, die man sonst nicht bauen würde (kulturabhängige Suche, `LanguagePrimitives` für
  Tabellenzellen); das ist gewollt (ADR-003), macht den Code aber für C#-Leser fremd. Noch kein End-to-End-Konsument:
  Nutzer erreichen den C#-Parser erst mit `-Engine` (I19). Ungeprüft: Laden unter PowerShell 7.4/7.5 und der erste
  CI-Lauf mit Build. Die Diagnose-Paritätstests dauern lange (mehrere 5-MB-Dateien, ~60 s je Lauf), was die
  Mutationsprobe auf ~1 min je Mutant bringt.
- **Lehren-Filter:** L9 und L10 je ein Fall in einem Projekt (L10: zweiter Fall im selben Projekt). L4–L8 unverändert
  offen.

### Changed
- `TODO.md`: Verweis „ab I17" auf „seit I17" (Health-Check). `STATE.md`: Reflexions-Marker auf das dritte Inkrement
  nach I18; I11–I13 nach `changelog/ARCHIVE-STATE.md`, CHANGELOG-Einträge vor I13 nach
  `changelog/ARCHIVE-CHANGELOG-I11-I15.md` (Rotation, eigener Commit).

### Confidence / Ungeprüft
- Health-Check: ein Treffer („ab I17", behoben); Validator OK. Interna-Scan gegen `.internal-terms` über alle
  versionierten Dateien: 0 Treffer; Suche mit Wortgrenzen für kurze Namen nicht gemacht.
- Hotspots seit der Reflexion I13: nur neue C#-Dateien und Tests (je 2–4 Commits, größte `TraceBlockParser.cs` mit
  ~370 Zeilen) — keine Kandidaten. Der Kandidat `Show-TraceStructure.ps1` in `BACKLOG.md` bleibt bis zur Entscheidung in
  I20 zurückgestellt (wird der PowerShell-Parser entfernt, entfällt er).
- Roadmap: nächste drei Inkremente I19, I20, I8 (Rest, mit dem Sweep am 2026-11-21); nichts zu bündeln.

## 2026-11-08 I18 – C#-Parser: Diagnose gleich wie PowerShell

Commits `7784857` (Paritätstests für Diagnose rot), `c33a557` (Umsetzung, Grenzfälle nach der Mutationsprobe ergänzt).
Umfang: C# ~250 Zeilen (neu `TraceDiagnostics.cs`), Tests ~190 Zeilen.

**Trigger-Matrix:** neues Modul → `architecture/OVERVIEW.md`; Boundary (Zeitlimit im C#-Parser) →
`architecture/ERROR_HANDLING.md`; Teststrategie → `features/TRACE_PARSING.md`; Lehren → `LESSONS_LEARNED.md` L9, L10.
Kein neuer Parameter, keine neue Dependency.

### Added
- `TraceDiagnostics.cs`: Warnungen `Line <n>: …` mit derselben Zeilenzählung (Zwischenspeicher je Stück, Verschiebung
  nach gekürztem Rest), Vorspann, Zählung je `Action` in einer Hashtable ohne Groß-/Kleinschreibung, Zusammenfassung
  sortiert wie `Sort-Object` (Anzahl absteigend, Name nach aktueller Kultur ohne Groß-/Kleinschreibung).
- Block-Parser: `-MaxBlockLines` (auch für schon beim Weitertragen gekürzte Blöcke), `RegexMatchTimeoutException`
  je Ereignis gefangen; Stück-Schleife kürzt den Rest wie das Skript. Zahl im Zeitlimit-Text wie PowerShell
  (`LanguagePrimitives`, geprüft: `0.30000000000000004` → `0.3`).
- `tests/TraceParity.ps1`: `Invoke-TraceEngine`, `Compare-TraceRun` (Objekte, Warnungen, Verbose in Reihenfolge; Zeit
  und Startzeile ausgenommen). Der Paritätstest aus I17 vergleicht damit auch Warnungen und Verbose.
- `tests/FirebirdTraceParser.Diagnostics.Parity.Tests.ps1`: 24 Tests — Eingaben der Diagnose-Tests, kleine
  `UNKNOWN`/Startzeile, Sortierung mit Unterstrich, alle Fixtures mit CRLF und gemischt, zwei Warnungen in zwei Stücken,
  Kürzen über Stückgrenzen (mit Block, ohne Zeitstempel, Zählung Stücke später), Zeitlimit.

### Confidence / Ungeprüft
- RED: 35 von 36 Tests rot gegen den I17-Stand (z. B. `'Warnings[0]: [Line 6: event header not readable, fields left
  empty] vs []'`). GREEN: 52 von 52 der C#-Testdateien.
- Gate: Build ✓, PSScriptAnalyzer ✓ 0, Pester 7.6.9: 206 passed; Windows PowerShell 5.1: 149 passed, 57 skipped
  (C#-Tests, gewollt).
- Mutationsprobe (Neubau je Mutant, Kontrolle 0): 23 Mutanten, 1 kompilierte nicht. Zuerst 4 überlebt, dafür 3 Fälle
  ergänzt (Sortierung `TEST_A`/`TESTB`, zwei Warnungen in zwei Stücken, Warnung Stücke nach dem gekürzten Block).
  Danach 20 rot, 2 äquivalent: Vorprüfung `carry.Length > MaxBlockLines` verdoppelt (der Block wird dann im
  Block-Parser gekürzt, gleiche Ausgabe — nur der Speicherschutz greift später) und `cut ||` in der Vorprüfung des
  Block-Parsers (ein gekürzter Block hat mindestens so viele Zeichen wie Zeilen; nur bei lauter Leerzeilen anders).
- Zeitlimit-Test: bei 1 ms lief in 1 von 3 Läufen auch der kleine Folgeblock ins Limit (gemessen) — Test auf 0,5 s
  gegen eine Suche, die Sekunden braucht (L10). Nicht geprüft: Verhalten bei Zeitlimit in einer anderen Regex als der
  Anwendungszeile.
- Ungeprüft: `Write-Progress` (nicht verglichen; nur Anzeige).

### Lessons Learned
- Nachbau in zweiter Sprache: die stille Semantik der ersten (Hashtable ohne Groß-/Kleinschreibung, `-eq`, `[long]`-Cast,
  kulturabhängige Suche) als eigene Funktionen nachbauen und mit Grenzfällen prüfen → `LESSONS_LEARNED.md` L9.
- Zeitlimit-Tests mit großem Abstand zwischen Limit und Laufzeit, sobald zwei Läufe gleich sein müssen → L10.

## 2026-11-08 I17 – C#-Parser: alle Felder je Ereignis gleich wie PowerShell

Commits `aa0393b` (Paritätstest rot), `9c90746` (Umsetzung, Grenzfälle nach der Mutationsprobe ergänzt). Über der
Faustgrenze im Umfang (~520 Zeilen: C# ~430, Test ~95), aber eine Entscheidung und ein Zweck; ein Split hätte den
Paritätstest auf den Fixtures halbiert. Gebündelt (Rest aus I18 vorgezogen): Routinen, Trigger, Verbindungsdauer —
ohne sie ist die Parität auf den I12-Fixtures nicht erreichbar.

**Trigger-Matrix:** neue Module → `architecture/OVERVIEW.md` (Modul-Verantwortlichkeiten, Constraint); Teststrategie →
`features/TRACE_PARSING.md`; Roadmap (I12-Teil nach I17) → `TODO.md`, `STATE.md`. Keine neue Dependency, kein neuer
Parameter, kein neues Feld (Vertrag unverändert).

### Added
- `TraceBlockParser.cs` (alle Abschnitte von `ConvertFrom-TraceBlock` in derselben Reihenfolge mit denselben
  Vorprüfungen), `TableStatParser.cs`, `PowerShellSemantics.cs` (`-eq` invariant ohne Groß-/Kleinschreibung,
  Hashtable mit `CurrentCultureIgnoreCase`, `[long]"Text"`: Ziffern direkt, sonst `LanguagePrimitives` wie der Cast).
  Kulturabhängige Aufrufe des Skripts (`IndexOf(string)`, `EndsWith`, `StartsWith`, `LastIndexOf("\n")`) bleiben
  kulturabhängig; die Analysator-Regeln dagegen sind mit Begründung unterdrückt.
- `tests/FirebirdTraceParser.Parity.Tests.ps1`: DLL vorhanden, 5 Fixtures, 10 erzeugte Grenzfälle — 16 Tests.

### Confidence / Ungeprüft
- RED: 11 von 12 Tests rot gegen den I16-Stand (z. B. `'#0.DatabasePath: [C:\DATA\SAMPLE.FDB] vs [] (null)'`).
  GREEN: 28 von 28 (Parität + Engine) unter PowerShell 7.6.9.
- Gate: Build ✓ 0 Warnungen, PSScriptAnalyzer ✓ 0, Pester 7.6.9: 182 passed; Windows PowerShell 5.1: 149 passed,
  33 skipped (C#-Tests, gewollt).
- Mutationsprobe (Neubau je Mutant, Kontrolle 0): 35 Mutanten in Block-Parser, Tabellenstatistik, Semantik und Regex;
  zuerst 7 überlebt, dafür 5 Grenzfälle ergänzt (CREATE_DATABASE/doppeltes Detach, SQL mit Leerzeichen, nur unlesbare
  Tabellenzeilen, SQL direkt vor der Tabellenstatistik, Fehlertext mit Leerzeichen am Ende). Danach 31 rot, 4
  äquivalent: Vorprüfung `hasStatement` vor Routinen (reine Abkürzung), `Success`-Prüfung der Leistungszähler (leere
  Gruppe ergibt ohnehin 0), `nameWidth <= 0` (die Regex verlangt `Table\s+Natural`, Breite ist mindestens 3),
  Routinenname gierig statt faul (das `$` erzwingt denselben Treffer).
- Belegt: `[long]"01e3"` = 1000, `[long]"0x1F"` = 31 in PowerShell 7.6 — der Grenzfall prüft also den Weg über
  `LanguagePrimitives`. Nicht geprüft: Unterschiede der Kultur (`CurrentCulture` de-DE lokal, CI en-US) — beide
  Parser laufen in derselben Kultur, ein Vergleich über Kulturen hinweg ist nicht Ziel.
- Ungeprüft: Ausnahmen auf demselben Weg — eine Zahl mit mehr als 19 Ziffern bricht in beiden ab, aber mit
  verschiedenen Fehlertexten (Skript: Methodenaufruf, Cmdlet: `PSInvalidCastException`); kein Test.

## 2026-11-08 I16 – C#-Parser: Entscheidung, Projektgerüst, Build in Gate und CI

Commits `4b2da51` (Tests rot, Stub mit Vertrag, ADR-003, Build in Gate und CI), `1a33b89` (Umsetzung, Ziel `net8.0`).
Kein Split nötig: 5 C#-Dateien (~260 Zeilen), 2 Testdateien (~190 Zeilen), Gate/CI ~40 Zeilen.

**Trigger-Matrix:** Architekturentscheidung → `architecture/ADR/ADR-003-parser-in-csharp.md`; neues Modul und
Datenfluss → `architecture/OVERVIEW.md` (Stack, Modul-Verantwortlichkeiten, Mermaid, Constraints, Lese-Pfad); neue
Schicht/Ordner → `architecture/PROJECT_LAYOUT.md`; neue Dependencies (.NET SDK, NuGet, `actions/setup-dotnet`) →
`architecture/DEPENDENCIES.md`, `security/DEPENDENCY_AUDIT.md` (Ereignis-Prüfung mit Websuche und `dotnet list
package --vulnerable`); Build-Pfad → `operations/DEPLOYMENT.md`, `operations/SETUP.md`; Gate-Regel →
`CONVENTIONS.md` §9; Risiko → `STATE.md`. README nicht ausgelöst: das Cmdlet liefert erst die Kopfzeile und ist für
Nutzer erst mit `-Engine` (I19) gedacht.

### Added
- `src/FirebirdTraceParser/` (`net8.0`, einziges Paket `PowerShellStandard.Library` 5.1.1 nur zum Übersetzen,
  `packages.lock.json`): Cmdlet `ConvertFrom-FirebirdTrace -Path -MaxBlockLines -RegexTimeoutSeconds`, liest in
  4-MB-Stücken wie das Skript, Kopfzeile (Zeitstempel, Action, Prozess, Adresse, `ErrorSource`), alle 46 Felder in
  Vertrags-Reihenfolge mit denselben Standardwerten und Typen als echtes `PSCustomObject`.
- `tools/Invoke-QualityGate.ps1 -Gate Build` (Exit 4); `All` = Build, Lint, Test. CI Job PowerShell 7 mit
  `actions/setup-dotnet` (SDK 10.0.x) und Build-Schritt; `global.json`; `.gitignore` für `bin/` und `obj/`.
- `tests/TraceParity.ps1` (strenger Vergleich: Namen, Reihenfolge, Typ, Wert, `$null` gegen leer, ordinal) und
  `tests/FirebirdTraceParser.Engine.Tests.ps1` (16 Tests: Laden, Parameter, fehlende Datei, Feldliste je Fixture,
  Kopfzeile je Fixture, Standardwerte, Stückgrenze bei 5 MB).

### Changed
- Korrektur des Owners während I16: **Priorität PowerShell 7**, Windows PowerShell 5.1 für den C#-Kern nicht Pflicht.
  Erst als `netstandard2.0` angelegt (lud unter 5.1 und 7, geprüft), dann auf `net8.0` umgestellt (kleinstes LTS-Ziel
  für PowerShell 7.4+; `NETStandard.Library` entfällt, neuere APIs möglich). Unter 5.1 lädt die DLL nicht (geprüft:
  `FileNotFoundException`), die Tests des C#-Parsers sind dort übersprungen; der 5.1-CI-Job baut nicht.

### Confidence / Ungeprüft
- RED: 13 von 16 Tests rot gegen den Stub (z. B. `Expected 7, but got 0`, `count: 7 vs 0`); die drei grünen
  (DLL liegt vor, Cmdlet geladen, Parameterprüfung) prüft schon der Stub — gewollt, sie sichern Build und Laden.
  GREEN: 16 von 16 unter PowerShell 7.6.9; unter Windows PowerShell 5.1 16 übersprungen.
- Gate: Build ✓ (0 Warnungen mit `latest-recommended`), PSScriptAnalyzer ✓ 0, Pester 7.6.9: 166 passed;
  Windows PowerShell 5.1: 165 passed, 1 skipped (vor der Umstellung auf `net8.0`; danach Engine-Tests übersprungen).
- Mutationsprobe (Neubau je Mutant, Kontrolle 0): 16 Mutanten, 14 rot. Nicht erkannt: `ChunkSize` 4 MB → 1 MB
  (äquivalent: die Teilung hängt nicht von der Stückgröße ab) und `Replace("\r", …)` ausgeschaltet (bei nur
  Kopfzeilen nicht sichtbar, `\S+` endet vor `\r`; CRLF-Fälle kommen in I18).
- Nicht geprüft: Laden unter PowerShell 7.4/7.5 (.NET 8/9; nicht installiert) und der erste CI-Lauf mit Build.
  Annahme: `windows-latest` mit `actions/setup-dotnet` v6.0.0 baut wie lokal.
- Struktur-Check mit Template-Skript.

## 2026-11-08 Roadmap – C#-Parser parallel zum PowerShell-Parser (I16–I20)

**Trigger-Matrix:** keine Zeile ausgelöst (nur Planung in `TODO.md`/`STATE.md`).

### Changed
- `TODO.md`/`STATE.md`: neue Inkremente I16–I20 nach der Entscheidung des Owners vom 2026-11-08 (Parser in C#
  neu bauen, beide Parser verhalten sich gleich, bis C# den PowerShell-Parser ersetzen kann). Wegen der Größengrenze
  in fünf Schritte geteilt: Gerüst und Build, Felder mit Paritätstest, I12/I13-Verhalten, `-Engine`-Schalter,
  Abschluss. I8 und der Refactoring-Kandidat `Show-TraceStructure.ps1` bleiben getrennt (andere Quellen bzw. durch
  I20 vielleicht überflüssig).

## 2026-11-08 Fix – Zeitlimit-Test wackelte

**Trigger-Matrix:** keine Zeile ausgelöst (nur Test).

### Fixed
- `tests/Show-TraceStructure.Diagnostics.Tests.ps1`: Der Test zum Regex-Zeitlimit (I13) schlug in etwa 1 von 6 vollen
  Läufen fehl (keine Zeitlimit-Warnung): Ein langer Text ohne Umbrüche lief über eine schnelle Suche, bei der .NET das
  Zeitlimit nicht zuverlässig prüft. Neu: viele Leerzeilen mit Leerzeichen, die Suche muss zurückverfolgen.

### Confidence / Ungeprüft
- 12 von 12 Läufen der Testdatei grün (vorher 2 von 8 rot); Mutation „jede Ausnahme weiterwerfen“ wird erkannt.
  Unter Windows PowerShell 5.1 nur in der CI geprüft (lokal fehlt Pester 5.7.1 für 5.1).

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
