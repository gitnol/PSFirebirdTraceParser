# Changelog – PSFirebirdTraceParser

Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/).
Einträge chronologisch absteigend (neueste oben). Jeder Eintrag entspricht
genau einem Inkrement (= einem Commit oder einer eng zusammengehörigen
Commit-Serie). Roadmap-Änderungen (KICKOFF Phase 1 Punkt 2a), Reflexions-Refreshs und
Post-Mortems erhalten einen kurzen Eintrag ohne I#.

Nicht alle Sektionen sind in jedem Eintrag nötig — leere Sektionen weglassen.

---

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

## 2026-11-08 Reflexion nach I3

Kein Inkrement (KICKOFF Phase 1c, `REFLECTION.md`). Erste Reflexion; begutachtet: I1, I9, I10, I7, K3, I6, I2, I3.

### Changed
- Fakten-Drift nach I2/I3/I6/I9 in Querschnitts-Docs behoben: Ablauf des Parsers (Streaming statt `Get-Content -Raw`),
  Hash-Verfahren (HMAC statt SHA-256) in Übersicht, Abhängigkeiten, Secrets- und Credential-Doku, Teststand (seit I9
  statt „ab I2"), erledigte Zeilen in „Bekannte Einschränkungen" von `features/TRACE_PARSING.md` und `features/PSEUDONYMIZATION.md`.
- `STATE.md`: zwei Risiken auf „gemindert" (Pseudonymisierung, Tests); Reflexions-Marker auf I11.
- `TODO.md`: Altformat-Abschnitt „Abgeschlossen" entfernt (I1 steht mit Hash in `STATE.md`).
- `REFLECTION.md` wieder auf Template-Stand v37 (veralteter Projektblock zu Backports entfernt).
- `LESSONS_LEARNED.md`: Kopf und Pflege auf v37; neu L3, L4.
- `BACKLOG.md`: erledigte technische Schuld entfernt, Hotspot `Pseudonymize-FirebirdTrace.ps1` als Refactoring-Kandidat.

### Confidence / Ungeprüft
- Interna-Scan nur mit Ersatzliste: `.internal-terms` fehlt in diesem Klon, der Hook ist nicht aktiviert
  (`core.hooksPath` leer). Owner-Aufgabe in `TODO.md` besteht weiter.
- PSScriptAnalyzer 1.25.0 auf dem Stand `9d5b1b9`: 0 ParseError, 0 Error, 20 Warnungen (vorher 28).

## 2026-11-07 I3 – Pseudonyme per HMAC-SHA256 mit Kundenschlüssel

**Trigger-Matrix:** Architekturentscheidung → `architecture/ADR/ADR-001-pseudonymisierung-hmac.md`; neue Parameter →
`features/PSEUDONYMIZATION.md`, README (beide Sprachen); Bedrohung gemindert → `security/THREAT_MODEL.md` Bedrohung 2;
Umgang mit Schlüssel/Zuordnung → `security/DATA_HANDLING.md`.

### Changed
- Pseudonyme = HMAC-SHA256 mit geheimem Schlüssel statt ungesalzenem SHA-256. **Pseudonyme ändern sich gegenüber
  früheren Läufen**; alte und neue Exporte sind nicht vergleichbar.

### Added
- `-KeyFile`: Schlüssel (Base64, ≥ 32 Byte); fehlt die Datei, wird sie mit 32 Zufallsbytes angelegt und auf den aktuellen
  Benutzer beschränkt. Ohne `-KeyFile`: Zufallsschlüssel nur für diesen Lauf, mit Warnung.
- `-MappingFile`: Zuordnung Pseudonym → Original (CSV) für den Verantwortlichen, Rechte nur aktueller Benutzer, meldet Kollisionen.
- 8 Tests (alle vorher rot).

### Security
- Pseudonyme sind ohne Schlüssel nicht mehr vorausberechenbar (Test: ungleich SHA-256 des Klartexts). Schlüssel erscheint
  weder in der Ausgabe noch in der Zuordnungsdatei (Test). Schlüsselbytes werden nach dem Einlesen gelöscht.

### Confidence / Ungeprüft
- Mutationsprüfung: 5 Mutanten, alle erkannt. Zugriffsrechte unter Windows nachgesehen (nur aktueller Benutzer, keine
  Vererbung); unter Linux (`SetUnixFileMode`, .NET 7+) nicht getestet.
- Windows PowerShell 5.1 nicht getestet (Code nutzt nur .NET-Framework-kompatible Aufrufe; die Tests selbst brauchen PowerShell 7).

## 2026-11-07 I2 – Pseudonymisierung: Klartext-Lücken geschlossen

**Trigger-Matrix:** Verhalten geändert → `features/PSEUDONYMIZATION.md` (Feldabdeckung als Vertrag), README (Felderliste);
Bedrohung gemindert → `security/THREAT_MODEL.md` Bedrohung 1; Fehler behoben → `KNOWN_ISSUES.md` K6, K7 (neu, direkt behoben).

### Fixed
- `DatabasePath` wird pseudonymisiert (Server-, Ordner-, Kundennamen).
- Mit `-RedactLiterals` werden auch Zahlen im SQL und Zeichenketten aus einem Zeichen pseudonymisiert; Ziffern in
  Bezeichnern, Pseudonyme und reine `%`-Muster bleiben.
- `-SensitiveKeywords` (Stichwort außerhalb von Literalen): alles ab der **ersten** WHERE/HAVING-Klausel wird ersetzt —
  vorher blieb alles bis zur letzten Klausel sichtbar (z. B. äußere Bedingungen vor einer Unterabfrage).
- `-AnalyzeOnly` schreibt die Auswertung nur noch auf die Konsole (vorher Formatierungsobjekte in der Ausgabe, K7).
- Keine Zuweisung mehr an die automatische Variable `$matches` (K6).

### Added
- 16 Tests (11 Charakterisierung, 5 Lücken); 4 der Lücken-Tests und der `-AnalyzeOnly`-Test waren gegen den alten Stand rot.

### Changed
- `-RedactLiterals` gilt jetzt für alle nicht leeren Literale (vorher ab 2 Zeichen), Hilfetext angepasst.

### Confidence / Ungeprüft
- Mutationsprüfung: 11 Mutanten, zunächst einer überlebt (Längenregel) — mit der Entscheidung „auch Einzelzeichen"
  und einem Test geschlossen.
- Hash-Verfahren unverändert (SHA-256) — folgt in I3.

## 2026-11-07 I6 – Streaming statt ganze Datei im Speicher

**Trigger-Matrix:** Verhalten geändert → README (beide Sprachen), `features/TRACE_PARSING.md` bleibt gültig (Felder unverändert); bekannter Fehler behoben → `KNOWN_ISSUES.md` K2; `TODO.md`, `STATE.md`.

### Changed
- `Show-TraceStructure.ps1` liest in 4-MB-Stücken, zerlegt jedes Stück mit einem Regex an den Ereignisgrenzen und gibt jedes
  Ereignis sofort in die Pipeline (vorher: ganze Datei lesen, alle Objekte sammeln, am Ende zurückgeben).
- Vorprüfung mit `Contains` vor den Regexen für SQL, Parameter, Plan, Tabellenstatistik und Laufzeit — Transaktions- und
  Verbindungsereignisse (im echten Log 90 %) brauchen sie nicht.
- Zähler (`DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks`) als `[long]`; Werte über 2^31 brachen vorher mit Fehler ab.
- Statusmeldungen über `Write-Verbose`/`Write-Progress` statt `Write-Host`; `[CmdletBinding()]` ergänzt.
- Wagenrückläufe (`\r`) werden entfernt; die ungetrimmte Tabellenstatistik enthielt bei gemischten Zeilenenden vorher `\r`.

### Added
- 3 Tests (Zähler > 2^31 und keine Host-Ausgabe waren rot; Ausgabe einzeln in die Pipeline sichert ab), 1 Prüfung ohne `\r`.

### Confidence / Ungeprüft
- Messungen (PowerShell 7.6, gleicher Rechner, `| ForEach-Object` als Verbraucher):
  - 78-MB-Datei, 175.000 Ereignisse (statementlastig, synthetisch): 58,3 s / 1.529 MB → 49,3 s / 321 MB.
  - 33 MB, 89.400 Ereignisse (echtes Firebird-5-Log 300-fach vervielfacht, nur lokal, nur Zeit/Speicher gelesen):
    24,9 s / 802 MB → 17,5 s / 302 MB.
- Gleichheit alt/neu per Skript auf allen Ereignissen geprüft: identisch bis auf die beabsichtigt entfernten `\r` in der
  Tabellenstatistik (10 Ereignisse im echten Log).
- Ein zeilenweiser Zwischenstand war langsamer (79,7 s) und wurde verworfen.

## 2026-11-07 I7 – Lizenzdatei und README-Drift

**Trigger-Matrix:** Bekannter Fehler behoben → `KNOWN_ISSUES.md` K1; README; `TODO.md` (Aufgabe „line-by-line" nach I6 verschoben).

### Added
- `LICENSE`: MIT (Entscheidung des Eigentümers 2026-11-07, wie im README angekündigt).

### Fixed
- `README.md`/`README.de.md`: Ausgabe-Properties entsprechen dem Code (`ClientIP`, `ApplicationPath`, Verbindung,
  Transaktion, `Params`, `TableStats`, Kopfzeile); Verweis auf `LICENSE`. Abgleich gegen die tatsächlich ausgegebenen
  Properties (27) per Skript.

### Confidence / Ungeprüft
- Nachgetragen in der Reflexion nach I3: Properties per Skript gegen die Ausgabe abgeglichen (siehe Fixed); keine Tests.

## 2026-11-07 K3 – Verbindungszeile in allen Formen (Teil von I6)

Vorgezogen, weil mit einem echten Firebird-5.0.4-Log belegt (12 von 298 Verbindungszeilen ohne Daten).

**Trigger-Matrix:** Bekannter Fehler behoben → `KNOWN_ISSUES.md` K3; `features/TRACE_PARSING.md`; `TODO.md` I6 (Aufgabe erledigt).

### Fixed
- `Show-TraceStructure.ps1`: Die Verbindungszeile wird unabhängig von Dateiendung, Rolle und Protokoll gelesen —
  `<internal>` (z. B. Firebirds Zugriff auf die Sicherheitsdatenbank), `USER:ROLLE`, `.fdb` klein, Linux-Pfade,
  IPv6 und lokale Protokolle ohne Port (`XNET:HOST`). Vorher blieben Datenbank, Benutzer und IP leer.

### Added
- 4 Tests (je ein roter Fall vor der Änderung).

### Confidence / Ungeprüft
- Echtes Log danach: alle 298 Einträge mit Verbindungsdaten. XNET und IPv6 nur synthetisch geprüft.

## 2026-11-07 I10 – Fehler-Ereignisse mit Fehlercodes

**Trigger-Matrix:** Neue Ausgabe-Properties → `features/TRACE_PARSING.md`, `README.md`, `README.de.md`; Pseudonymisierung erweitert → `features/PSEUDONYMIZATION.md`; `TODO.md`, `STATE.md`.

### Added
- `Show-TraceStructure.ps1`: Properties `ErrorSource`, `ErrorCodes`, `ErrorMessages` für `ERROR AT <Komponente>` und
  `WARNING AT <Komponente>` (Fehlerzeilen `%9lu : <Text>`, Format nach Firebird 5.0.4 `TraceStatusVectorImpl::getText`).
  Die Trace-Konfiguration zeichnet Sperrkonflikte und Deadlocks auf; bisher wurden diese Daten verworfen.
- `Pseudonymize-FirebirdTrace.ps1`: mit `-RedactLiterals` werden in `ErrorMessages` Schlüsselwerte (`("ID" = 42)`) und
  String-Literale gehasht; Constraint- und Tabellennamen bleiben lesbar.
- Tests: 11 neue (Fehler-Ereignisse, `FAILED`, `WARNING AT`, Abgrenzung zu SQL-Text, Pseudonymisierung der Fehlertexte).

### Changed
- `Action` enthält bei `FAILED …` und `UNAUTHORIZED …` den vollständigen Ereignisnamen (`FAILED EXECUTE_STATEMENT_FINISH`
  statt `FAILED`). Auswertungen, die auf `Action -eq 'FAILED'` prüfen, müssen angepasst werden (bisher dokumentiert war
  nur der Ereignisname der Kopfzeile).

### Confidence / Ungeprüft
- Alle 11 neuen Tests waren vor der Umsetzung rot (7) bzw. sichern Abgrenzungen ab; Mutationsprüfung: 8 Mutanten,
  alle erkannt (einer erst nach einem zusätzlichen Test).
- Echtes Firebird-5.0.4-Log enthält keine Fehler-Ereignisse; das Fehlerformat stammt aus dem Quellcode, nicht aus einem
  echten Log. Weitere Wertformen in Fehlertexten (z. B. Zahlen außerhalb von Schlüsselwerten) werden nicht gehasht.

## 2026-11-07 I9 – Kopfzeile plattformneutral, Parser-Tests

**Trigger-Matrix:** Verhalten geändert → `features/TRACE_PARSING.md` (Kopfzeile); bekannter Fehler präzisiert → `KNOWN_ISSUES.md` K3; Testgerüst neu → `TODO.md` I2 (Hinweis); `STATE.md`.

### Fixed
- `Show-TraceStructure.ps1`: Die Kopfzeile `(pid:adresse)` wird jetzt in beiden Formaten erkannt, die Firebird je nach
  Plattform schreibt (`printf("%p")`): Windows `000001A2B3C4D5E0`, Linux `0x7f3a1c2b4d10`. Vorher blieben bei
  Linux-Logs Ereignis, Zeitstempel und Adresse in **allen** Einträgen leer (Test war rot: 6 von 6 ohne `Action`).

### Added
- Pester-Grundgerüst: `tests/Show-TraceStructure.Tests.ps1` (11 Tests: Kopfzeile, Verbindung, Transaktion inkl. INIT,
  SQL/Plan/Parameter, Laufzeit/I/O, Tabellenstatistik, Linux-Kopfzeile, CRLF, fehlende Datei),
  `tests/fixtures/trace_fb5_windows.log` (synthetisch, Format nach Firebird-5.0.4-Quellcode, Werte ausgedacht,
  IPs aus 192.0.2.0/24), `tests/RequiredModules.psd1` (Pester 5.7.1, PSScriptAnalyzer 1.25.0).

### Confidence / Ungeprüft
- Windows-Format mit einem echten Firebird-5.0.4-Log belegt (298 Kopfzeilen, alle 16 Hex-Großbuchstaben ohne `0x`;
  nur Zählwerte ausgewertet, keine Inhalte). Das Linux-Format stammt aus dem Verhalten von glibc `%p`, nicht aus
  einem echten Linux-Log.
- Mutationsprüfung: 6 absichtliche Fehler im Parser, alle von mindestens einem Test erkannt.
- Echtes Log zusätzlich: alle 298 Einträge mit Ereignis, 10 Statements mit SQL/Laufzeit/Statistik; 12 Verbindungszeilen
  mit `<internal>` bleiben leer (K3).

## 2026-11-07 Roadmap – Inkremente aus dem Funktionsvergleich

Kein Inkrement (KICKOFF Phase 1 Punkt 2a). Vergleich mit dem Open-Source-Projekt firebird-trace-analyzer (C#, nicht-kommerzielle Lizenz; nur Ideen übernommen).

### Changed
- `TODO.md`: neu I9 (Kopfzeile plattformneutral, hoch), I10 (Fehler-Ereignisse mit Codes, hoch), I11–I13 (Transaktionsoptionen/RecordsFetched/Tabellenstatistik, Verbindungen/Prozeduren/Trigger, Robustheit; mittel), I14 (CI, aus `BACKLOG.md`); Hinweis in I4 auf den Firebird-5-Entwurf der Trace-Skripte.
- `STATE.md` „Offene Punkte“: I8 nachgetragen (fehlte), I9–I14 ergänzt.
- `BACKLOG.md`: Idee SQL-Normalisierung; SSH-Abruf verworfen.

### Confidence / Ungeprüft
- Plattformformat der Kopfzeile (I9) ist eine Vermutung aus dem Vergleich der beiden Parser; noch nicht mit Logs belegt.

## 2026-10-11 I1 – docs_template-Baseline eingeführt

Initialisiert mit docs_template v27@5ce0f84, Stack `powershell-automation`, keine Overlays. Bestandsrepo, kein Code geändert.
Commits: `chore: enforce LF line endings (.gitattributes + normalize)` (von `rollout_eol.sh`), `chore: extend .gitignore
for docs baseline`, `docs: initialize project documentation baseline (I1)`.

### Added
- `docs/` nach Template (base + Stack `powershell-automation`), projektspezifisch befüllt; Feature-Docs
  `features/TRACE_PARSING.md`, `features/PSEUDONYMIZATION.md`, `features/TRACE_CAPTURE.md`
- `AGENTS.md` und `CLAUDE.md` als Einstiegszeiger auf `docs/KICKOFF.md`
- `tools/git-hooks/pre-commit` und `commit-msg` (Interna-Sperre für das öffentliche Repo)
- `.gitattributes` (`* text=auto eol=lf`); Arbeitsbaum auf LF normalisiert (Index war bereits LF)

### Changed
- `.gitignore`: `/config.ps1`, `*.tmp`, `*.secret`, `*.dpapi`, `*.pfx`, `*.pem`, `*.key`, `/*.csv`, `/docs/local/`,
  `/.internal-terms`; Ausnahme `!/config.sample.json` (wurde von `config*.json` erfasst, ist aber versioniert)

### Removed
- Bedingte Template-Dateien ohne zutreffende Bedingung nicht übernommen: `architecture/DOMAIN_MODEL.md`,
  `architecture/REMOTE_EXECUTION.md`, `operations/TASK_SCHEDULER.md`, `testing/INTEGRATION_TESTS.md`

### Security
- Security-Currency-Abgleich beim Init (Base + Stack + Firebird-Werkzeuge), datiert in `security/DEPENDENCY_AUDIT.md`
- Sechs Bedrohungen aus dem Code in `security/THREAT_MODEL.md`; Inkrementplan I2–I7 in `TODO.md` (I2–I4 sicherheitsrelevant)
- Befund: Interna in der öffentlichen Git-History (gelöschte Kommentar-Beispiele) — Details nur in `docs/local/`, Owner-Aufgabe in `TODO.md`

### Confidence / Ungeprüft
- (a) Nicht getestet: Trace-Skripte (kein Firebird-Server im Init), Parser gegen eine echte oder synthetische Trace-Datei,
  Verhalten unter Windows PowerShell 5.1. Geprüft: Pseudonymisierer mit einem fiktiven Objekt (PowerShell 7.6);
  PSScriptAnalyzer 1.25.0 über alle Skripte (Befunde: Write-Host, BOM, automatische Variable, zwei vermutlich falsche
  `PSReviewUnusedParameter`-Treffer).
- (b) Ungeprüfte Annahmen: Format der `paramN`-Zeilen (Werte immer in doppelten Anführungszeichen?); Umleitung `>` unter
  Windows PowerShell 5.1 erzeugt UTF-16; Verhalten der `[int]`-Casts bei Werten > Int32; CVE-Nummern und Fix-Versionen aus
  Suchmaschinen-Snapshots (CVE-2026-28212 in Quellen uneinheitlich); Paketversionen Pester/PSScriptAnalyzer laut Gallery-Snapshot;
  EDPB-Leitlinie 01/2025 nur über Sekundärquellen zur Konsultationsfassung geprüft; `fbtracemgr`-Optionen nur aus der
  Linux-Manpage (Firebird 4.0), nicht am Windows-Binary.
- (c) Unverändert übernommene, nicht vollständig gelesene Template-Dateien: `principles/*` (außer `SECURITY_CURRENCY.md`,
  `INDEX.md`, `LOGGING.md`), `security/THREAT_MODEL_GUIDE.md`, `REFLECTION.md` (nur Abschnitte 3–5 gelesen),
  `architecture/ADR/ADR-000-template.md`, `features/FEATURE-template.md`.
- Struktur-Check mit `validate_project_docs.sh --stack powershell-automation` (Template-Skript).
- Advocatus-Diaboli-Hook (`KICKOFF.md` Phase 1 Punkt 7) **nicht** eingerichtet: `.claude/settings.json` ist
  Agenten-Konfiguration und wurde in diesem autonomen Lauf nicht ohne Freigabe angelegt — offen.

### Lessons Learned
- History-Scan beim Init eines bereits öffentlichen Repos — Scope: generisch-base
  Backport-Ziel: `NEUES_PROJECT_INITIALISIEREN.md` Schritt 1 | Status: offen
  Die Push-Regel aus `CONVENTIONS_COMMON.md` 3.1 greift bei bereits veröffentlichten Repos zu spät; Interna lagen nur in gelöschten Zeilen alter Commits.
  → Spiegel-Eintrag `## L1:` in `LESSONS_LEARNED.md`.
- Datenschutz-Versprechen per Probeaufruf belegen — Scope: projekt-spezifisch
  Backport-Ziel: keiner | Status: projekt-intern
  → Spiegel-Eintrag `## L2:` in `LESSONS_LEARNED.md`.
