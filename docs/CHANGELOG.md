# Changelog – PSFirebirdTraceParser

Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/).
Einträge chronologisch absteigend (neueste oben). Jeder Eintrag entspricht
genau einem Inkrement (= einem Commit oder einer eng zusammengehörigen
Commit-Serie). Roadmap-Änderungen (KICKOFF Phase 1 Punkt 2a), Reflexions-Refreshs und
Post-Mortems erhalten einen kurzen Eintrag ohne I#.

Nicht alle Sektionen sind in jedem Eintrag nötig — leere Sektionen weglassen.

---

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
