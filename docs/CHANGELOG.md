# Changelog – PSFirebirdTraceParser

Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/).
Einträge chronologisch absteigend (neueste oben). Jeder Eintrag entspricht
genau einem Inkrement (= einem Commit oder einer eng zusammengehörigen
Commit-Serie). Roadmap-Änderungen (KICKOFF Phase 1 Punkt 2a), Reflexions-Refreshs und
Post-Mortems erhalten einen kurzen Eintrag ohne I#.

Nicht alle Sektionen sind in jedem Eintrag nötig — leere Sektionen weglassen.

---

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
