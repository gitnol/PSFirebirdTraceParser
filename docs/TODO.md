# TODO – PSFirebirdTraceParser

Einzige Quelle des Inkrementplans (KICKOFF verweist nur hierher). Pro Inkrement: Aufgaben und — falls über die
Standard-DoD hinaus nötig — zusätzliche Kriterien. Ein Inkrement gilt erst als erledigt, wenn die Standard-DoD
**und** seine eigenen Kriterien erfüllt sind.

Parkplatz für noch unspezifizierte Ideen: `BACKLOG.md`.
Bekannte Bugs ohne aktiven Fix: `KNOWN_ISSUES.md`.

---

## Standard-Definition of Done (gilt für jedes Inkrement — nicht abhaken, sie bleibt stehen)

- Code-Änderungen abgeschlossen, kein TODO-/FIXME-Kommentar offen
- Quality Gates grün (`CONVENTIONS_COMMON.md` §5; Befehle in `CONVENTIONS.md`)
- Integration-Tests grün, falls relevant
- Security-Checkliste aus `CONVENTIONS.md` durchgegangen (falls der Stack eine liefert)
- Trigger-Matrix in `KICKOFF.md` Phase 3a geprüft → alle relevanten Docs aktualisiert
  (`architecture/OVERVIEW.md`, `features/`, `architecture/`, `security/`, `GLOSSARY.md`, `KNOWN_ISSUES.md`, `LESSONS_LEARNED.md`)
- `STATE.md`: Tabellenzeile + „Nächster Schritt"-Abschnitt aktualisiert
- `CHANGELOG.md`: neuer Abschnitt mit Datum + Inkrement-Titel + Sections
  (Added / Changed / Fixed / Removed / Security / Confidence / Ungeprüft / Lessons Learned)
- KICKOFF Phase 3b vollständig (Struktur-Check, TODO-Verschiebung, Advocatus-Diaboli-Gate)
- Commit erstellt (`<type>(<scope>): <desc>`); Commit-Hash in `STATE.md` eingetragen

---

## Mittlere Priorität

### I11: Parser – Transaktionsoptionen, RecordsFetched, Tabellenstatistik als Zahlen

Herkunft: Funktionsvergleich mit dem Open-Source-Projekt firebird-trace-analyzer (2026-11-07); nur Ideen, kein Code (dessen Lizenz ist nicht kommerziell).

**Aufgaben:**

- [ ] Transaktionsoptionen in Felder zerlegen: Isolation (`READ_COMMITTED`, `CONCURRENCY`, `CONSISTENCY`), Lesemodus
      (`READ_CONSISTENCY`, `REC_VERSION`, `NO_REC_VERSION`), Sperrmodus inkl. `LOCK_TIMEOUT`-Wert, Zugriff
      (`READ_WRITE`/`READ_ONLY`); `TransactionOptions` als Text bleibt (Vertrag)
- [ ] Neues Feld `RecordsFetched` aus `N records fetched` (getrennt von den Seiten-Fetches `Fetches`)
- [ ] Tabellenstatistik zusätzlich als Liste von Objekten je Tabelle (Natural, Index, Update, Insert, Delete, Backout,
      Purge, Expunge) über die Spaltenpositionen der Kopfzeile; `TableStats` als Text bleibt

### I12: Parser – Verbindungen, Prozeduren und Trigger als Ereignisse

Herkunft: Funktionsvergleich mit dem Open-Source-Projekt firebird-trace-analyzer (2026-11-07); nur Ideen, kein Code (dessen Lizenz ist nicht kommerziell).

**Aufgaben:**

- [ ] `ATTACH_DATABASE`/`DETACH_DATABASE` mit Verbindungsdaten ausgeben; Verbindungsdauer (Attach→Detach) berechnen
- [ ] `EXECUTE_PROCEDURE_FINISH` und `EXECUTE_TRIGGER_FINISH` mit Namen (Trigger: Tabelle, Zeitpunkt, Aktion), Laufzeit, I/O
- [ ] Format der Trigger-Zeile unterscheidet sich zwischen Firebird 4 (`\t%s (%s) `) und 5 (`%s (%s):`) — beide testen
- [ ] Ausgabe so gestalten, dass bestehende Auswertungen (nur Statements) unverändert funktionieren (z. B. über `Action` filterbar)

### I13: Parser – Robustheit und Diagnose

Herkunft: Funktionsvergleich mit dem Open-Source-Projekt firebird-trace-analyzer (2026-11-07); nur Ideen, kein Code (dessen Lizenz ist nicht kommerziell).

**Aufgaben:**

- [ ] Warnungen mit Zeilennummer für Blöcke, die nicht zugeordnet werden können
- [ ] Zusammenfassung am Ende: Anzahl Blöcke je `Action`, übersprungene/unbekannte Blöcke
- [ ] Zeitlimit für Regex-Auswertung (Schutz vor sehr langen Blöcken), Obergrenze Zeilen je Block

---

## Niedrige Priorität

### I8: Laufzeit- und Beispielstände aus dem Security-Sweep 2026-10-23 nachziehen

Herkunft: `security/DEPENDENCY_AUDIT.md` → Kadenz-Sweep 2026-10-23.

**Aufgaben:**

- [ ] Prüfen und entscheiden (YAGNI): Trace-Skripte warnen unter PowerShell 7 bei einer Version unter 7.6.7 / 7.5.12 / 7.4.21 oder auf 7.4/7.5 nach dem Supportende 2026-11-10 — sonst als bewusst dokumentiertes Restrisiko in `security/DEPENDENCY_AUDIT.md`
- [ ] MSRC Security Update Guide (Oktober 2026) auf Windows PowerShell 5.1 filtern und den Befund im Sweep-Protokoll nachtragen

**Zusätzliche Kriterien:**

- [ ] Kein Interna-Treffer im Diff (öffentliches Repo, `CONVENTIONS_COMMON.md` 3.1)

### Ohne Inkrement-Nummer (Owner-Aufgaben)

- [ ] Branch-History nach `CONVENTIONS_COMMON.md` 3.1 prüfen; Befund und Optionen in `docs/local/ENVIRONMENT.md` (Entscheidung Repo-Owner: History-Bereinigung oder dokumentierte Akzeptanz)
- [ ] Interna-Hook in jedem Klon aktivieren: `git config core.hooksPath tools/git-hooks` und `.internal-terms` anlegen
