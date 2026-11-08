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
Zusammen mit dem nächsten Kadenz-Sweep (2026-11-21) erledigen: beide lesen dieselben Quellen (Reflexion I5). Der
erste Punkt (Vorlage versionsneutral) ist mit I4/I5 erledigt.

**Aufgaben:**

- [ ] Prüfen und entscheiden (YAGNI): Trace-Skripte warnen unter PowerShell 7 bei einer Version unter 7.6.7 / 7.5.12 / 7.4.21 oder auf 7.4/7.5 nach dem Supportende 2026-11-10 — sonst als bewusst dokumentiertes Restrisiko in `security/DEPENDENCY_AUDIT.md`
- [ ] MSRC Security Update Guide (Oktober 2026) auf Windows PowerShell 5.1 filtern und den Befund im Sweep-Protokoll nachtragen

**Zusätzliche Kriterien:**

- [ ] Kein Interna-Treffer im Diff (öffentliches Repo, `CONVENTIONS_COMMON.md` 3.1)
