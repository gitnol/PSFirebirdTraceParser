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

## Hohe Priorität

Herkunft I16–I20: Entscheidung Owner 2026-11-08 — den Parser in C# neu bauen, parallel zum PowerShell-Parser, bis C#
ihn ohne Änderung für Nutzer ersetzen kann; danach steuert PowerShell nur noch den C#-Code. Beide Parser müssen sich
bis dahin immer gleich verhalten; der Paritätstest (ab I17) ist die Ratsche dafür. Qualitätsregeln unverändert.
Split wegen der Größengrenze (KICKOFF Phase 2 Punkt 5): je Inkrement höchstens eine neue Entscheidung, ~400 Zeilen.
Gebündelt wird nichts: I8 liest andere Quellen (Security-Sweep), der Refactoring-Kandidat `Show-TraceStructure.ps1`
(`BACKLOG.md`) wird durch I20 vielleicht überflüssig — deshalb **getrennt gelassen** und erst nach I20 entschieden.

### I19: `Show-TraceStructure.ps1 -Engine Auto|PowerShell|CSharp`, Standard Auto

**Aufgaben:**

- [ ] `-Engine`: `Auto` nimmt C#, wenn PowerShell 7 läuft und die gebaute DLL neben dem Skript oder unter `bin/`
  liegt, sonst PowerShell (Windows PowerShell 5.1 immer PowerShell);
  `-Verbose` nennt die gewählte Engine; gleiche Parameter, Warnungen und Verbose-Meldungen in beiden
- [ ] Paritätstest über das Skript mit beiden Engines; Pseudonymisierer mit C#-Ausgabe (Test)
- [ ] README en/de, `features/TRACE_PARSING.md`, `architecture/CONFIGURATION.md`
- [ ] Messung auf kleinem Ausschnitt (synthetisch ~10–20 MB oder Ausschnitt eines echten Logs; nur Zahlen und
  Zeiten, kein Inhalt, Ausgaben nur unter `C:\Temp`)

### I20: Umstellung abschließen — PowerShell-Parsing als Referenz/Fallback behalten oder entfernen

**Aufgaben:**

- [ ] Entscheidung mit Belegen (ADR-003 nachtragen): Bleibt der PowerShell-Parser als Fallback für Nutzer ohne Build
  und als Orakel des Paritätstests, oder wird er entfernt und das Skript ruft nur noch das Cmdlet?
- [ ] Voraussetzung: I19 abgeschlossen und mindestens ein grüner CI-Lauf beider Jobs mit Build und Paritätstest

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
