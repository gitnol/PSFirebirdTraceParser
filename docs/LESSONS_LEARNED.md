# Lessons Learned – PSFirebirdTraceParser

Strukturierter Index für gelernte Patterns. Jeder Eintrag benennt Scope und
Backport-Ziel, damit die Reflexions-Phase (REFLECTION.md Schritt 3) offene
generische Patterns als Backport-Vorschlag melden kann; eingespielt wird erst nach Freigabe
des Prompters (REFLECTION.md Schritt 3, Freigabe-Disziplin).

Neue Einträge entstehen aus dem „Lessons Learned"-Abschnitt der `CHANGELOG.md` —
dort kurze Beschreibung, hier der strukturierte Steckbrief.

---

## L1: History-Scan beim Init eines bereits öffentlichen Repos
- Inkrement: I1
- Scope: generisch-base
- Backport-Ziel: `NEUES_PROJECT_INITIALISIEREN.md` Schritt 1 („Öffentliches Repository?") bzw. `base/CONVENTIONS_COMMON.md` 3.1
- Status: offen

Die Regel „vor dem ersten Push die Branch-History prüfen" greift nicht, wenn das Repository schon öffentlich ist; beim
Init fanden sich Interna nur in **gelöschten** Kommentar-Beispielen älterer Commits, nicht im aktuellen Stand. Ein
History-Scan (`git log -p --all` gegen die Denylist) gehört deshalb in den Init, der Befund nach `docs/local/` und die
Bereinigung als Owner-Entscheidung in `TODO.md`.

---

## L2: Datenschutz-Versprechen per Probeaufruf belegen
- Inkrement: I1
- Scope: projekt-spezifisch
- Backport-Ziel: keiner
- Status: projekt-intern

Aussagen über die Feldabdeckung des Pseudonymisierers wurden nicht nur aus dem Code gelesen, sondern mit einem
fiktiven Objekt nachgeprüft; dabei zeigte sich eine im Code leicht zu übersehende Bedingung (Bulk-Redaktion nur,
wenn das Schlüsselwort nach der Literal-Ersetzung noch vorkommt). Künftige Änderungen belegen die Abdeckung per Pester-Test.

---

## Pflege

- Neuer „Lessons Learned"-Block im `CHANGELOG.md` → Eintrag `## L<N>:` hier anlegen.
- Mehrere Patterns aus einem Inkrement → mehrere `## L<N>:`-Einträge.
- Scope-Werte:
  - `projekt-spezifisch` — nur für dieses Projekt relevant, kein Backport nötig.
  - `generisch-stack` — gehört in `docs_template/stacks/<stack>/CONVENTIONS.md` o.ä.
  - `generisch-base` — gehört in `docs_template/base/` (Prinzip, Basis-Convention, MANIFEST).
- Status `offen` → wird bei der nächsten Reflexion (REFLECTION.md Schritt 3) als Backport-Vorschlag gemeldet;
  bleibt `offen` bis zur Freigabe.
- Status `backported vN@<commit>` → Backport-Commit ins Template-Repo durchgeführt (Template-Stand
  Version + Commit, z. B. `v26@0a4c8f1`); der Tag `vN` folgt erst nach dem Pre-Tag-Gate (REFLECTION.md Schritt 3b).
- Status `projekt-intern` → Endzustand für `Scope: projekt-spezifisch` (kein Backport vorgesehen; die Lesson gilt
  im Projekt weiter). Wird in der Reflexion nicht als Backport-Kandidat gemeldet.
- Niemals Patterns löschen, auch wenn überholt — `Status: verworfen (<grund>)` setzen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
