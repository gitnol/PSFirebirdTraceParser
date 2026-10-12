# Backlog – PSFirebirdTraceParser

Parkplatz für Ideen, Verbesserungen und Aufgaben, die noch **nicht** für ein
konkretes Inkrement priorisiert sind.

**Abgrenzung:**

- `TODO.md` = aktuelle, priorisierte Arbeit mit Definition of Done
- `BACKLOG.md` = noch nicht eingeplant, kein DoD nötig
- `KNOWN_ISSUES.md` = bekannte Probleme mit Workaround, nicht aktiv geplant

Wenn ein Backlog-Punkt für ein Inkrement vorgesehen wird → Verschiebung von
`BACKLOG.md` nach `TODO.md` (mit DoD ergänzen).

---

## Ideen / Features

- CI (z. B. GitHub Actions) mit PSScriptAnalyzer und Pester unter Windows PowerShell 5.1 und PowerShell 7 — sinnvoll, sobald I2 Tests liefert
- Pseudonymisierte Ausgabe im Trace-Rohformat (nicht nur Objekte/CSV) — für Analysedienste, die Original-Trace-Dateien erwarten; frühere Hilfsskripte dafür wurden entfernt
- `Timestamp` als `[datetime]` (zusätzliche Property, um den Vertrag nicht zu brechen)
- Trace-Konfiguration mit Datenbankfilter als zweite Vorlage (Datenminimierung, `security/DATA_HANDLING.md` §2)
- Veröffentlichung als Modul in der PowerShell Gallery (dann Manifest mit expliziten `FunctionsToExport`)

---

## Refactoring-Kandidaten

- Konfig-Laden ist in `trace_start.ps1` und `trace_stop.ps1` dupliziert — bei der nächsten Änderung an beiden in eine gemeinsame Funktion/Modul ziehen (I4/I5)
- Skriptnamen `trace_start.ps1`/`trace_stop.ps1` auf genehmigte Verben umstellen (`Start-FirebirdTrace.ps1`/`Stop-FirebirdTrace.ps1`) — bricht Nutzer-Gewohnheiten, nur mit README-Hinweis
- `#Requires -Version 5.1` in allen Skripten

---

## Technische Schuld

- Keine Tests und keine Linter-Konfiguration — jede Änderung am Parser/Pseudonymisierer ist ungesichert (wird mit I2 begonnen)
- README beschreibt teils veraltetes Verhalten (K1) — Nutzer bauen Auswertungen auf falsche Property-Namen

---

## Template-Evolution / Stack-Lücken

Hier landen Projekt-Charakteristiken, für die kein passender Stack/Overlay
existierte. Jeder Eintrag ist eine potenzielle Template-Erweiterung — so sind
z.B. `react-web` und die document-intelligence-Overlays entstanden.

- Stack-Lücke: interaktives PowerShell-Pipeline-Werkzeug (Skripte ohne Modul, ohne Task Scheduler, ohne REST, Ausgabe als Objekte in die Pipeline). `powershell-automation` ist auf geplante Automation (Task Scheduler, Dienstkonto, Event-Log) und Modul/REST-Clients zugeschnitten; `CONVENTIONS.md`, `operations/SETUP.md`, `RUNBOOK.md`, `MONITORING.md` und `security/AUTHENTICATION.md` mussten beim Init weitgehend umgeschrieben werden. Fehlend: Regeln für Pipeline-Skripte (Output-Stream-Disziplin, `begin/process/end`, Objekt-Verträge) und für Datei-Parser großer Eingaben (Streaming). — 2026-10-11 PSFirebirdTraceParser

---

## Verworfen (mit Begründung)

Punkte, die geprüft und bewusst nicht weiterverfolgt wurden. Bleiben als Spur
sichtbar, damit derselbe Punkt nicht in jeder Session erneut diskutiert wird.

- (noch keine Einträge)
