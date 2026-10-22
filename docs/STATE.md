# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-10-23
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I1 – docs_template-Baseline eingeführt (2026-10-11)
**Nächster Schritt:** I2 – Pseudonymisierung: Klartext-Lücken schließen (mit Pester-Grundgerüst)
**Nächste Reflexion:** bei Abschluss von I3 (siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md` — `docs/`-Drift prüfen + Template-Backport prüfen; danach Marker um 3 erhöhen)
**Nächster Security-Sweep:** 2026-11-06 (Intervall 14 Tage; letzter Sweep 2026-10-23, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I2 aus `docs/TODO.md`: Pester-Grundgerüst und PSScriptAnalyzer-Gate anlegen, den Ist-Stand von
`Pseudonymize-FirebirdTrace.ps1` per Charakterisierungstests festschreiben und danach die Klartext-Lücken
(numerische SQL-Literale, `DatabasePath`, nur letzte WHERE/HAVING-Klausel) mit behavioral roten Tests schließen.
Begründung der Reihenfolge: Das Werkzeug verspricht „sicheres Teilen" von Trace-Daten; Lücken dort führen zu
nicht rückholbarer Weitergabe personenbezogener Daten an Dritte (`docs/security/THREAT_MODEL.md` Bedrohung 1).

---

## Abgeschlossene Inkremente

| # | Titel | Datum | Commit |
|---|-------|-------|--------|
| I1 | docs_template-Baseline eingeführt (Bestandscode dokumentiert, kein Code geändert) | 2026-10-11 | 21e92bc |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
| I2 | Pseudonymisierung: Klartext-Lücken schließen (mit Pester-Grundgerüst) | Hoch |
| I3 | Pseudonymisierung: geheimer Schlüssel (HMAC) statt ungesalzenem SHA-256 | Hoch |
| I4 | Trace-Credentials: kein Passwort in Kommandozeile/Klartext-Konfiguration, kein SYSDBA | Hoch |
| I5 | Trace-Skripte robust machen (Ausgabepfad, Session-ID, Fehlerbehandlung, Encoding) | Mittel |
| I6 | Parser: Streaming statt Gesamtdatei im Speicher, Regex-Abdeckung | Mittel |
| I7 | README-Drift beheben, Lizenzdatei klären | Niedrig |

---

## Risiken & Blocker

Eintragen, **sobald** ein Punkt erkannt ist — nicht erst, wenn er eskaliert.
Wenn keine Risiken bekannt: Zeile „(noch keine Einträge)" einsetzen, Tabelle nicht leer lassen (`CONVENTIONS_COMMON.md` §3).

| Risiko / Blocker | Auswirkung | Mitigation / Nächster Schritt | Owner | Status |
|---|---|---|---|---|
| Pseudonymisierte Exporte enthalten weiterhin Klartext (Zahlen-Literale, Datenbankpfad) und umkehrbare Hashes (IP-Adressen) | Weitergabe personenbezogener Daten an Dritte trotz „Pseudonymisierung" | Bis I2/I3: Exporte vor Weitergabe manuell prüfen (`-AnalyzeOnly`), nur mit Freigabe teilen (`docs/security/DATA_HANDLING.md`) | Maintainer | offen |
| `trace_start.ps1`/`trace_stop.ps1` übergeben das SYSDBA-Passwort als Kommandozeilenargument | Passwort für Administratoren/Monitoring in der Prozess-Kommandozeile sichtbar, ggf. in Prozess-Audit-Logs (Befehlszeilen-Protokollierung) | I4; bis dahin Skripte nur auf Hosts ohne Befehlszeilen-Protokollierung nutzen bzw. Passwort nach Nutzung rotieren | Maintainer | offen |
| Ältere Commits der öffentlichen Git-History enthalten echte interne Verbindungsdaten in Kommentar-Beispielen | Informationsabfluss über das öffentliche Repository | Owner-Entscheidung zu History-Bereinigung (Force-Push) oder Akzeptanz; Details nur in `docs/local/ENVIRONMENT.md` | Repo-Owner | offen |
| Keine automatisierten Tests, kein Linter-Gate | Refactorings am Parser/Pseudonymisierer ohne Regressionsschutz | Pester + PSScriptAnalyzer in I2 einführen | Maintainer | offen |
