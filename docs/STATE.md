# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-11-07
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update) → v37@b5021d9 (2026-11-07, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I2 – Pseudonymisierung: Klartext-Lücken (2026-11-07)
**Nächster Schritt:** I3 – HMAC mit Kundenschlüssel
**Nächste Reflexion:** bei Abschluss von I3 (siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md` — `docs/`-Drift prüfen + Template-Backport prüfen; danach Marker um 3 erhöhen)
**Nächster Security-Sweep:** 2026-11-21 (Intervall 14 Tage; letzter Sweep 2026-11-07, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I6 ist umgesetzt (Streaming). Als Nächstes I11–I14 (mittlere Priorität). Offen hoch: I2/I3 (Pseudonymisierung, HMAC mit Kundenschlüssel) — Voraussetzung für einen Dienst mit pseudonymisierten Daten. Empfohlenes Modell: Sonnet, mittlerer Effort; für I3 höherer Effort.

---

## Abgeschlossene Inkremente

| # | Titel | Datum | Commit |
|---|-------|-------|--------|
| I1 | docs_template-Baseline eingeführt (Bestandscode dokumentiert, kein Code geändert) | 2026-10-11 | 21e92bc |
| I9 | Kopfzeile plattformneutral (Windows/Linux-Adressformat), Pester-Grundgerüst, 11 Parser-Tests | 2026-11-07 | ae01289 |
| I10 | Fehler-Ereignisse: `ERROR AT`/`WARNING AT` mit Komponente, Codes, Texten; `FAILED …` vollständig; Pseudonymisierung der Fehlertexte | 2026-11-07 | 442d834 |
| I7 | MIT-Lizenzdatei, README-Properties an den Code angeglichen (K1) | 2026-11-07 | f3e476a |
| I6 | Streaming in 4-MB-Stücken, Ausgabe je Ereignis, Zähler als `[long]`, Vorprüfung je Regex, Statusmeldungen über `-Verbose` | 2026-11-07 | ae83580 |
| I2 | Pseudonymisierung: Datenbankpfad, Zahlen und Einzelzeichen im SQL, alle WHERE-Klauseln, `-AnalyzeOnly`-Ausgabe, K6; Feldabdeckung als Vertrag | 2026-11-07 | 02ba8c7 |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
| I3 | Pseudonymisierung: geheimer Schlüssel (HMAC) statt ungesalzenem SHA-256 | Hoch |
| I4 | Trace-Credentials: kein Passwort in Kommandozeile/Klartext-Konfiguration, kein SYSDBA | Hoch |
| I5 | Trace-Skripte robust machen (Ausgabepfad, Session-ID, Fehlerbehandlung, Encoding) | Mittel |
| I8 | Laufzeit- und Beispielstände aus dem Security-Sweep nachziehen | Niedrig |
| I11 | Parser: Transaktionsoptionen, RecordsFetched, Tabellenstatistik als Zahlen | Mittel |
| I12 | Parser: Verbindungen, Prozeduren und Trigger als Ereignisse | Mittel |
| I13 | Parser: Robustheit und Diagnose | Mittel |
| I14 | CI mit PSScriptAnalyzer und Pester | Mittel |

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
