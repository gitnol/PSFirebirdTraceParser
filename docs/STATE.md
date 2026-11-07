# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-11-08
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update) → v37@b5021d9 (2026-11-07, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I15 – Sweep- und Service-Ereignisse (2026-11-08)
**Nächster Schritt:** I4 – Trace-Credentials (Entwurf für Firebird 5 nach echtem Lauf übernehmen)
**Nächste Reflexion:** bei Abschluss von I11 (= drittes Inkrement nach I3 in der Reihenfolge von `TODO.md`; ändert sich die Reihenfolge, gilt das dritte abgeschlossene Inkrement nach I3; siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md`)
**Nächster Security-Sweep:** 2026-11-21 (Intervall 14 Tage; letzter Sweep 2026-11-07, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I15 umgesetzt (Sweep- und Service-Ereignisse, mit Zustimmung des Owners vom 2026-11-07). Als Nächstes I4/I5 (Trace-Skripte, Firebird-5-Entwurf nach echtem Lauf), danach I11–I14. Empfohlenes Modell: Sonnet, mittlerer Effort.

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
| I3 | HMAC-SHA256 mit Schlüsseldatei (ADR-001), Zufallsschlüssel je Lauf ohne Datei, optionale Zuordnungsdatei für den Verantwortlichen | 2026-11-07 | 06489c4 |
| I15 | Sweep-Ereignisse (Transaktionszähler OIT/OAT/OST/Next) und Service-Ereignisse (Dienstname, Kennung, Verbindung) lesen; synthetisches Fixture nach Firebird-5-Quellcode; 13 Tests | 2026-11-08 | bb82165 |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
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
| Pseudonymisierte Exporte enthalten Klartext-Reste | Weitergabe personenbezogener Daten an Dritte trotz „Pseudonymisierung" | I2 (Klartext-Lücken) und I3 (HMAC mit Schlüssel) umgesetzt. Rest: Fehlertexte nur teilweise gehasht (`features/PSEUDONYMIZATION.md`); Exporte weiter vor Weitergabe mit `-AnalyzeOnly` prüfen, nur mit Freigabe teilen (`docs/security/DATA_HANDLING.md`) | Maintainer | gemindert |
| `trace_start.ps1`/`trace_stop.ps1` übergeben das SYSDBA-Passwort als Kommandozeilenargument | Passwort für Administratoren/Monitoring in der Prozess-Kommandozeile sichtbar, ggf. in Prozess-Audit-Logs (Befehlszeilen-Protokollierung) | I4; bis dahin Skripte nur auf Hosts ohne Befehlszeilen-Protokollierung nutzen bzw. Passwort nach Nutzung rotieren | Maintainer | offen |
| Ältere Commits der öffentlichen Git-History enthalten echte interne Verbindungsdaten in Kommentar-Beispielen | Informationsabfluss über das öffentliche Repository | Owner-Entscheidung zu History-Bereinigung (Force-Push) oder Akzeptanz; Details nur in `docs/local/ENVIRONMENT.md` | Repo-Owner | offen |
| Tests laufen nur lokal, kein Linter-Gate in CI | Regressionen fallen erst auf, wenn jemand die Tests von Hand startet | Pester-Tests seit I9 (54 Tests, Stand 2026-11-08), Versionen gepinnt; CI mit PSScriptAnalyzer und Pester: I14 | Maintainer | gemindert |
