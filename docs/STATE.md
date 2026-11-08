# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-11-08
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update) → v37@b5021d9 (2026-11-07, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I12 – Parser: Prozeduren, Funktionen und Trigger als Ereignisse, Verbindungsdauer (2026-11-08)
**Nächster Schritt:** I13 – Parser: Robustheit und Diagnose
**Nächste Reflexion:** beim dritten abgeschlossenen Inkrement nach I5 (voraussichtlich I13, Reihenfolge `TODO.md`: I11 und I12 erledigt, dann I13; siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md`)
**Nächster Security-Sweep:** 2026-11-21 (Intervall 14 Tage; letzter Sweep 2026-11-07, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I12 umgesetzt: Prozeduren, Funktionen und Trigger mit Namen (Trigger: Tabelle, Zeitpunkt, Aktion; Firebird 4 und 5) und `ConnectionDurationMs` bei `DETACH_DATABASE`. Damit echte Daten kommen, muss im Trace `log_procedure_finish`/`log_trigger_finish` eingeschaltet werden (in `fbtrace50.conf` auskommentiert, Entscheidung Owner). Als Nächstes I13 mit Reflexion; I8 (Rest) zusammen mit dem Security-Sweep am 2026-11-21. Vorher sinnvoll: einmal `trace_start.ps1`/`trace_stop.ps1` gegen den Testserver laufen lassen und den ersten CI-Lauf nach dem Push ansehen. Empfohlenes Modell: Sonnet, mittlerer Effort.

---

## Abgeschlossene Inkremente

| # | Titel | Datum | Commit |
|---|-------|-------|--------|
| I12 | Parser: Prozeduren, Funktionen und Trigger als Ereignisse (`RoutineType`, `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent`; Trigger-Zeile Firebird 4 und 5), `ConnectionDurationMs`; 16 Tests | 2026-11-08 | 263b43d |
| I11 | Parser: `RecordsFetched`, Transaktionsoptionen als fünf Felder (`Tx…`), Tabellenstatistik als `TableCounts` je Tabelle (Spalten relativ zum Kopf, Umlaute, überlange Namen); Pseudonymisierer kopiert `TableCounts`; 21 Tests | 2026-11-08 | 6450b79 |
| I15 | Sweep-Ereignisse (Transaktionszähler OIT/OAT/OST/Next) und Service-Ereignisse (Dienstname, Kennung, Verbindung) lesen; synthetisches Fixture nach Firebird-5-Quellcode; 13 Tests | 2026-11-08 | bb82165 |
| I14 | CI (GitHub Actions) mit PSScriptAnalyzer und Pester unter PowerShell 7 und Windows PowerShell 5.1; Settings-Datei, Gate-Skript, 21 Analyzer-Befunde beseitigt | 2026-11-08 | c26fb8b |
| I4 | Trace-Anmeldung ohne Klartext-Passwort (`-FETCH_PASSWORD`/`-TRUSTED`, `-ROLE`, ADR-002), Vorlage ohne Passwort/SYSDBA; gebündelt mit I5 | 2026-11-08 | d9a2a8b |
| I5 | Trace-Skripte robust: Konfigurationsprüfung, Sitzung per Name und Zustandsdatei, Exit-Codes 0–6, PowerShell 7.4+, `fbtrace50.conf`, 32 Tests mit gemocktem `fbtracemgr`; gebündelt mit I4 | 2026-11-08 | d9a2a8b |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
| I8 | Laufzeit- und Beispielstände aus dem Security-Sweep nachziehen | Niedrig |
| I13 | Parser: Robustheit und Diagnose | Mittel |

---

## Risiken & Blocker

Eintragen, **sobald** ein Punkt erkannt ist — nicht erst, wenn er eskaliert.
Wenn keine Risiken bekannt: Zeile „(noch keine Einträge)" einsetzen, Tabelle nicht leer lassen (`CONVENTIONS_COMMON.md` §3).

| Risiko / Blocker | Auswirkung | Mitigation / Nächster Schritt | Owner | Status |
|---|---|---|---|---|
| Pseudonymisierte Exporte enthalten Klartext-Reste | Weitergabe personenbezogener Daten an Dritte trotz „Pseudonymisierung" | I2 (Klartext-Lücken) und I3 (HMAC mit Schlüssel) umgesetzt. Rest: Fehlertexte nur teilweise gehasht (`features/PSEUDONYMIZATION.md`); Exporte weiter vor Weitergabe mit `-AnalyzeOnly` prüfen, nur mit Freigabe teilen (`docs/security/DATA_HANDLING.md`) | Maintainer | gemindert |
| Trace-Anmeldung mit SYSDBA über eine Klartext-Passwortdatei | Wer die Datei lesen kann, hat vollen DB-Zugriff | Seit I4 kein Passwort mehr in Befehlszeile oder `config.json` (ADR-002). Rest: Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` einrichten und testen, Passwortdatei nach Gebrauch löschen, früher per `-PASS` genutztes Passwort rotieren | Owner / DB-Administration | gemindert |
| Ältere Commits der öffentlichen Git-History enthalten echte interne Verbindungsdaten in Kommentar-Beispielen | Informationsabfluss über das öffentliche Repository | Neue Commits schützt seit 2026-11-08 der aktive Interna-Hook (`.internal-terms` vorhanden); synthetische Fixtures sind seit `aebd937` versioniert. **Entscheidung Owner 2026-11-08: History nicht bereinigen.** Geprüft: zwei interne Begriffe in je zwei Commits, kein echtes Passwort (nur Platzhalter und das Firebird-Standardbeispiel `masterkey`). Ein Force-Push würde bestehende Klone brechen, GitHub-Caches und Forks behielten die alten Stände trotzdem. Stattdessen SYSDBA-Passwort ändern; neue Commits schützt der Interna-Hook. Details nur in `docs/local/ENVIRONMENT.md` | Repo-Owner | akzeptiert (2026-11-08) |
| CI noch nie auf GitHub gelaufen | Workflow-Fehler (Modulinstallation, Runner-Image) fallen erst beim ersten Lauf auf | Seit I14 Workflow mit PSScriptAnalyzer und Pester (67 Tests, PS 7 und 5.1); lokal mit denselben Befehlen grün. Nach dem nächsten Push den ersten Lauf ansehen | Maintainer | gemindert |
