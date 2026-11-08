# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-11-08
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update) → v37@b5021d9 (2026-11-07, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I4 + I5 – Trace-Skripte für Firebird 5 ohne Klartext-Passwort (2026-11-08)
**Nächster Schritt:** I11 – Parser: Transaktionsoptionen, RecordsFetched, Tabellenstatistik als Zahlen
**Nächste Reflexion:** beim dritten abgeschlossenen Inkrement nach I5 (voraussichtlich I13, Reihenfolge `TODO.md`: I11, I12, I13; siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md`)
**Nächster Security-Sweep:** 2026-11-21 (Intervall 14 Tage; letzter Sweep 2026-11-07, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I4 und I5 gemeinsam umgesetzt (Entwurf des Owners für Firebird 5.0.4 übernommen, ADR-002); Reflexion nach I5 durchgeführt. Als Nächstes I11–I13; I8 (Rest) zusammen mit dem Security-Sweep am 2026-11-21. Vorher sinnvoll: einmal `trace_start.ps1`/`trace_stop.ps1` gegen den Testserver laufen lassen und den ersten CI-Lauf nach dem Push ansehen. Empfohlenes Modell: Sonnet, mittlerer Effort.

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
| I14 | CI (GitHub Actions) mit PSScriptAnalyzer und Pester unter PowerShell 7 und Windows PowerShell 5.1; Settings-Datei, Gate-Skript, 21 Analyzer-Befunde beseitigt | 2026-11-08 | c26fb8b |
| I4 | Trace-Anmeldung ohne Klartext-Passwort (`-FETCH_PASSWORD`/`-TRUSTED`, `-ROLE`, ADR-002), Vorlage ohne Passwort/SYSDBA; gebündelt mit I5 | 2026-11-08 | d9a2a8b |
| I5 | Trace-Skripte robust: Konfigurationsprüfung, Sitzung per Name und Zustandsdatei, Exit-Codes 0–6, PowerShell 7.4+, `fbtrace50.conf`, 32 Tests mit gemocktem `fbtracemgr`; gebündelt mit I4 | 2026-11-08 | d9a2a8b |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
| I8 | Laufzeit- und Beispielstände aus dem Security-Sweep nachziehen | Niedrig |
| I11 | Parser: Transaktionsoptionen, RecordsFetched, Tabellenstatistik als Zahlen | Mittel |
| I12 | Parser: Verbindungen, Prozeduren und Trigger als Ereignisse | Mittel |
| I13 | Parser: Robustheit und Diagnose | Mittel |

---

## Risiken & Blocker

Eintragen, **sobald** ein Punkt erkannt ist — nicht erst, wenn er eskaliert.
Wenn keine Risiken bekannt: Zeile „(noch keine Einträge)" einsetzen, Tabelle nicht leer lassen (`CONVENTIONS_COMMON.md` §3).

| Risiko / Blocker | Auswirkung | Mitigation / Nächster Schritt | Owner | Status |
|---|---|---|---|---|
| Pseudonymisierte Exporte enthalten Klartext-Reste | Weitergabe personenbezogener Daten an Dritte trotz „Pseudonymisierung" | I2 (Klartext-Lücken) und I3 (HMAC mit Schlüssel) umgesetzt. Rest: Fehlertexte nur teilweise gehasht (`features/PSEUDONYMIZATION.md`); Exporte weiter vor Weitergabe mit `-AnalyzeOnly` prüfen, nur mit Freigabe teilen (`docs/security/DATA_HANDLING.md`) | Maintainer | gemindert |
| Trace-Anmeldung mit SYSDBA über eine Klartext-Passwortdatei | Wer die Datei lesen kann, hat vollen DB-Zugriff | Seit I4 kein Passwort mehr in Befehlszeile oder `config.json` (ADR-002). Rest: Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` einrichten und testen, Passwortdatei nach Gebrauch löschen, früher per `-PASS` genutztes Passwort rotieren | Owner / DB-Administration | gemindert |
| Ältere Commits der öffentlichen Git-History enthalten echte interne Verbindungsdaten in Kommentar-Beispielen | Informationsabfluss über das öffentliche Repository | Neue Commits schützt seit 2026-11-08 der aktive Interna-Hook (`.internal-terms` vorhanden); synthetische Fixtures sind seit `aebd937` versioniert. Offen bleibt die Owner-Entscheidung zur History-Bereinigung (Force-Push) oder Akzeptanz; Details nur in `docs/local/ENVIRONMENT.md` | Repo-Owner | offen |
| CI noch nie auf GitHub gelaufen | Workflow-Fehler (Modulinstallation, Runner-Image) fallen erst beim ersten Lauf auf | Seit I14 Workflow mit PSScriptAnalyzer und Pester (67 Tests, PS 7 und 5.1); lokal mit denselben Befehlen grün. Nach dem nächsten Push den ersten Lauf ansehen | Maintainer | gemindert |
