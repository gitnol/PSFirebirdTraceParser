# Archiv – Abgeschlossene Inkremente aus STATE.md

Rotiert aus `docs/STATE.md` (`REFLECTION.md` Schritt 5a). Neue Zeilen nur unten anhängen, bestehende nie ändern.

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
