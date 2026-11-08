# Aktueller Projektstatus – PSFirebirdTraceParser

Zuletzt aktualisiert: 2026-11-08
**Initialisiert mit:** docs_template v27@5ce0f84 → v27@2268889 → v28@63b85ec (2026-10-22, Delta-Update) → v37@b5021d9 (2026-11-07, Delta-Update)
**Stack / Overlays:** powershell-automation / keine
**Letztes abgeschlossenes Inkrement:** I21 – K8 behoben (2026-11-08)
**Nächster Schritt:** I20 (Entscheidung Fallback oder Entfernen, nach grünem CI-Lauf); I8 (Rest) mit dem Security-Sweep am 2026-11-21
**Nächste Reflexion:** beim dritten abgeschlossenen Inkrement nach I18 (Reflexion I18 am 2026-11-08; siehe `KICKOFF.md` Phase 1c → `docs/REFLECTION.md`)
**Nächster Security-Sweep:** 2026-11-21 (Intervall 14 Tage; letzter Sweep 2026-11-07, `security/DEPENDENCY_AUDIT.md`; siehe `KICKOFF.md` Phase 1 Punkt 4a → `docs/principles/SECURITY_CURRENCY.md` — fällig, sobald heute ≥ diesem Datum; nach dem Sweep Marker = Sweep-Datum + Intervall)

---

## Nächster Schritt

I16–I19 umgesetzt: `Show-TraceStructure.ps1` nimmt unter PowerShell 7 mit gebauter DLL den C#-Parser (`-Engine Auto`), unter 5.1 den PowerShell-Parser; Paritätstests über das Skript. I21 (K8) behoben. Als Nächstes I20 (Entscheidung: PowerShell-Parser als Fallback behalten oder entfernen; Voraussetzung grüner CI-Lauf). Offen für den Owner: Push und ersten CI-Lauf ansehen, lokal .NET SDK 10 installieren, Verteilung der DLL (Release?) entscheiden; `log_procedure_finish`/`log_trigger_finish` weiter offen. I8 (Rest) mit dem Security-Sweep am 2026-11-21. Empfohlenes Modell: Sonnet, mittlerer Effort (I21), Opus für I20.

---

## Abgeschlossene Inkremente

| # | Titel | Datum | Commit |
|---|-------|-------|--------|
| I21 | K8: Zeilensuche in beiden Parsern ordinal (300 000 Zeilen: 42,7 s → 1,6 s); 1 Test | 2026-11-08 | ed913e9 |
| I19 | `Show-TraceStructure.ps1 -Engine Auto\|PowerShell\|CSharp` (Auto = C# unter PowerShell 7 mit gebauter DLL), Paritätstests über das Skript, Pseudonymisierer mit beiden Parsern, Messung 15 MB: 1,6 s statt 13–14 s; 11 Tests | 2026-11-08 | 9965aad |
| I18 | C#-Parser: Warnungen mit Zeilennummer, Kürzen, Zeitlimit, Zusammenfassung und CRLF/LF gleich wie das Skript (Paritätstest mit Warnungen und Verbose); 24 Tests | 2026-11-08 | c33a557 |
| I17 | C#-Parser: alle Felder je Ereignis wie das Skript (inkl. Routinen/Trigger/Verbindungsdauer aus I12), Paritätstest auf 5 Fixtures und 10 Grenzfällen; 16 Tests | 2026-11-08 | 9c90746 |
| I16 | C#-Parser: ADR-003, Projekt `src/FirebirdTraceParser` (`net8.0`, nur PowerShell 7), Cmdlet `ConvertFrom-FirebirdTrace` mit Kopfzeile und 46 Feldern, Build in Gate und CI; 16 Tests | 2026-11-08 | 1a33b89 |

---

## Offene Punkte

| # | Beschreibung | Priorität |
|---|-------------|-----------|
| I20 | Umstellung abschließen: PowerShell-Parsing als Fallback behalten oder entfernen | Hoch |
| I8 | Laufzeit- und Beispielstände aus dem Security-Sweep nachziehen | Niedrig |

---

## Risiken & Blocker

Eintragen, **sobald** ein Punkt erkannt ist — nicht erst, wenn er eskaliert.
Wenn keine Risiken bekannt: Zeile „(noch keine Einträge)" einsetzen, Tabelle nicht leer lassen (`CONVENTIONS_COMMON.md` §3).

| Risiko / Blocker | Auswirkung | Mitigation / Nächster Schritt | Owner | Status |
|---|---|---|---|---|
| Pseudonymisierte Exporte enthalten Klartext-Reste | Weitergabe personenbezogener Daten an Dritte trotz „Pseudonymisierung" | I2 (Klartext-Lücken) und I3 (HMAC mit Schlüssel) umgesetzt. Rest: Fehlertexte nur teilweise gehasht (`features/PSEUDONYMIZATION.md`); Exporte weiter vor Weitergabe mit `-AnalyzeOnly` prüfen, nur mit Freigabe teilen (`docs/security/DATA_HANDLING.md`) | Maintainer | gemindert |
| Trace-Anmeldung mit SYSDBA über eine Klartext-Passwortdatei | Wer die Datei lesen kann, hat vollen DB-Zugriff | Seit I4 kein Passwort mehr in Befehlszeile oder `config.json` (ADR-002). Rest: Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` einrichten und testen, Passwortdatei nach Gebrauch löschen, früher per `-PASS` genutztes Passwort rotieren | Owner / DB-Administration | gemindert |
| Ältere Commits der öffentlichen Git-History enthalten echte interne Verbindungsdaten in Kommentar-Beispielen | Informationsabfluss über das öffentliche Repository | Neue Commits schützt seit 2026-11-08 der aktive Interna-Hook (`.internal-terms` vorhanden); synthetische Fixtures sind seit `aebd937` versioniert. **Entscheidung Owner 2026-11-08: History nicht bereinigen.** Geprüft: zwei interne Begriffe in je zwei Commits, kein echtes Passwort (nur Platzhalter und das Firebird-Standardbeispiel `masterkey`). Ein Force-Push würde bestehende Klone brechen, GitHub-Caches und Forks behielten die alten Stände trotzdem. Stattdessen SYSDBA-Passwort ändern; neue Commits schützt der Interna-Hook. Details nur in `docs/local/ENVIRONMENT.md` | Repo-Owner | akzeptiert (2026-11-08) |
| .NET SDK 9 lokal, Supportende 2026-11-10 | Build mit einem SDK ohne Sicherheitskorrekturen | CI baut mit SDK 10.0.x; `global.json` lässt SDK 10 zu (`latestMajor`). Lokal .NET SDK 10 installieren | Owner | offen |
| CI noch nie auf GitHub gelaufen | Workflow-Fehler (Modulinstallation, Runner-Image) fallen erst beim ersten Lauf auf | Seit I14 Workflow mit PSScriptAnalyzer und Pester (PS 7 und 5.1), seit I16 mit Build des C#-Parsers (`actions/setup-dotnet`, nur Job PS 7); lokal mit denselben Befehlen grün. Nach dem nächsten Push den ersten Lauf ansehen | Maintainer | gemindert |
