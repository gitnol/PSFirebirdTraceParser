# Deployment – PSFirebirdTraceParser

Default-Template; derzeit liefert kein Stack eine eigene Variante. Für dieses Projekt gibt es keinen Build und
keinen Server-Dienst: Ausgeliefert werden die Skripte selbst über das öffentliche Git-Repository.
Einsatz auf einem Datenbankserver: `operations/RUNBOOK.md` → Deployment-Checkliste; Erst-Setup: `operations/SETUP.md`.

Verbindet sich mit `operations/SETUP.md` (Erst-Setup), `operations/RUNBOOK.md`
(Betrieb) und `operations/SECRETS_MANAGEMENT.md`.

---

## Umgebungen

| Umgebung | Zweck | Datenquelle | Wer darf deployen |
|---|---|---|---|
| dev | Entwicklung, Tests | synthetische Trace-Dateien mit fiktiven Daten (`tests/fixtures/`, seit I9) | Maintainer |
| Nutzer-Einsatz | Trace auf einem Firebird-Server erfassen und auswerten | echte Trace-Daten (vertraulich) | Nutzer kopiert die Skripte aus einem Tag/Commit |

Unterschiede zwischen Einsätzen werden ausschließlich über `config.json` und Parameter gesteuert
(siehe `architecture/CONFIGURATION.md`).

---

## Build

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build   # dotnet build src/FirebirdTraceParser -> bin/FirebirdTraceParser.dll
```

Die `.ps1`-Dateien werden direkt ausgeführt. Seit I16 gibt es den C#-Parser (ADR-003): Er wird mit dem .NET SDK
(`global.json`) nach `bin/` gebaut, Paketversionen fest über `src/FirebirdTraceParser/packages.lock.json`
(`RestoreLockedMode`). `bin/` ist nicht versioniert. Ein PowerShell-Prozess, der die DLL geladen hat, sperrt sie —
vor einem Neubau diesen Prozess beenden. Die DLL läuft nur unter PowerShell 7.4+ (`net8.0`).

Auslieferungsartefakt: Git-Commit bzw. -Tag des Repositories (Skripte, `TraceCommon.ps1`, `fbtrace50.conf`/`fbtrace30.conf`, `config.sample.json`, READMEs, Handbücher in `docs/handbuch/`). Die DLL wird bisher nicht ausgeliefert, nur lokal gebaut (Verteilung: I22).

**Reproduzierbar:**
- [ ] Entwickler-Module gepinnt (`tests/RequiredModules.psd1`, seit I9)
- [ ] NuGet-Pakete gepinnt (`packages.lock.json`, seit I16); SDK-Mindestversion in `global.json`
- [ ] Gates laufen in sauberer Umgebung: CI seit I14 (`.github/workflows/ci.yml`, frischer Checkout auf `windows-latest`)

---

## Release

Bisher gibt es keine Tags oder Releases; Nutzer verwenden `main`.

| Schritt | Verantwortung | Verifikation |
|---|---|---|
| Dependency-Audit + Security-Currency-Abgleich (Pflicht vor jedem Release) | Maintainer | datierter Eintrag in `security/DEPENDENCY_AUDIT.md` → Befunde (`principles/SECURITY_CURRENCY.md`) |
| Gates grün (PSScriptAnalyzer, Pester) | Maintainer | Gate-Lauf im CHANGELOG-Eintrag |
| README.md und README.de.md aktuell | Maintainer | Parameter/Properties gegen Code geprüft |
| Tag setzen (`vMAJOR.MINOR.PATCH`) und pushen | Maintainer | Tag auf GitHub sichtbar |

---

## Rollback

**Bedingung:** Ein Release liefert falsche Ergebnisse (Parser) oder pseudonymisiert weniger als vorher.

| Schritt | Befehl / Aktion |
|---|---|
| 1. Letzte stabile Version identifizieren | `git tag --sort=-creatordate` bzw. `git log --oneline` |
| 2. Rollback ausführen | Nutzer: `git checkout <tag>`; Maintainer: `git revert <commit>` (kein Force-Push auf `main`) |
| 3. Verifikation | Gates + Stichprobe mit synthetischer Trace |
| 4. Hinweis an Nutzer | README/Release-Notiz, wenn bereits Daten mit fehlerhafter Pseudonymisierung weitergegeben sein könnten |

---

## Post-Deploy-Verifikation

- [ ] Parser auf synthetischer Trace: erwartete Anzahl Objekte und Felder
- [ ] Pseudonymisierer: kein Feld der Feldabdeckung fällt in den Klartext zurück
- [ ] Trace-Skripte: Start/Stopp gegen eine Testinstanz (nicht Produktion)

---

## Pflege

Trigger: erstes Tag / CI eingeführt / geänderter Auslieferungsweg → hier eintragen.
