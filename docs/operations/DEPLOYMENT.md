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
| dev | Entwicklung, Tests | synthetische Trace-Dateien mit fiktiven Daten (ab I2/I6) | Maintainer |
| Nutzer-Einsatz | Trace auf einem Firebird-Server erfassen und auswerten | echte Trace-Daten (vertraulich) | Nutzer kopiert die Skripte aus einem Tag/Commit |

Unterschiede zwischen Einsätzen werden ausschließlich über `config.json` und Parameter gesteuert
(siehe `architecture/CONFIGURATION.md`).

---

## Build

```
(kein Build — die .ps1-Dateien werden direkt ausgeführt)
```

Auslieferungsartefakt: Git-Commit bzw. -Tag des Repositories (Skripte, `fbtrace30.conf`, `config.sample.json`, READMEs).

**Reproduzierbar:**
- [ ] Entwickler-Module gepinnt (`tests/RequiredModules.psd1`, ab I2)
- [ ] Gates laufen in sauberer Umgebung (lokal bzw. CI, siehe BACKLOG)

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
