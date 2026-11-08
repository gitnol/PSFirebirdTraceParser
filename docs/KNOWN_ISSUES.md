# Bekannte Probleme – PSFirebirdTraceParser

Bugs, Quirks und Einschränkungen, die **nicht** akut behoben werden, aber
dokumentiert sein müssen, damit niemand zweimal darüber stolpert.

**Abgrenzung:**

- `TODO.md` = Arbeit, die in einem priorisierten Inkrement aufgeräumt wird
- `KNOWN_ISSUES.md` = bekannt, akzeptiert oder verschoben; mit Workaround
- `BACKLOG.md` = noch unpriorisierte Ideen, keine konkreten Probleme

Sicherheitsrelevante Schwächen stehen in `security/THREAT_MODEL.md` und `STATE.md` → Risiken, nicht hier.

---

## Aktive Probleme

| # | Beschreibung | Reproduktion | Workaround | Akzeptanzgrund | Geplant für |
|---|---|---|---|---|---|
| K4 | `trace_stop.ps1` wählt die neueste `*.log` unter `E:\`; Hinweistext in `trace_start.ps1` nennt `trace-stop.ps1` statt `trace_stop.ps1` | andere `.log`-Datei nach dem Start unter `E:\` ablegen, dann stoppen → Exit 4 | `fbtracemgr … -LIST` und `-STOP -ID <n>` von Hand (`operations/RUNBOOK.md`) | betrifft nur den Bedienkomfort | `I5` |

---

## Behobene Probleme

Letzte Einträge behalten bis zur nächsten Aufräum-Iteration (Spur für
Lessons Learned). Danach archivieren oder löschen.

| # | Beschreibung | Behoben in | Commit |
|---|---|---|---|
| ~~K5~~ | `trace_start.ps1`/`trace_stop.ps1` enthielten Umlaute ohne BOM (unter Windows PowerShell 5.1 falsch dargestellt) | `I14` (2026-11-08) | ca1edc9 |
| ~~K6~~ | Zuweisung an die automatische Variable `$matches` im `-AnalyzeOnly`-Zweig | `I2` (2026-11-07) | 02ba8c7 |
| ~~K7~~ | `-AnalyzeOnly` schrieb seine Auswertungstabellen als Formatierungsobjekte in die Ausgabe (beim Charakterisierungstest gefunden) | `I2` (2026-11-07) | 02ba8c7 |
| ~~K2~~ | Parser lud die ganze Datei in den Speicher und gab erst am Ende aus (78-MB-Datei: 1,5 GB Arbeitsspeicher) | `I6` (2026-11-07) | ae83580 |
| ~~K1~~ | README nannte `IPAddress`/`Application` statt `ClientIP`/`ApplicationPath`, weitere Properties fehlten | `I7` (2026-11-07) | f3e476a |
| ~~K3~~ | Verbindungsfelder blieben leer bei `<internal>`-Verbindungen (belegt: 12 von 298 im echten Firebird-5-Log), Rolle ≠ `NONE`, kleiner Endung, Protokoll ohne Port | `K3` (2026-11-07) | e82e31e |

---

## Pflege

- Neuer Bug ohne sofortigen Fix → Eintrag hier; TODO-Punkt **nur**, wenn
  priorisiert wird.
- Eintrag wird behoben → in „Behobene Probleme" verschieben, in der nächsten
  Aufräum-Iteration löschen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
