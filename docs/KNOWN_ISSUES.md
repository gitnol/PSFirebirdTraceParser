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
| K1 | README nennt Ausgabe-Properties `IPAddress`/`Application`, der Code liefert `ClientIP`/`ApplicationPath`; weitere Properties (`Action`, `Params`, `TableStats`, `RootTxID` …) fehlen in der Liste; „line-by-line (low memory)" trifft nicht zu | README mit `.\Show-TraceStructure.ps1 -Path <datei> \| Get-Member` vergleichen | `Get-Member` bzw. `features/TRACE_PARSING.md` nutzen | reine Doku-Drift, kein Datenrisiko | `I7` |
| K2 | Parser lädt die ganze Datei in den Speicher und gibt erst am Ende aus | großes Trace-Log parsen, Speicher beobachten | 64-Bit-PowerShell mit genug RAM; Datei an Zeitstempel-Zeilen teilen | Umbau braucht vorher Charakterisierungstests | `I6` |
| K3 | Verbindungsfelder (`DatabasePath`, `User`, `ClientIP` …) bleiben leer bei Rolle ≠ `NONE`, Endung `.fdb` in Kleinschreibung oder Nicht-TCP-Verbindungen | Block mit solcher Verbindungszeile parsen | keiner | wie K2 | `I6` |
| K4 | `trace_stop.ps1` wählt die neueste `*.log` unter `E:\`; Hinweistext in `trace_start.ps1` nennt `trace-stop.ps1` statt `trace_stop.ps1` | andere `.log`-Datei nach dem Start unter `E:\` ablegen, dann stoppen → Exit 4 | `fbtracemgr … -LIST` und `-STOP -ID <n>` von Hand (`operations/RUNBOOK.md`) | betrifft nur den Bedienkomfort | `I5` |
| K5 | `trace_start.ps1`/`trace_stop.ps1` enthalten Umlaute ohne BOM → unter Windows PowerShell 5.1 falsch dargestellt | mit `powershell.exe` ausführen, `config.json` ungültig machen; PSScriptAnalyzer meldet `PSUseBOMForUnicodeEncodedFile` (bestätigt) | PowerShell 7 verwenden | kosmetisch | `I5` |
| K6 | `Pseudonymize-FirebirdTrace.ps1` weist im `-AnalyzeOnly`-Zweig an `$matches` zu (automatische Variable) | `Invoke-ScriptAnalyzer` meldet `PSAvoidAssignmentToAutomaticVariable` (beim Init mit PSScriptAnalyzer 1.25.0 bestätigt) | keiner nötig | keine bekannte Fehlfunktion | `I2` |

---

## Behobene Probleme

Letzte Einträge behalten bis zur nächsten Aufräum-Iteration (Spur für
Lessons Learned). Danach archivieren oder löschen.

| # | Beschreibung | Behoben in | Commit |
|---|---|---|---|
| (noch keine Einträge) | | | |

---

## Pflege

- Neuer Bug ohne sofortigen Fix → Eintrag hier; TODO-Punkt **nur**, wenn
  priorisiert wird.
- Eintrag wird behoben → in „Behobene Probleme" verschieben, in der nächsten
  Aufräum-Iteration löschen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
