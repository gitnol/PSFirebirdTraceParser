# Runbook – PSFirebirdTraceParser

Häufige Operationen und Troubleshooting. Die Skripte laufen interaktiv (kein Task Scheduler).

---

## Häufige Commands

```powershell
# 1. Trace starten (auf dem Datenbankserver, PowerShell 7.4+; blockiert diese Konsole, bis die Session gestoppt ist)
pwsh -File .\trace_start.ps1
# Ausgabe: <OutputDirectory>\trace_output_<yyyyMMdd_HHmmss>.log

# 2. In einer ZWEITEN Konsole: Trace stoppen (findet die gemerkte Sitzung über ihren Namen)
pwsh -File .\trace_stop.ps1          # oder gezielt: -Id <n>

# 3. Auswerten
.\Show-TraceStructure.ps1 -Path <OutputDirectory>\trace_output_<zeitstempel>.log | Out-GridView

# 4. Für Weitergabe pseudonymisieren (erst -AnalyzeOnly, dann Export)
.\Show-TraceStructure.ps1 -Path <datei> | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals -AnalyzeOnly
.\Show-TraceStructure.ps1 -Path <datei> | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals | Export-Csv <ziel> -NoTypeInformation

# 5. Aufräumen: Rohdatei löschen, sobald die Analyse abgeschlossen ist (security/DATA_HANDLING.md §5)

# Fehlerdetails anzeigen
$Error[0] | Format-List * -Force
```

---

## Troubleshooting

### "cannot be loaded because running scripts is disabled"
→ Execution Policy setzen (einmalig): `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`;
aus dem Internet geladene Dateien mit `Unblock-File` entsperren.

### `trace_start.ps1` / `trace_stop.ps1` endet mit Exit 1 oder 2
→ 1: `config.json` fehlt (aus `config.sample.json` anlegen). 2: Konfiguration ungültig — die Meldung nennt alle
Fehler auf einmal (Pfad, Passwortdatei, `Password`-Schlüssel noch vorhanden, Sitzungsname). Beim Start bedeutet 2 auch:
`trace_session.json` ist noch da (voriger Trace nicht gestoppt) → `trace_stop.ps1` aufrufen.

### `trace_stop.ps1` endet mit Exit 3 oder 4
→ 3: keine laufende Sitzung mit dem gemerkten Namen bzw. dem `SessionName`-Präfix (schon beendet?). 4: mehrere passende
Sitzungen — die Meldung listet sie; gezielt `trace_stop.ps1 -Id <n>`. Alle Sitzungen von Hand:
`fbtracemgr -SE service_mgr -USER <name> -FETCH_PASSWORD <datei> -LIST`.

### Exit 5 oder Trace-Datei bleibt leer
→ 5: `fbtracemgr` meldet einen Fehler (Anmeldung, Rechte, Server nicht erreichbar) oder bestätigt den Stopp nicht;
die Meldung steht auf der Konsole. Eine leere Datei während der Aufzeichnung ist normal (gepuffert); nach dem Stopp
leer: keine Statements über `time_threshold` → in der Trace-Konfiguration senken.
`-TRUSTED` scheitert: der Server erlaubt keine Windows-Anmeldung (`AuthServer = Srp256, Win_Sspi` in `firebird.conf`).

### Parser braucht sehr lange
→ Seit I6 liest der Parser in 4-MB-Stücken (Speicher bleibt begrenzt, K2 behoben); die Laufzeit wächst mit der
Dateigröße. Fortschritt mit `-Verbose`; bei sehr großen Dateien Ausgabe direkt in `Export-Csv` leiten statt in
`Out-GridView`.

### Felder `DatabasePath`, `User`, `ClientIP` sind leer
→ Seit dem K3-Fix (2026-11-07) liest der Parser alle bekannten Formen der Verbindungszeile. Bleiben die Felder leer,
hat der Block keine Verbindungszeile (z. B. Sweep- oder Fehlerereignis ohne Verbindung) oder eine neue Form — dann
als Fehler melden, mit einer **fiktiven** Beispielzeile.

### Trace-Skripte melden, dass PowerShell 7.4 nötig ist
→ Die Trace-Skripte brauchen PowerShell 7.4+ (ADR-002): `pwsh -File .\trace_start.ps1`.

---

## Deployment-Checkliste (Einsatz auf einem Datenbankserver)

- [ ] PowerShell 7.6 LTS vorhanden (Trace-Skripte brauchen ≥ 7.4)
- [ ] Skripte, `TraceCommon.ps1` und `fbtrace50.conf` in ein Verzeichnis mit eingeschränkten NTFS-Rechten kopiert
- [ ] `config.json` angelegt (ohne `Password`), Passwortdatei nur für das eigene Konto lesbar (`operations/SETUP.md`)
- [ ] Ausgabeordner (`OutputDirectory`) vorhanden, freier Platz geprüft (`operations/MONITORING.md`)
- [ ] Trace-Dauer und Verantwortlichen für Stopp und Löschung festgelegt
- [ ] Nach Abschluss: Session gestoppt (`-LIST` leer), Rohdatei gelöscht oder in geschützten Bereich verschoben,
      Passwortdatei gelöscht
