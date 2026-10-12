# Runbook – PSFirebirdTraceParser

Häufige Operationen und Troubleshooting. Die Skripte laufen interaktiv (kein Task Scheduler).

---

## Häufige Commands

```powershell
# 1. Trace starten (auf dem Datenbankserver; blockiert diese Konsole, bis die Session gestoppt ist)
.\trace_start.ps1
# Ausgabe: E:\trace_output_<yyyyMMdd_HHmmss>.log

# 2. In einer ZWEITEN Konsole: Trace stoppen (nimmt die neueste *.log unter E:\)
.\trace_stop.ps1

# 3. Auswerten
.\Show-TraceStructure.ps1 -Path E:\trace_output_<zeitstempel>.log | Out-GridView

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
→ `config.json` fehlt (1) bzw. ist kein gültiges JSON (2). Aus `config.sample.json` anlegen bzw. Syntax prüfen
(`Get-Content config.json -Raw | ConvertFrom-Json`).

### `trace_stop.ps1` endet mit Exit 3 oder 4
→ 3: keine `*.log` unter `E:\`. 4: Die neueste `*.log` unter `E:\` ist nicht die Trace-Ausgabe (andere Logdatei dort)
oder die Session ist nicht gestartet. Workaround: laufende Sessions mit `fbtracemgr -SE service_mgr -LIST …`
anzeigen und gezielt mit `-STOP -ID <n>` stoppen (Anmeldung wie in `security/AUTHENTICATION.md`); K4.

### Trace-Datei bleibt leer bzw. enthält nur eine Fehlermeldung
→ Bei `trace_start.ps1` wird nur stdout von `fbtracemgr` in die Trace-Datei umgeleitet; Fehlermeldungen können dort oder
(über stderr) auf der Konsole stehen — beides prüfen. Meldung lesen (Benutzer/Passwort, Pfad zu `fbtrace30.conf`, Rechte für Traces auf fremde Verbindungen).

### Parser bricht mit OutOfMemory ab oder braucht sehr lange
→ Die Datei wird komplett in den Speicher geladen (K2). 64-Bit-PowerShell mit genug RAM nutzen oder die Datei vorher
an Blockgrenzen (Zeilen mit Zeitstempel) teilen; Streaming folgt in I6.

### Felder `DatabasePath`, `User`, `ClientIP` sind leer
→ Verbindungszeile passt nicht zum Regex (Rolle ≠ `NONE`, Endung `.fdb` klein, Nicht-TCP-Verbindung) — K3.

### Umlaute in Meldungen der Trace-Skripte falsch dargestellt
→ Windows PowerShell 5.1 liest die BOM-losen UTF-8-Skripte als ANSI (K5); mit PowerShell 7 ausführen.

---

## Deployment-Checkliste (Einsatz auf einem Datenbankserver)

- [ ] PowerShell ≥ 5.1 vorhanden, besser 7.6 LTS
- [ ] Skripte und `fbtrace30.conf` in ein Verzeichnis mit eingeschränkten NTFS-Rechten kopiert
- [ ] `config.json` angelegt, Zugriff nur für Administratoren; kein Standardpasswort
- [ ] Laufwerk `E:\` vorhanden, freier Platz geprüft (`operations/MONITORING.md`)
- [ ] Trace-Dauer und Verantwortlichen für Stopp und Löschung festgelegt
- [ ] Nach Abschluss: Session gestoppt (`-LIST` leer), Rohdatei gelöscht oder in geschützten Bereich verschoben
