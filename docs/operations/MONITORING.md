# Monitoring & Betrieb – PSFirebirdTraceParser

Kein Dauerbetrieb: Die Skripte laufen interaktiv. Zu beobachten ist vor allem eine **laufende Trace-Session**,
weil sie unbegrenzt Daten schreibt und den Datenbankserver belastet.

---

## Erfolgsindikatoren

| Indikator | Erwarteter Wert | Prüfung |
|-----------|----------------|---------|
| Exit-Code der Trace-Skripte | `0` | `$LASTEXITCODE` nach dem Aufruf (Codes 1–4: `architecture/ERROR_HANDLING.md`) |
| Kopfzeile der Trace-Datei | `Trace session ID <n> started` | `Get-Content <datei> -TotalCount 1` |
| Trace-Datei wächst während der Session | Dateigröße steigt | `(Get-Item <datei>).Length` |
| Session nach dem Stopp beendet | keine eigene Session mehr gelistet | `fbtracemgr -SE service_mgr -LIST …` |
| Parser-Lauf | „Parsed <n> records" ≈ Anzahl Zeitstempel-Zeilen | Konsolenausgabe von `Show-TraceStructure.ps1` |

---

## Exit-Codes

| Code | Bedeutung |
|------|-----------|
| `0` | Durchlauf ohne erkannten Fehler (Fehler von `fbtracemgr` werden nicht ausgewertet, I5) |
| `1` | `config.json` fehlt |
| `2` | `config.json` ist kein gültiges JSON |
| `3` | `trace_stop.ps1`: keine `*.log` unter `E:\` |
| `4` | `trace_stop.ps1`: keine Session-ID in der ersten Zeile |

---

## Manuelle Checks

```powershell
# Laufende Trace-Sessions (Anmeldung wie in security/AUTHENTICATION.md)
& "<FirebirdPath>\fbtracemgr" -SE service_mgr -LIST <Anmeldeparameter>

# Freier Platz auf dem Ausgabelaufwerk
Get-PSDrive -Name E | Select-Object Used, Free

# Größe und Alter der Trace-Dateien (Retention, security/DATA_HANDLING.md §5)
Get-ChildItem E:\trace_output_*.log | Select-Object Name, Length, LastWriteTime
```

---

## Bekannte Warnsignale

| Signal | Mögliche Ursache | Maßnahme |
|--------|-----------------|---------|
| Trace-Datei wächst sehr schnell | `time_threshold` zu niedrig, alle Datenbanken im Trace | Session stoppen, Konfiguration einschränken |
| Freier Platz auf `E:\` sinkt stark | vergessene Session | Session per `-LIST`/`-STOP` beenden, Datei sichern oder löschen |
| Alte `trace_output_*.log` liegen herum | Aufräumen vergessen | löschen bzw. Retention durchsetzen |
| Spürbar höhere Last/Latenz auf dem DB-Server | Trace mit `print_plan`/`print_perf` auf viele Statements | Dauer verkürzen, Schwellwert erhöhen |
| Parser meldet deutlich weniger Datensätze als erwartet | Format abweichend (Firebird-Version) oder Datei abgeschnitten | Kopf- und Zeitstempelzeilen der Datei prüfen |
