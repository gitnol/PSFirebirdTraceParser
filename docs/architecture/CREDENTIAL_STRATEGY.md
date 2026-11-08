# Credential-Strategie – PSFirebirdTraceParser

Wo und wie Credentials für die Trace-Skripte gespeichert und benutzt werden.
Konkretisiert `docs/operations/SECRETS_MANAGEMENT.md` für Windows / PowerShell.

Nur `trace_start.ps1` und `trace_stop.ps1` brauchen ein Credential (Firebird-Benutzer für den Service-Manager).
Parser und Pseudonymisierer arbeiten ohne Credentials.

---

## Ist-Zustand (seit I4, 2026-11-08, ADR-002)

| Credential | Ablage | Übergabe an `fbtracemgr` | Bewertung |
|---|---|---|---|
| Firebird-Benutzer + Passwort | Benutzer in `config.json`; Passwort in einer Passwortdatei außerhalb des Repos (`PasswordFile`, Rechte nur eigenes Konto) | `-USER <name> -FETCH_PASSWORD <datei>` — nur der Pfad in der Befehlszeile | konform mit Restrisiko: Datei ist Klartext, Schutz über Dateirechte |
| keins (Windows-Anmeldung) | — | `-TRUSTED` | konform; Server braucht `Win_Sspi` |

Bis I4 standen Benutzer und Passwort im Klartext in `config.json` und gingen per `-PASS` in die Befehlszeile
(Bedrohung 3 in `security/THREAT_MODEL.md`).

---

## Erlaubte Speicherorte (Soll)

| Credential-Typ | Empfohlener Store | Bemerkung |
|---|---|---|
| Firebird-Passwort des Trace-Benutzers | Passwortdatei mit Rechten nur für den ausführenden Benutzer (ADR-002); nach der Aufzeichnung löschen | DPAPI + kurzlebige Datei geprüft und verworfen (ADR-002: Start blockiert während der ganzen Aufzeichnung) |
| Übergabe an `fbtracemgr` | `-FETCH_PASSWORD <datei>` **oder** `-TRUSTED` (Windows-Authentifizierung, falls serverseitig konfiguriert) | umgesetzt in `TraceCommon.ps1` (`Get-TraceAuthArgumentList`) |
| Pseudonymisierungs-Schlüssel (seit I3, ADR-001) | Schlüsseldatei `-KeyFile` (Base64, Rechte nur aktueller Benutzer) oder Zufallsschlüssel nur im Speicher des Laufs | nie in Exporten, Logs, Zuordnungsdatei oder `config.json` |

`.dpapi`-/`*.secret`-Dateien stehen in `.gitignore`.

---

## DPAPI-Pattern (User-bound)

```powershell
# Einmalig, als der Benutzer, der die Trace-Skripte ausführt
Get-Credential -UserName 'TRACE_USER' -Message 'Firebird-Trace-Benutzer' |
    Export-Clixml -Path (Join-Path $env:LOCALAPPDATA 'PSFirebirdTraceParser\firebird-trace.clixml')

# Zur Laufzeit
$cred = Import-Clixml -Path (Join-Path $env:LOCALAPPDATA 'PSFirebirdTraceParser\firebird-trace.clixml')
```

`TRACE_USER` ist ein fiktiver Beispielname. **Wichtig:** DPAPI verschlüsselt mit dem Benutzerprofil; die Datei
ist auf anderen Konten/Rechnern nicht lesbar.

---

## Least Privilege: Trace-Benutzer statt SYSDBA

Ab Firebird 4 kann ein normaler Benutzer fremde Verbindungen tracen, wenn er eine Rolle mit dem Systemprivileg
`TRACE_ANY_ATTACHMENT` besitzt (Firebird-Doku „Trace configuration"; ohne das Privileg nur eigene Verbindungen).
Damit braucht `fbtracemgr` kein SYSDBA-Passwort. Einrichtung: `operations/SETUP.md`; die Skripte geben die Rolle
mit `-ROLE` weiter (`Role` in `config.json`). Gegen einen echten Server noch nicht geprüft.

---

## Anti-Pattern

```powershell
# Verboten: Passwort als Kommandozeilenargument (früher in trace_start.ps1/trace_stop.ps1)
& $exe -SE service_mgr -USER $user -PASS $pass -START …

# Verboten: Klartext-Passwort in config.json (seit I4: Abbruch mit Exit 2)
# Verboten: bekanntes Standardpasswort in Vorlagen
```

---

## Pattern: nur den Pfad durchreichen

```powershell
# TraceCommon.ps1 (gekürzt): das Passwort selbst liest kein Skript, nur fbtracemgr
$list.AddRange([string[]]@('-USER', $Config.Username, '-FETCH_PASSWORD', $Config.PasswordFile))
```

Braucht ein Skript künftig das Passwort selbst, als `[pscredential]` (`SecureString`) durchreichen — niemals als
Klartext-String.

---

## Logging-Regeln

- Niemals Passwort, Kommandozeile mit `-PASS` oder Inhalt der `-fetch`-Datei ausgeben.
- Bei Fehlern das Ereignis melden („Anmeldung am Service-Manager fehlgeschlagen"), nicht die Zugangsdaten.

---

## Rotation

| Credential | Intervall | Trigger außerplanmäßig |
|---|---|---|
| Firebird-Passwort des Trace-Benutzers | nach Policy des DB-Betriebs, mindestens jährlich | Passwort stand in einer Kommandozeile/Log, Personalwechsel |
| SYSDBA-Passwort | nach Policy | wurde früher mit den Trace-Skripten über die Kommandozeile genutzt → jetzt rotieren |

---

## Pflege

Trigger: neue Credential-Quelle / Rotation durchgeführt →
hier eintragen und in `docs/operations/SECRETS_MANAGEMENT.md` referenzieren.
