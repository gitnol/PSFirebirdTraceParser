# Credential-Strategie – PSFirebirdTraceParser

Wo und wie Credentials für die Trace-Skripte gespeichert und benutzt werden.
Konkretisiert `docs/operations/SECRETS_MANAGEMENT.md` für Windows / PowerShell.

Nur `trace_start.ps1` und `trace_stop.ps1` brauchen ein Credential (Firebird-Benutzer für den Service-Manager).
Parser und Pseudonymisierer arbeiten ohne Credentials.

---

## Ist-Zustand (Init, 2026-10-11)

| Credential | Ablage | Übergabe an `fbtracemgr` | Bewertung |
|---|---|---|---|
| Firebird-Benutzer + Passwort (Vorlage: SYSDBA) | `config.json` im Skriptverzeichnis, Klartext, gitignored | Kommandozeile `-USER … -PASS …` | **nicht konform**: Klartext auf Platte, Passwort in der Prozess-Kommandozeile sichtbar, höchstprivilegierter Benutzer |

Bedrohung 3 in `security/THREAT_MODEL.md`; Ablösung in I4 (`docs/TODO.md`).

---

## Erlaubte Speicherorte (Soll)

| Credential-Typ | Empfohlener Store | Bemerkung |
|---|---|---|
| Firebird-Passwort des Trace-Benutzers | DPAPI-Datei (`Export-Clixml`) oder `SecretManagement` | an den ausführenden Windows-Benutzer gebunden |
| Übergabe an `fbtracemgr` | Option `-fetch <datei>` (Passwort aus Datei, ACL nur ausführender Benutzer, nach Gebrauch löschen) **oder** `-trusted` (Windows-Authentifizierung, falls serverseitig konfiguriert) | Optionen laut Firebird-4.0-Manpage von `fbtracemgr`; Auswahl in ADR-002 (I4) |
| Pseudonymisierungs-Schlüssel (ab I3) | nur im Speicher des Laufs oder `SecretManagement` | nie in Exporten, Logs oder `config.json` |

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
Damit braucht `fbtracemgr` kein SYSDBA-Passwort. Einrichtung (Rolle anlegen, als Default-Rolle zuweisen) wird
in I4 in `operations/SETUP.md` beschrieben und gegen die eingesetzte Firebird-Version geprüft.

---

## Anti-Pattern

```powershell
# Verboten: Passwort als Kommandozeilenargument (Bestand trace_start.ps1/trace_stop.ps1)
& "$MyPfad\fbtracemgr" -SE service_mgr -USER $MyUser -PASS $MyPass -START …

# Verboten: Klartext-Passwort in einer Konfigurationsdatei (Bestand config.json)
# Verboten: bekanntes Standardpasswort in Vorlagen (Bestand config.sample.json)
```

---

## Pattern: `[PSCredential]` durchreichen

```powershell
function Invoke-FbTraceManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string[]]$Arguments
    )
    # Passwort erst unmittelbar vor dem Aufruf in die kurzlebige -fetch-Datei schreiben, danach löschen
}
```

`[pscredential]` hält das Passwort als `SecureString` — niemals als Klartext-String durch die Skripte reichen.

---

## Logging-Regeln

- Niemals Passwort, Kommandozeile mit `-PASS` oder Inhalt der `-fetch`-Datei ausgeben.
- Bei Fehlern das Ereignis melden („Anmeldung am Service-Manager fehlgeschlagen"), nicht die Zugangsdaten.

---

## Rotation

| Credential | Intervall | Trigger außerplanmäßig |
|---|---|---|
| Firebird-Passwort des Trace-Benutzers | nach Policy des DB-Betriebs, mindestens jährlich | Passwort stand in einer Kommandozeile/Log, Personalwechsel |
| SYSDBA-Passwort | nach Policy | wurde bisher mit den Trace-Skripten genutzt (Kommandozeile) → nach Umstellung (I4) rotieren |

---

## Pflege

Trigger: neue Credential-Quelle / Rotation durchgeführt / Umstellung in I4 →
hier eintragen und in `docs/operations/SECRETS_MANAGEMENT.md` referenzieren.
