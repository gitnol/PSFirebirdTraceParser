# Authentication – PSFirebirdTraceParser

Nur die Trace-Skripte authentifizieren sich — am lokalen Firebird-Service-Manager. Parser und Pseudonymisierer
arbeiten ohne Anmeldung auf lokalen Dateien bzw. Pipeline-Objekten.

---

## Auth-Übersicht

| Ziel | Verfahren | Secret-Ablageort | Anlage |
|------|-----------|-----------------|--------|
| Firebird-Service-Manager (`service_mgr`, lokal) | Firebird-Benutzer + Passwortdatei (`fbtracemgr -USER … -FETCH_PASSWORD <datei>`) oder Windows-Anmeldung (`-TRUSTED`), optional `-ROLE` | Passwortdatei außerhalb des Repos, Rechte nur eigenes Konto | Einmalig manuell (`operations/SETUP.md`) |

Entscheidung: `architecture/ADR/ADR-002-trace-anmeldung.md` (seit I4). Bedrohung 3 in `security/THREAT_MODEL.md`.

---

## 1. Ablauf (Ist, seit I4)

```powershell
# TraceCommon.ps1, gekürzt: nur der Pfad der Passwortdatei geht an fbtracemgr
$arguments = @('-SE', 'service_mgr') + (Get-TraceAuthArgumentList -Config $config) + @('-START', '-NAME', $name, '-CONFIG', $conf)
Invoke-FbTraceMgr -FilePath $config.FbTraceMgr -ArgumentList $arguments -OutFile $logFile
```

| Datei | Inhalt | Ablageort | Anlage-Account |
|-------|--------|-----------|---------------|
| `config.json` | Benutzer, Pfad der Passwortdatei, Rolle, Firebird-Pfad, Ausgabeordner, Sitzungsname | Skriptverzeichnis (`$PSScriptRoot`) | der Administrator, der Traces startet |
| Passwortdatei | Passwort in der ersten Zeile | z. B. `%LOCALAPPDATA%\PSFirebirdTraceParser\` | derselbe Benutzer; Rechte nur für ihn |

**Restschwäche:** Die Passwortdatei ist Klartext (Schutz über Dateirechte). Bis I4: Passwort in `config.json` und in der
Befehlszeile, Vorlage mit SYSDBA und Standardpasswort.

---

## 2. Varianten

| Variante | Secret-Ablage | Vorteil | Voraussetzung |
|---|---|---|---|
| `-FETCH_PASSWORD <datei>` (genutzt mit echten Traces, Firebird 5.0.4) | Passwortdatei, Rechte nur ausführender Benutzer | kein Passwort in der Befehlszeile | Datei anlegen, nach Gebrauch löschen |
| `-TRUSTED` (ungeprüft gegen einen Server) | keins (Windows-Anmeldung) | kein Firebird-Passwort | `AuthServer = Srp256, Win_Sspi`, Benutzer-Mapping |
| eine davon + `-ROLE` (ungeprüft gegen einen Server) | wie oben | kein SYSDBA | Firebird ≥ 4, Rolle mit `TRACE_ANY_ATTACHMENT` |

---

## Security-Checkliste

- [ ] Kein Plaintext-Passwort im Quellcode oder in versionierten Konfigurationsdateien (`config.sample.json` ohne Passwort, seit I4; Test)
- [ ] `config.json` und Credential-Dateien (`*.dpapi`, `*.secret`, `*.clixml` außerhalb des Repos) nicht versioniert
- [ ] Kein Passwort als Kommandozeilenargument (seit I4; Test)
- [ ] Dedizierter Trace-Benutzer mit minimalen Rechten statt SYSDBA (möglich über `Role`; im Einsatz noch SYSDBA)
- [ ] Bei Personal- oder Rollenwechsel bzw. nach der Umstellung: Passwort rotieren, DPAPI-Dateien neu anlegen
