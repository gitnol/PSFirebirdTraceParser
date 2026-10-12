# Authentication – PSFirebirdTraceParser

Nur die Trace-Skripte authentifizieren sich — am lokalen Firebird-Service-Manager. Parser und Pseudonymisierer
arbeiten ohne Anmeldung auf lokalen Dateien bzw. Pipeline-Objekten.

---

## Auth-Übersicht

| Ziel | Verfahren | Secret-Ablageort | Anlage |
|------|-----------|-----------------|--------|
| Firebird-Service-Manager (`service_mgr`, lokal) | Firebird-Benutzer + Passwort (Legacy/SRP je nach Serverkonfiguration), übergeben als `fbtracemgr -USER … -PASS …` | `config.json` im Skriptverzeichnis, Klartext, gitignored | Einmalig manuell (Kopie von `config.sample.json`) |

Die Gefährdung durch dieses Verfahren steht in `security/THREAT_MODEL.md` (Bedrohung 3), die Ablösung in I4.

---

## 1. Firebird-Benutzer/Passwort (Ist)

```powershell
# Bestand (trace_start.ps1 / trace_stop.ps1), gekürzt
$Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
& "$MyPfad\fbtracemgr" -SE service_mgr -USER $Config.Firebird.Username -PASS $Config.Firebird.Password -START -CONFIG $TraceConfig
```

| Datei | Inhalt | Ablageort | Anlage-Account |
|-------|--------|-----------|---------------|
| `config.json` | Benutzer + Passwort für den Firebird-Service-Manager, Firebird-Pfad, Trace-Konfiguration | Skriptverzeichnis (`$PSScriptRoot`) | der Administrator, der Traces startet |

**Schwächen:** Passwort im Klartext auf der Platte; Passwort in der Prozess-Kommandozeile; Vorlage mit
höchstprivilegiertem Benutzer und bekanntem Standardpasswort.

---

## 2. Soll-Varianten (Entscheidung in ADR-002, I4)

Optionen laut Firebird-4.0-Manpage von `fbtracemgr` (Verbindungsparameter `-user`, `-password`, `-fetch`, `-trusted`):

| Variante | Secret-Ablage | Vorteil | Voraussetzung |
|---|---|---|---|
| `-fetch <datei>` | Passwort aus DPAPI/`SecretManagement` (`architecture/CREDENTIAL_STRATEGY.md`), nur für den Aufruf in eine ACL-geschützte Temp-Datei geschrieben und danach gelöscht | kein Passwort in der Kommandozeile | Schreib-/Löschdisziplin, ACL nur ausführender Benutzer |
| `-trusted` | keins (Windows-Anmeldung) | kein Firebird-Passwort | Server mit Windows-Authentifizierung (`Win_Sspi`) und Benutzer-Mapping |
| beide + Trace-Benutzer | wie oben | kein SYSDBA | Firebird ≥ 4, Rolle mit `TRACE_ANY_ATTACHMENT` |

Vor der Umsetzung gegen `fbtracemgr -?` der eingesetzten Firebird-Version prüfen (Schreibweise und Verhalten der Optionen).

---

## Security-Checkliste

- [ ] Kein Plaintext-Passwort im Quellcode oder in versionierten Konfigurationsdateien (`config.sample.json` ohne echtes oder Standardpasswort — offen, I4)
- [ ] `config.json` und Credential-Dateien (`*.dpapi`, `*.secret`, `*.clixml` außerhalb des Repos) nicht versioniert
- [ ] Kein Passwort als Kommandozeilenargument (offen, I4)
- [ ] Dedizierter Trace-Benutzer mit minimalen Rechten statt SYSDBA (offen, I4)
- [ ] Bei Personal- oder Rollenwechsel bzw. nach der Umstellung: Passwort rotieren, DPAPI-Dateien neu anlegen
