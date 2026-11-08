# Entwicklungsumgebung Setup – PSFirebirdTraceParser

---

## Voraussetzungen

- PowerShell 7.6 LTS empfohlen (mindestens 7.6.9 bzw. 7.5.13 / 7.4.22 wegen der Advisories vom 2026-10-13 und
  2026-10-25; 7.4/7.5 Supportende 2026-11-10); `$PSVersionTable.PSVersion` prüfen
  - Parser und Pseudonymisierer laufen auch unter Windows PowerShell 5.1 (über Windows Update aktuell halten)
  - Die Trace-Skripte brauchen **PowerShell 7.4+** (byte-genaue Logdatei, ADR-002)
- Für Parser und Pseudonymisierer: nichts weiter — keine Module, kein Netz
- Für die Trace-Skripte: Firebird-Installation mit `fbtracemgr.exe` auf dem Datenbankserver, Zugang für den
  Service-Manager (`security/AUTHENTICATION.md`), ein Ausgabeordner mit ausreichend Platz (`OutputDirectory`)
- Für Entwicklung: Pester und PSScriptAnalyzer (Versionen in `tests/RequiredModules.psd1`)

---

## Installation

### Repository holen

```powershell
git clone <Repository-URL> PSFirebirdTraceParser
Set-Location PSFirebirdTraceParser
git config core.hooksPath tools/git-hooks      # Interna-Hook aktivieren (CONVENTIONS_COMMON.md 3.1)
New-Item .internal-terms -ItemType File   # lokal, gitignored: interne Begriffe je Zeile eintragen (Denylist)
```

### PowerShell 7 (empfohlen)

```powershell
winget install Microsoft.PowerShell
```

### Execution Policy (einmalig, aktueller Benutzer)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
# Aus dem Internet geladene Skripte ggf. entsperren:
Get-ChildItem *.ps1 | Unblock-File
```

### Entwickler-Module

```powershell
# Genau die gepinnten Versionen (tests/RequiredModules.psd1), wie in der CI
$required = Import-PowerShellDataFile ./tests/RequiredModules.psd1
foreach ($name in $required.Keys) {
    Install-Module -Name $name -RequiredVersion $required[$name].RequiredVersion -Scope CurrentUser -Force -SkipPublisherCheck
}
```

Versionen: `security/DEPENDENCY_AUDIT.md` → Befunde.

### Konfiguration für die Trace-Skripte anlegen

```powershell
# config.json ist gitignored — NIEMALS committen. Es enthält kein Passwort.
Copy-Item config.sample.json config.json
# config.json bearbeiten: FirebirdPath, Username + PasswordFile (oder UseTrustedAuth), Role, OutputDirectory, SessionName
```

### Passwortdatei anlegen (ohne `UseTrustedAuth`)

```powershell
$dir = Join-Path $env:LOCALAPPDATA 'PSFirebirdTraceParser'
$null = New-Item -ItemType Directory -Force -Path $dir
$file = Join-Path $dir 'firebird-trace.pass'
$pw = Read-Host 'Firebird-Passwort' -MaskInput          # verdeckt eingeben; nur die erste Zeile wird gelesen
Set-Content -Path $file -Value $pw -NoNewline -Encoding ascii
Remove-Variable pw
icacls $file /inheritance:r /grant:r "$($env:USERNAME):(R,W)"   # nur das eigene Konto
```

Nach der Aufzeichnung löschen. Nie ins Repo legen. Das früher in `config.json` stehende Passwort rotieren.

### Optional: Trace-Benutzer statt SYSDBA

Ab Firebird 4.0 darf ein normaler Benutzer fremde Verbindungen tracen, wenn eine Rolle mit dem Systemrecht
`TRACE_ANY_ATTACHMENT` aktiv ist. Als SYSDBA, verbunden mit der Datenbank, die aufgezeichnet werden soll (Namen fiktiv):

```sql
CREATE USER TRACE_USER PASSWORD '<neues Passwort>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Erklärung:

- `CREATE USER` legt den Benutzer an (in der Sicherheitsdatenbank). Das Passwort danach in die Passwortdatei (oben)
  schreiben, nirgends sonst.
- Die Rolle gibt nur dieses eine Systemrecht, keine Rechte an Tabellen. Sie liegt in der Datenbank, in der sie angelegt
  wurde — bei mehreren Datenbanken dort jeweils anlegen und zuweisen.
- `GRANT DEFAULT` (ab Firebird 4.0) macht die Rolle zur Standardrolle: Sie ist beim Anmelden aktiv, auch ohne
  Rollenangabe. Die Skripte geben sie mit `"Role"` ohnehin mit (`-ROLE`).

In `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"`, dazu `PasswordFile` mit dem Passwort von `TRACE_USER`
oder `"UseTrustedAuth": true`. So machen es die Firebird-QA-Tests (`tests/functional/syspriv/test_trace_any_attachment.py`,
ab 4.0: Rolle in der Testdatenbank, `grant default`, Trace mit Benutzer und Rolle); mit diesen Skripten gegen einen
echten Server noch nicht geprüft (bisher SYSDBA ohne Rolle).

Stand das SYSDBA-Passwort je auf einer Befehlszeile (früher `fbtracemgr -PASS`, sichtbar in Prozesslisten und in der
Befehlshistorie der Shell), das SYSDBA-Passwort ändern: `ALTER USER SYSDBA PASSWORD '<neues Passwort>';`

### Optional: Windows-Anmeldung

`"UseTrustedAuth": true`; der Server braucht `AuthServer = Srp256, Win_Sspi` in `firebird.conf` (Neustart) und ein
Mapping des Windows-Kontos auf einen Firebird-Benutzer. Ungeprüft gegen einen echten Server.

---

## Wichtige Commands

```powershell
# Parsen und ansehen
.\Show-TraceStructure.ps1 -Path .\trace.log | Out-GridView

# Vorab prüfen, was pseudonymisiert würde (gibt Klartext auf der Konsole aus!)
.\Show-TraceStructure.ps1 -Path .\trace.log | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals -AnalyzeOnly

# Pseudonymisiert exportieren (Export liegt außerhalb des Repos oder ist per /*.csv ignoriert)
.\Show-TraceStructure.ps1 -Path .\trace.log | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals |
    Export-Csv -Path ..\safe_trace.csv -NoTypeInformation

# Quality Gates (wie in CI, CONVENTIONS.md §9)
pwsh -File ./tools/Invoke-QualityGate.ps1
```

---

## Credentials / Konfiguration

| Variable / Parameter | Beschreibung | Fundort |
|---------------------|-------------|---------|
| `Firebird.Username` | Firebird-Benutzer für den Service-Manager | DB-Administration (Trace-Benutzer mit Rolle empfohlen) |
| `Firebird.PasswordFile` | Pfad der Passwortdatei (nicht das Passwort) | eigener Profilordner, siehe oben |
| `Firebird.Role` | Rolle mit `TRACE_ANY_ATTACHMENT` | DB-Administration |
| `Firebird.FirebirdPath` | Firebird-Installationsordner | Datenbankserver |

> **Niemals `config.json` oder die Passwortdatei committen.** `.gitignore` erfasst `config*.json` (außer
> `config.sample.json`); ein Test prüft, dass `config.json` nicht in git ist.
