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

Ab Firebird 4.0 darf ein normaler Benutzer fremde Verbindungen tracen, wenn er eine Rolle mit dem Systemrecht
`TRACE_ANY_ATTACHMENT` benutzt. Als SYSDBA in der Datenbank (Namen fiktiv):

```sql
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT TRACER TO TRACE_USER;   -- TRACE_USER vorher mit CREATE USER anlegen
```

In `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"`. So beschreibt es die Firebird-Dokumentation; mit
diesen Skripten gegen einen echten Server noch nicht geprüft (bisher SYSDBA ohne Rolle).

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
