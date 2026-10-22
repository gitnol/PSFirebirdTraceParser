# Entwicklungsumgebung Setup – PSFirebirdTraceParser

---

## Voraussetzungen

- PowerShell ≥ 5.1 (`$PSVersionTable.PSVersion` prüfen)
  - Windows PowerShell 5.1 (vorinstalliert, über Windows Update aktuell halten) oder PowerShell 7.6 LTS (empfohlen,
    mindestens 7.6.7 bzw. 7.5.12 / 7.4.21 wegen der Advisories vom 2026-10-13; 7.4/7.5 Supportende 2026-11-10)
- Für Parser und Pseudonymisierer: nichts weiter — keine Module, kein Netz
- Für die Trace-Skripte: Firebird-Installation mit `fbtracemgr.exe` auf dem Datenbankserver, Zugang für den
  Service-Manager (`security/AUTHENTICATION.md`), Laufwerk `E:\` mit ausreichend Platz
- Für Entwicklung (ab I2): Pester und PSScriptAnalyzer

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

### Entwickler-Module (ab I2)

```powershell
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
Get-Module -Name Pester, PSScriptAnalyzer -ListAvailable
```

Versionen: `security/DEPENDENCY_AUDIT.md` → Befunde; ab I2 gepinnt in `tests/RequiredModules.psd1`.

### Konfiguration für die Trace-Skripte anlegen

```powershell
# config.json ist gitignored — NIEMALS committen
Copy-Item config.sample.json config.json
# config.json bearbeiten: FirebirdPath (Verzeichnis mit fbtracemgr.exe), Username, Password, TraceConfigFilename
```

Kein Standardpasswort übernehmen; bis I4 steht das Passwort im Klartext in `config.json`
(`architecture/CREDENTIAL_STRATEGY.md`).

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

# Quality Gates (ab I2)
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning
Invoke-Pester ./tests -ExcludeTag Integration -Output Detailed
```

---

## Credentials / Konfiguration

| Variable / Parameter | Beschreibung | Fundort |
|---------------------|-------------|---------|
| `Firebird.Username` | Firebird-Benutzer für den Service-Manager | DB-Administration (künftig dedizierter Trace-Benutzer, I4) |
| `Firebird.Password` | Passwort dazu | DB-Administration / Passwortverwaltung der Organisation — nie aus Vorlagen übernehmen |
| `Firebird.FirebirdPath` | Firebird-Installationsverzeichnis | Datenbankserver |

> **Niemals `config.json` committen.** `.gitignore` erfasst `config*.json` (außer `config.sample.json`).
