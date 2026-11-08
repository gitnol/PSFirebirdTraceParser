# Externe Abhängigkeiten – PSFirebirdTraceParser

Bestand zum Init (2026-10-11), aus dem Code ermittelt. Es gibt keine Manifest-/Lock-Datei (`*.psd1`,
`RequiredModules`); Laufzeit-Abhängigkeiten sind nur PowerShell/.NET und — für die Trace-Skripte — eine
Firebird-Installation.

---

## PSGallery-Module (Install-Module)

**Laufzeit:** keine.

**Entwicklung (seit I9 in `tests/RequiredModules.psd1` gepinnt):**

| Modul | Mindestversion | Zweck | Risiko bei Ausfall |
|-------|----------------|-------|-------------------|
| `Pester` | 5.7.1 (gepinnt seit I9) | Gate 4 — Unit-Tests | Kein Regressionsschutz; Laufzeit unberührt |
| `PSScriptAnalyzer` | 1.25.0 (gepinnt seit I9) | Gate 1 — Linter | Kein Lint-Gate; Laufzeit unberührt |

**Installationsbefehl (Entwickler, einmalig):**
```powershell
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

# Installation prüfen
Get-Module -Name Pester, PSScriptAnalyzer -ListAvailable | Select-Object Name, Version, Path
```

`-Scope CurrentUser` genügt: Die Skripte laufen interaktiv unter dem angemeldeten Benutzer, nicht unter einem Dienstkonto.
Gepinnte Versionen installieren: `Install-Module -Name <Modul> -RequiredVersion <Version aus tests/RequiredModules.psd1>`
(so macht es auch die CI).

---

## CI (GitHub Actions, seit I14)

| Baustein | Version | Zweck | Risiko bei Ausfall |
|---|---|---|---|
| `actions/checkout` | v7.0.1, gepinnt auf Commit `3d3c42e5aac5ba805825da76410c181273ba90b1` | Repository im CI-Lauf auschecken (`persist-credentials: false`) | CI läuft nicht; lokal unberührt |
| Runner `windows-latest` | von GitHub gepflegt (nicht pinnbar) | PowerShell 7 und Windows PowerShell 5.1 vorinstalliert | Neues Runner-Image kann andere `pwsh`-Version bringen |
| PowerShell Gallery | — | Pester und PSScriptAnalyzer in den gepinnten Versionen | CI-Lauf rot (Exit 3 „Modul fehlt") |

Workflow: `.github/workflows/ci.yml`; Befehle: `tools/Invoke-QualityGate.ps1` (`CONVENTIONS.md` §9).

---

## Windows-Systemmodule / .NET (kein Install-Module nötig)

| Modul / Klasse | Zweck | Verfügbarkeit |
|-------|-------|--------------|
| `Microsoft.PowerShell.Utility` (`ConvertFrom-Json`, `Select-Object`, `Write-Progress`) | JSON-Konfiguration, Objektkopie, Fortschritt | Windows PowerShell 5.1 und PowerShell 7 |
| `System.Text.RegularExpressions.Regex` | Parsing und Ersetzung | .NET Framework 4.x / .NET (PS 7) |
| `System.Security.Cryptography.HMACSHA256` | Pseudonyme (seit I3, ADR-001) | .NET Framework 4.x / .NET (PS 7) |
| `System.Diagnostics.Stopwatch` | Laufzeitmessung im Parser | .NET Framework 4.x / .NET (PS 7) |

---

## Externe Binaries

| Binary | Pfad | Zweck | Fehler-Verhalten |
|--------|------|-------|-----------------|
| `fbtracemgr.exe` | `<Firebird.FirebirdPath>\fbtracemgr.exe` aus `config.json` (Vorlage: Firebird-5.0-Installationsordner) | Trace-Session starten (`-START -CONFIG`) und stoppen (`-STOP -ID`) über den Service-Manager | Keine Vorabprüfung; fehlt das Binary, bricht der Aufruf mit PowerShell-Fehler ab, Exit-Code nicht definiert (TODO I5) |

Seit I5: Pfad per `Join-Path`, Existenz vor dem ersten Aufruf geprüft (Exit 2), Exit-Code jedes Aufrufs ausgewertet
(Exit 5); Anmeldung per `-FETCH_PASSWORD`/`-TRUSTED`, `-ROLE`, Sitzungsname per `-NAME` (ADR-002).

---

## Externe Services / APIs

| Service | URL / Endpunkt | Zweck | Fallback bei Ausfall |
|---------|---------------|-------|---------------------|
| Firebird Services API (Service-Manager) | lokal `service_mgr` | Trace-Sessions verwalten | keiner; Fehlermeldung von `fbtracemgr` (stdout geht beim Start in die Trace-Datei, stderr auf die Konsole — Kanal der Fehlermeldungen ungeprüft) |

Parser und Pseudonymisierer arbeiten rein lokal auf Dateien bzw. Objekten. Eine Weitergabe an externe
Analysedienste ist kein Teil der Skripte (`architecture/OVERVIEW.md` → Scope-Grenzen). Credentials für den
Service-Manager: `security/AUTHENTICATION.md`.

---

## Systemabhängigkeiten

| Ressource | Mindestversion / Pfad | Zweck |
|-----------|----------------------|-------|
| Windows | Windows mit Windows PowerShell 5.1 oder PowerShell 7 | Laufzeit; Trace-Skripte nutzen Windows-Pfade (`E:\`) |
| PowerShell | ≥ 5.1 (nicht deklariert; Code nutzt `::new()`, `[ordered]`, `[CmdletBinding()]`) | Sprache; ein `#Requires -Version 5.1` fehlt (BACKLOG) |
| Firebird-Server | Trace-Format ab Firebird 3 (Zeitstempel `…T…ffff`); Vorlage: Firebird 4.0 | Quelle der Trace-Logs |
| Ausgabeordner | `OutputDirectory` in `config.json` (seit I5) | Ablage der Trace-Ausgabe (`trace_output_*.log`) — muss existieren und genug Platz haben |
| PowerShell 7.4+ | nur für die Trace-Skripte (`#Requires -Version 7.4`, ADR-002) | byte-genaue Umleitung der `fbtracemgr`-Ausgabe |

---

## Upgrade-Hinweise

- **PowerShell 7:** 7.4 und 7.5 erreichen laut Microsoft-Lebenszyklus am 2026-11-10 das Supportende; 7.6 ist die
  aktuelle LTS (`security/DEPENDENCY_AUDIT.md`). Parser und Pseudonymisierer müssen unter 5.1 lauffähig bleiben (CI-Job);
  die Trace-Skripte brauchen 7.4+.
- **Firebird:** Das Trace-Ausgabeformat kann sich zwischen Hauptversionen ändern (Zeitstempel, Verbindungszeile) —
  nach einem Server-Upgrade Parser gegen eine neue synthetische/anonymisierte Probe prüfen.
- **`fbtracemgr`:** genutzt werden `-SE`, `-USER`, `-FETCH_PASSWORD`, `-TRUSTED`, `-ROLE`, `-START -NAME -CONFIG`, `-LIST`,
  `-STOP -ID` (Firebird 5.0.4, Entwurf des Owners mit echten Traces). Ausgabe von `-LIST` und Stopp-Bestätigung sind nur
  gegen ein Ersatzprogramm getestet — bei einem Server-Upgrade einmal von Hand prüfen.
- **Pester:** Wechsel 5.x → 6.x kann Test-Syntax brechen — Version pinnen und Wechsel als eigenes Inkrement.
