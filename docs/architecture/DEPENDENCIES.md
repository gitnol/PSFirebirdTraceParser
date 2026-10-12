# Externe Abhängigkeiten – PSFirebirdTraceParser

Bestand zum Init (2026-10-11), aus dem Code ermittelt. Es gibt keine Manifest-/Lock-Datei (`*.psd1`,
`RequiredModules`); Laufzeit-Abhängigkeiten sind nur PowerShell/.NET und — für die Trace-Skripte — eine
Firebird-Installation.

---

## PSGallery-Module (Install-Module)

**Laufzeit:** keine.

**Entwicklung (geplant ab I2, Versionen dann in `tests/RequiredModules.psd1` gepinnt):**

| Modul | Mindestversion | Zweck | Risiko bei Ausfall |
|-------|----------------|-------|-------------------|
| `Pester` | 5.x oder 6.x (Entscheidung in I2, `security/DEPENDENCY_AUDIT.md`) | Gate 4 — Unit-Tests | Kein Regressionsschutz; Laufzeit unberührt |
| `PSScriptAnalyzer` | aktuelle Version (Recherche 2026-10-11: 1.25.0) | Gate 1 — Linter | Kein Lint-Gate; Laufzeit unberührt |

**Installationsbefehl (Entwickler, einmalig):**
```powershell
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

# Installation prüfen
Get-Module -Name Pester, PSScriptAnalyzer -ListAvailable | Select-Object Name, Version, Path
```

`-Scope CurrentUser` genügt: Die Skripte laufen interaktiv unter dem angemeldeten Benutzer, nicht unter einem Dienstkonto.

---

## Windows-Systemmodule / .NET (kein Install-Module nötig)

| Modul / Klasse | Zweck | Verfügbarkeit |
|-------|-------|--------------|
| `Microsoft.PowerShell.Utility` (`ConvertFrom-Json`, `Select-Object`, `Write-Progress`) | JSON-Konfiguration, Objektkopie, Fortschritt | Windows PowerShell 5.1 und PowerShell 7 |
| `System.Text.RegularExpressions.Regex` | Parsing und Ersetzung | .NET Framework 4.x / .NET (PS 7) |
| `System.Security.Cryptography.SHA256` | Pseudonym-Hashes | .NET Framework 4.x / .NET (PS 7) |
| `System.Diagnostics.Stopwatch` | Laufzeitmessung im Parser | .NET Framework 4.x / .NET (PS 7) |

---

## Externe Binaries

| Binary | Pfad | Zweck | Fehler-Verhalten |
|--------|------|-------|-----------------|
| `fbtracemgr.exe` | `<Firebird.FirebirdPath>\fbtracemgr` aus `config.json` (Vorlage: Firebird-4.0-Installationsverzeichnis) | Trace-Session starten (`-START -CONFIG`) und stoppen (`-STOP -ID`) über den Service-Manager | Keine Vorabprüfung; fehlt das Binary, bricht der Aufruf mit PowerShell-Fehler ab, Exit-Code nicht definiert (TODO I5) |

Der Pfad wird per String-Konkatenation gebaut (`"$MyPfad\fbtracemgr"`), nicht als `$script:`-Konstante (TODO I5).

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
| Laufwerk `E:\` | fest im Code | Ablage der Trace-Ausgabe (`trace_output_*.log`) — muss existieren und genug Platz haben |

---

## Upgrade-Hinweise

- **PowerShell 7:** 7.4 und 7.5 erreichen laut Microsoft-Lebenszyklus am 2026-11-10 das Supportende; 7.6 ist die
  aktuelle LTS (`security/DEPENDENCY_AUDIT.md`). Skripte müssen unter 5.1 lauffähig bleiben.
- **Firebird:** Das Trace-Ausgabeformat kann sich zwischen Hauptversionen ändern (Zeitstempel, Verbindungszeile) —
  nach einem Server-Upgrade Parser gegen eine neue synthetische/anonymisierte Probe prüfen.
- **`fbtracemgr`:** Optionen (`-fetch`, `-trusted`) und Exit-Codes vor I4 gegen `fbtracemgr -?` der eingesetzten Version prüfen.
- **Pester:** Wechsel 5.x → 6.x kann Test-Syntax brechen — Version pinnen und Wechsel als eigenes Inkrement.
