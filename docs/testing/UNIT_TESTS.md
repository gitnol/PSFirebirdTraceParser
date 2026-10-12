# Unit Test Conventions – PSFirebirdTraceParser

**Stand I1:** Es gibt noch keine Tests. Das Grundgerüst entsteht in I2 (`docs/TODO.md`); diese Datei legt die
Regeln dafür fest.

Framework: Pester — Version zentral in `tests/RequiredModules.psd1` pinnen, damit lokale Setups und spätere CI auf
demselben Stand sind. Beim Init (2026-10-11) sind Pester 6.x und 5.x (gepflegt) verfügbar; die Wahl trifft I2 bewusst
(`security/DEPENDENCY_AUDIT.md`). Die Fallstricke in Abschnitt 7 beziehen sich auf Pester 5.

```powershell
# tests/RequiredModules.psd1 (Beispiel, Version in I2 festlegen)
@{ Pester = @{ RequiredVersion = '5.9.1' } }

# Lokales Setup / im CI-Workflow vor Test-Lauf
$req = Import-PowerShellDataFile ./tests/RequiredModules.psd1
Install-Module Pester -RequiredVersion $req.Pester.RequiredVersion `
    -Scope CurrentUser -Force -SkipPublisherCheck
```

---

## 1. Grundregeln

- Test-Dateien enden auf `.Tests.ps1`, liegen unter `tests/` und heißen wie das getestete Skript:
  ```
  tests/
  ├── Show-TraceStructure.Tests.ps1
  ├── Pseudonymize-FirebirdTrace.Tests.ps1
  ├── trace_stop.Tests.ps1
  └── fixtures/
      └── synthetic_trace.log      # nur fiktive Daten
  ```
- Jeder Test läuft vollständig isoliert — kein gemeinsamer State zwischen `It`-Blöcken
- `fbtracemgr` wird nie echt aufgerufen: Aufruf hinter einer Wrapper-Funktion kapseln und mocken
- Dateien nur in `TestDrive:` schreiben; niemals echte Trace-Dateien, echte Pfade (`E:\`) oder echte Credentials in Tests
- **Fixtures sind synthetisch:** erfundene Benutzer, Dokumentations-IP-Bereiche (`192.0.2.0/24`), fiktive Datenbankpfade —
  nie Auszüge aus echten Traces (öffentliches Repo, `CONVENTIONS.md` §6)

---

## 2. Pester-Installation und Ausführung

```powershell
# Alle Unit-Tests (Gate 4)
Invoke-Pester ./tests -ExcludeTag Integration -Output Detailed

# Einzelne Datei
Invoke-Pester ./tests/Pseudonymize-FirebirdTrace.Tests.ps1 -Output Detailed

# Mit Coverage
Invoke-Pester ./tests -CodeCoverage ./*.ps1 -CodeCoverageOutputFile coverage.xml
```

`coverage.xml` und `testResults.xml` nicht committen (bei Einführung in `.gitignore` aufnehmen).

---

## 3. Grundstruktur eines Tests

Die Skripte sind keine Funktionen, sondern werden als Skript mit Pipeline-Eingabe aufgerufen:

```powershell
BeforeAll {
    $script:Sut = Join-Path $PSScriptRoot '..' 'Pseudonymize-FirebirdTrace.ps1'
}

Describe 'Pseudonymize-FirebirdTrace' {
    Context 'Normalfall' {
        It 'ersetzt ClientIP durch ein 12-stelliges Pseudonym' {
            # Arrange
            $in = [pscustomobject]@{ ClientIP = '192.0.2.10' }

            # Act
            $result = $in | & $script:Sut

            # Assert
            $result.ClientIP | Should -Match '^[0-9a-f]{12}$'
            $result.ClientIP | Should -Not -Be '192.0.2.10'
        }

        It 'verändert das Eingabeobjekt nicht' {
            $in = [pscustomobject]@{ User = 'ALICE:NONE' }
            $null = $in | & $script:Sut
            $in.User | Should -Be 'ALICE:NONE'
        }
    }

    Context 'Fehlerfall' {
        It 'lehnt HashLength außerhalb 8..64 ab' {
            { [pscustomobject]@{} | & $script:Sut -HashLength 65 } | Should -Throw
        }
    }
}
```

`Join-Path` mit drei Argumenten braucht PowerShell 7; für 5.1 verschachteln.

---

## 4. Mock-Pattern: Externe Calls

`fbtracemgr` ist ein natives Programm und lässt sich nicht direkt mocken. Deshalb ab I5 eine Wrapper-Funktion
(z. B. `Invoke-FbTraceManager`) einführen und im Test ersetzen:

```powershell
Describe 'trace_stop' {
    BeforeEach {
        Mock Invoke-FbTraceManager { $global:LASTEXITCODE = 0 }
    }

    It 'stoppt die Session aus der Kopfzeile' {
        Set-Content -Path TestDrive:/trace_output_20260101_000000.log -Value 'Trace session ID 7 started'
        # … Skript mit TestDrive-Ausgabeverzeichnis aufrufen (konfigurierbar ab I5) …
        Should -Invoke Invoke-FbTraceManager -Times 1 -Exactly -ParameterFilter { $Arguments -contains '7' }
    }
}
```

---

## 5. Was wird getestet

- **Parser:** jede Property aus `features/TRACE_PARSING.md` mit exaktem Wert aus der synthetischen Fixture; Blöcke ohne
  SQL; abweichende Verbindungszeilen (K3); leere Datei; fehlende Datei
- **Pseudonymisierer:** jede Zeile der Feldabdeckung in `features/PSEUDONYMIZATION.md`; Original unverändert;
  Determinismus; `-AnalyzeOnly` gibt keine Trace-Objekte aus
- **Trace-Skripte:** Exit-Codes 1–4 (`architecture/ERROR_HANDLING.md`); Passwort taucht in keiner Ausgabe auf
- **Repo-Hygiene:** `config.json` ist nicht getrackt (`CONVENTIONS.md` 6.1.1)
- **Edge Cases:** leeres Array, `$null`-Properties, sehr lange SQL-Texte, Sonderzeichen und `''` in Literalen

---

## 6. Pester-Konfiguration (optional, `tests/pester.config.ps1`)

```powershell
$config = New-PesterConfiguration
$config.Run.Path = './tests'
$config.Filter.ExcludeTag = 'Integration'
$config.Output.Verbosity = 'Detailed'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = './*.ps1'

Invoke-Pester -Configuration $config
```

Ein Coverage-Ziel wird erst festgelegt, wenn Charakterisierungstests den Ist-Stand abdecken (dann als Floor, nur anheben).

---

## 7. Pester-5-Fallstricke (häufige Ursachen für „klappt lokal nicht" / „klappt in CI nicht")

Sammlung von Stolpersteinen, die sonst pro Projekt neu entdeckt werden. Quelle:
gelernte Lessons aus realen PowerShell-Modul-Projekten.

### 7.1 `BeforeEach`/`AfterEach` brauchen `Describe`/`Context`-Scope
Top-Level-`AfterEach` (direkt im Skript, außerhalb eines `Describe`) wirft in
Pester 5: **„Each test Teardown is not supported in root (directly in the block
container)"**. Cleanup-Logik immer **innerhalb** des Describe-Blocks platzieren,
in dem sie greift.

### 7.3 Pester-5-Coverage-API: `CommandsExecuted` + `CommandsMissed`
`$result.CodeCoverage.CommandsAnalyzed` ist in Pester 5 **`$null`**. Per-File-
Coverage rechnet man auf der Vereinigung von `CommandsExecuted` und
`CommandsMissed`, üblicherweise via `Group-Object File`:

```powershell
$all = @($cov.CommandsExecuted) + @($cov.CommandsMissed)
$all | Group-Object File | ForEach-Object {
    $exec = ($_.Group | Where-Object { $_ -in $cov.CommandsExecuted }).Count
    [pscustomobject]@{ File = $_.Name; Coverage = [math]::Round(100*$exec/$_.Count,1) }
}
```

### 7.5 `Should -BeOfType [object[]]` via Pipeline prüft Element-Typen
`$array | Should -BeOfType [object[]]` testet **jedes Element** gegen `object[]`,
nicht die Collection. Für „ist das ein Array?"-Checks:
```powershell
($value -is [Array]) | Should -BeTrue
```
ohne Pipeline.

### 7.6 PowerShell-Dateien mit Nicht-ASCII brauchen UTF-8 **mit BOM** — oder besser: ASCII bleiben
Sonst löst PSScriptAnalyzer `PSUseBOMForUnicodeEncodedFile` aus, und CI mit
`failOnWarnings: true` bricht ab. Klassische Stolper-Quellen in `.ps1`-Code:

- **Umlaute in Comments / Strings** (`Verfügbar`, `Größe`, …) — typischerweise
  unvermeidbar in deutschen Test-Dateien.
- **Em-dash / En-dash** (`—` U+2014, `–` U+2013) in Comment-based Help. Auf
  englischer Tastatur leicht aus Autokorrektur reingerutscht; PSSA flaggt es
  in `.ps1` genauso wie einen Umlaut.

Im **Test-File** (mit deutschen `It`-Strings) ist BOM die richtige Lösung:

```powershell
$utf8bom = [System.Text.UTF8Encoding]::new($true)
[System.IO.File]::WriteAllText($path, [System.IO.File]::ReadAllText($path), $utf8bom)
```

In **Module-Source** (`Public/*.ps1`, `Private/*.ps1`) ist die *bessere* Lösung:
**bei ASCII bleiben** (em-dash → `--`, Umlaute vermeiden). BOM-Pflicht verkompliziert
Tools/Heredocs/Datei-Vergleiche und sollte sich auf Test-Files mit echten
Lokalisierungs-Strings beschränken.
Festgelegt ist diese Ausnahme von `CONVENTIONS_COMMON.md` §2 in `CONVENTIONS.md` §3.

### 7.7 PSGallery braucht TLS 1.2 — Windows PowerShell 5.1 startet mit TLS 1.0
Vor jedem `Install-Module` / `Find-Module` auf Desktop in CI-Schritten:
```powershell
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
```

### 7.8 `Install-Module -SkipPublisherCheck` für Pester 5.x
Windows PowerShell 5.1 liefert Pester 3.4.0 vorinstalliert; die Signatur-Publisher
unterscheiden sich von Pester 5. Ohne `-SkipPublisherCheck` schlägt der Install
fehl. Außerdem: nach Install **explizit** `Import-Module Pester -RequiredVersion 5.x.x -Force`,
sonst lädt PS 5.1 weiterhin die eingebaute 3.4.0.

### 7.9 PSSA-Suppress-Attribute in Test-Dateien brauchen einen `Param()`-Block
`[Diagnostics.CodeAnalysis.SuppressMessageAttribute(...)]` ohne nachfolgendes
`Param()` (oder ohne Funktion) wird von PSScriptAnalyzer ignoriert — das Finding
bleibt und CI bricht. In Pester-Test-Dateien ist der saubere Weg, einen leeren
`Param()`-Block am Datei-Anfang einzuziehen, an dem das Attribut hängt:

```powershell
# Häufiger Bedarf in Tests: Dummy-SecureString, der den interaktiven
# Get-Credential-Prompt unterdrückt. PSAvoidUsingConvertToSecureStringWithPlainText
# würde sonst als Error feuern.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
Param()

BeforeAll {
    $secure = ConvertTo-SecureString 'pw' -AsPlainText -Force
    $script:DummyCred = [pscredential]::new('dummy', $secure)
}
```

Gleiches Pattern für `PSAvoidUsingEmptyCatchBlock` etc., wenn ein bewusst leerer
`catch {}` semantisch korrekt ist (z.B. Test prüft Warnungen, der spätere `throw`
ist erwartet und uninteressant).

### 7.10 `SuppressMessageAttribute`-Argumente sind String-**Konstanten** — Single-Quote-Pflicht

Ein scheinbar harmloses Detail mit harten Konsequenzen: Argumente an
`SuppressMessageAttribute` (`category`, `checkId`, `justification`) müssen
**String-Konstanten** sein. Eine Double-Quote-Justification wie
`Justification = "...$global:Foo ist..."` wird vom PowerShell-Parser als
**String-Interpolation** gewertet und damit nicht als Konstante akzeptiert.
PSScriptAnalyzer bricht dann mit:

> All the arguments of the Suppress Message Attribute should be string constants.

und das Attribut **greift nicht** — die Finding bleibt, CI bricht.

**Fix:** in Suppress-Attribut-Strings immer Single-Quotes verwenden:

```powershell
# Falsch (Parser sieht Interpolation):
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "",
    Justification = "Zugriff auf $global:DefaultFooConnection ist API.")]

# Richtig (Single-Quote = echte Konstante):
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
    Justification = 'Zugriff auf die globale DefaultFooConnection ist Teil der API.')]
```

Die gleiche Falle gibt's bei `[Parameter(...)]`, `[ValidateSet(...)]` und allen
anderen PowerShell-Attributen — sobald `$` in einem Double-Quote-Argument
auftaucht, wird daraus eine Interpolation und das Attribut wird invalid.

---

## 8. TDD-Disziplin (Iterations-Log + Gate-Reihenfolge)

Pester-Idiome zur TDD-Disziplin aus `KICKOFF.md` Phase 2 #2 (Rot/Grün, Iterations-Log, Einsatzgrenze) und zur
Gate-Reihenfolge aus `CONVENTIONS_COMMON.md` §5 (PowerShell-Modul/-Script + Pester 5). Verwandte Prinzipien:
`principles/ADVOCATUS_DIABOLI.md`, `principles/CETERIS_PARIBUS.md`, `principles/VERIFY_BEFORE_CITE.md`,
`principles/YAGNI.md`.

### 8.1 Behaviorales Rot ist Pflicht (realen Pester-Output einfangen)

Ein neuer Test muss als **echter `Invoke-Pester`-Lauf** rot sein — wegen einer **scheiternden
Assertion** (`Should -Be …`), nicht nur weil die Funktion noch fehlt (`CommandNotFoundException`)
oder ein Symbol nicht existiert. Letzteres ist nur **strukturelles** Rot; erst behaviorales Rot
beweist, dass der Test *diskriminiert*. Den realen Output zitieren („`Expected 2, but got 3`"),
nie „der Test sollte fehlschlagen". Praxis: die Funktion zuerst als leere Hülle (oder mit
falschem Rückgabewert) anlegen, damit der Test bis zur **Assertion** läuft und dort rot wird.

### 8.2 Erster-Lauf-grün → STOPPEN (und falsch-grün)

Ist ein neuer Test beim ersten Lauf schon grün, ist er verdächtig (testet nichts ODER das
Verhalten existiert bereits) → anhalten und untersuchen. Gleiches gilt für **falsch-grün**:
eine Assertion wie `$result -ne $null` kann grün sein, obwohl sie nichts beweist — z.B. wenn ein
Nebeneffekt Output in die Pipeline leckt (siehe `CONVENTIONS.md` „Bare-Aufruf … Output-Stream").
Exakt prüfen (`Count -eq 1`, erwarteter Typ/Wert), nicht „irgendetwas kam zurück".

### 8.3 Gate-Reihenfolge pro Code-Inkrement (Definition of Done)

Reihenfolge nach `CONVENTIONS_COMMON.md` §5 (Gate 2 und 3 entfallen in diesem Stack), jede Stufe grün, bevor
committet wird:

1. **Gate 1 — Linter:** `Invoke-ScriptAnalyzer -Path <geänderte Dateien> -Severity Warning`.
   Projektweit bewusst akzeptierte Findings (dokumentieren, z.B. Ressourcen-Plurale bei
   `PSUseSingularNouns`) sind kein Stopp; neue Findings zuerst beheben.
2. **Gate 4 — Unit-Tests:** `Invoke-Pester tests/ -ExcludeTag Integration -Output Detailed` → 0 Failed (Integrationstests sind eigene Skripte oder tragen das Tag `Integration`).
3. **Integrationstests:** derzeit keine (kein Test gegen einen echten Firebird-Server). Werden sie eingeführt, die
   Stack-Vorlage `testing/INTEGRATION_TESTS.md` aus dem Template übernehmen (nicht-destruktiv by Default).

Zuordnung zur Marker-Kernmenge (`principles/VERTICAL_SLICE_FIRST.md`): Das Pester-Tag `Integration` steht in diesem
Stack für alles, was eine echte Instanz braucht — Kernmarker `integration` und `live` zusammen. Gate 4 schließt es aus;
ein eigenes Tag `Live` ist nicht nötig.

### 8.4 Iterations-Log

Format: `KICKOFF.md` Phase 2 #2; Gate-Zeile z. B. `Gate: PSScriptAnalyzer ✓  Pester 42 passed ✓`. In diesem
Stack steht pro TDD-Zyklus zusätzlich eine Kurzform im `CHANGELOG.md`-Eintrag: **Rot** (welche Assertion, realer
Output) → **Grün** (minimale Implementierung) → **Refactor**. Kausale Aussagen
(„Fix X behebt Fehler Y") nur unter **Ceteris Paribus** (eine Variable pro Lauf), sonst trägt
das Ergebnis keine Einzelursachen-Aussage.

### 8.5 Einsatzgrenze — was hier TDD-bar ist und was nicht

| Schicht | TDD-Disziplin | Verifikation |
|---|---|---|
| Deterministische Kern-Logik (Trace-Parsing, Pseudonymisierung, Konfig-Validierung) | **Ja** — Pester mit Fixture bzw. gemocktem `fbtracemgr`-Wrapper (siehe Abschnitt 4) | rot→grün, exakte Assertions |
| Echter Firebird-Service-Manager (`fbtracemgr -START/-STOP`) | Nein (extern) | manueller Lauf gegen eine Testinstanz, im Confidence-Block vermerken |
| Schreibende/destruktive Operationen | Nein | `-WhatIf`/`SupportsShouldProcess` + explizite Freigabe; im Confidence-Block als „nicht live geschrieben" markieren |

Praxis: Public-Funktionen so schneiden, dass die Logik gegen **einen einzigen gemockten
Transport-Wrapper** (den HTTP-/Plattform-Einstiegspunkt) unit-testbar ist — der Netz-/
Schreibteil bleibt den Integrationstests vorbehalten.

### 8.6 Mutationsprüfung in PowerShell sicher ausführen

Für Charakterisierungs- und Negativtests (sofort grün) ist die Mutationsprüfung der Diskriminierungsnachweis
(`KICKOFF.md` TDD-Startregel). PowerShell-spezifische Fallen:

- **`Invoke-Pester` nie im Prozess des Mutationsskripts:** Ein Skript hielt das Original in `$orig`, schrieb
  Mutanten nach `$p` und stellte im `finally` mit `WriteAllText($p, $orig)` wieder her — nach dem
  In-Prozess-Lauf zeigte `$p` auf die `Pester.ps1` der installierten Pester-Version, die damit überschrieben
  wurde (Pester für alle Projekte kaputt), und Mutanten blieben im Modul stehen. Pro Mutant
  `pwsh -NoProfile -File <runner.ps1>` starten; das Original mit `Copy-Item`/`cp` sichern und nach jedem
  Mutanten per `cmp`/Hash gegen die Kopie zurückprüfen.
- **`-WhatIf`-Mutanten sind oft äquivalent:** Ersetzt man `if ($PSCmdlet.ShouldProcess(...))` durch
  `if ($true)`, löscht `Remove-Item` trotzdem nichts, weil es `-WhatIf` über `$WhatIfPreference` erbt. Den
  Mutanten als äquivalent ausweisen; nur wo .NET-Methoden statt Cmdlets schreiben, ist die eigene Abfrage
  per Test absicherbar.
