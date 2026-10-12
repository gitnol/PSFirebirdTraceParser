# Coding Conventions – PSFirebirdTraceParser

Stack: Windows PowerShell 5.1 und PowerShell 7.x | keine PSGallery-Module zur Laufzeit | Windows mit lokaler
Firebird-Installation (nur für die Trace-Skripte)

> Gilt **zusammen mit** `docs/CONVENTIONS_COMMON.md` (stack-übergreifend: Commit-Format, Encoding,
> öffentliche Repos/Interna, Quality Gates, parallele Agenten). Diese Datei regelt die
> Stack-Spezifika und hat dort Vorrang.
>
> **Doku-Sprache:** `docs/` ist deutsch (`CONVENTIONS_COMMON.md` §3). Das Projekt ist öffentlich und
> zweisprachig: `README.md` (englisch, primär) und `README.de.md` (deutsch) werden **gemeinsam** gepflegt;
> Code-Kommentare und Comment-based Help bleiben englisch.
>
> **Stack-Zuschnitt:** Das Projekt ist ein interaktives Pipeline-Werkzeug (Skripte, kein Modul, kein Task
> Scheduler, keine REST-Clients). Regeln des Stacks `powershell-automation` zu Task Scheduler, Modul-Manifesten,
> REST/HATEOAS und SQL Server wurden beim Init gestrichen (Stack-Lücke in `docs/BACKLOG.md`).

---

## 1. Git & Versionierung

Commit-Format, Scope-Wahl, `git add`-Regeln und Zeilenenden: `docs/CONVENTIONS_COMMON.md` §1–§2;
Commit-Pflicht pro Inkrement: `docs/KICKOFF.md` Phase 3b. Stack-spezifisch nur:

- Scope-Beispiele: `fix(I2): numeric-literal-redaction`, `feat(parser): streaming-read`, `docs(readme): output-properties`
- **Zeilenenden:** auch `.ps1` mit LF (`.gitattributes: * text=auto eol=lf`). PowerShell liest LF problemlos; eine
  CRLF-Ausnahme wäre nur für Authenticode-signierte Skripte nötig — es gibt keine.
- Öffentliches Repository: Interna-Hook aktiv halten (`git config core.hooksPath tools/git-hooks`,
  `CONVENTIONS_COMMON.md` 3.1). Trace-Auszüge aus echten Systemen nie committen — auch nicht als Test-Fixture.

## 2. PowerShell Code-Richtlinien

- **CmdletBinding + Param:** Jede Funktion und jedes Script mit `[CmdletBinding()]` und `param()` Block.
  *Bestand:* nur `Pseudonymize-FirebirdTrace.ps1` erfüllt das; `Show-TraceStructure.ps1` hat `param()` ohne
  `[CmdletBinding()]`, die Trace-Skripte haben keinen `param()`-Block (TODO I5/I6).
- **Approved Verbs:** Nur [genehmigte PowerShell-Verben](https://docs.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands) für Skript- und Funktionsnamen
  (`Show-`, `Get-`, `Start-`, `Stop-` …). *Bestand:* `trace_start.ps1`/`trace_stop.ps1` folgen dem Schema nicht —
  Umbenennung nur zusammen mit README und Hinweistexten (BACKLOG).
- **Fehlerbehandlung:** `$ErrorActionPreference = 'Stop'` am Scriptbeginn. `try/catch` für alle externen Aufrufe
  (`fbtracemgr.exe`, Dateizugriffe). Kein leeres `catch {}` ohne Logging. *Bestand:* nirgends gesetzt (TODO I5).
- **Exit-Codes nur in Skripten, die als Prozess aufgerufen werden** (`trace_start.ps1`, `trace_stop.ps1`); Pipeline-Skripte
  (`Show-TraceStructure.ps1`, `Pseudonymize-FirebirdTrace.ps1`) werfen Fehler statt `exit` (sonst beendet `exit` die
  aufrufende Sitzung beim Dot-Sourcing). Tabelle: `architecture/ERROR_HANDLING.md`.
- **Eingabevalidierung:** `[ValidateNotNullOrEmpty()]`, `[ValidateRange()]`, `[ValidateSet()]` in `param()` Blöcken.
  Fail-Fast vor Business-Logik (Beispiel im Bestand: `-HashLength` mit `[ValidateRange(8, 64)]`).
- **Keine Magic Strings:** Konstanten als `$script:CONSTANT_NAME = ...` am Scriptbeginn (z. B. Pfad zu `fbtracemgr`,
  Ausgabeverzeichnis). *Bestand:* `E:\` fest im Code beider Trace-Skripte (TODO I5).
- **Regex-Objekte einmal bauen:** `[regex]::new(…, Compiled)` außerhalb der Schleife bzw. im `begin`-Block — wie im
  Bestand; neue Muster mit Beispielzeile aus einer **fiktiven** Trace im Kommentar dokumentieren.
- **Pipeline-Ausgabe ist das Ergebnis:** Statusmeldungen über `Write-Verbose`/`Write-Information`/`Write-Progress`,
  nie über den Output-Stream. `Write-Host` nur für interaktive Hinweise. *Bestand:* `Show-TraceStructure.ps1` nutzt
  `Write-Host` für Status (TODO I6).
- **Eingabeobjekte nicht mutieren:** Pipeline-Filter arbeiten auf einer Kopie (`$InputObject | Select-Object *`), wie
  `Pseudonymize-FirebirdTrace.ps1`.
- **Keine automatischen Variablen überschreiben** (`$matches`, `$input`, `$args`, `$_` …) — PSScriptAnalyzer-Regel
  `PSAvoidAssignmentToAutomaticVariable`. *Bestand:* `$matches` im `-AnalyzeOnly`-Zweig (KNOWN_ISSUES K6).
- **Bare-Aufruf einer wertrückgebenden Funktion leckt in den Output-Stream:** PowerShell
  schreibt **jeden** nicht zugewiesenen Ausdruck in die Pipeline. Wird eine Funktion, die
  einen Wert zurückgibt, nur zur Seitenwirkung/Validierung aufgerufen (typisch: ein
  Precondition-Guard, der das geprüfte Objekt zurückgibt), leckt deren Rückgabe in
  die Ausgabe der aufrufenden Funktion. Rückgabe explizit verwerfen:
  ```powershell
  $null = Assert-Precondition   # ✓ Rückgabe verworfen ( oder | Out-Null / [void](…) )
  Assert-Precondition           # ✗ Rückgabe leckt in den Output-Stream der Funktion
  ```
  Tests, die nur „Output ist nicht null" prüfen, **maskieren** diesen Bug — exakt prüfen (`Count`, erwarteter Typ/Wert).

## 3. Dateiorganisation

- **Einstiegspunkte:** je Aufgabe ein Skript im Repo-Root (`Show-TraceStructure.ps1`, `Pseudonymize-FirebirdTrace.ps1`,
  `trace_start.ps1`, `trace_stop.ps1`); Skripte sind über die Pipeline kombinierbar.
- **Funktionen:** im selben Skript bei < 300 Zeilen; darüber in `functions/` auslagern.
- **Module:** Wird Logik von mehr als einem Skript genutzt (z. B. Konfig-Laden in beiden Trace-Skripten), als `.psm1`
  auslagern; ein Modul-Manifest (`.psd1`) nennt `FunctionsToExport` dann **explizit**, nie `'*'`.
- **Encoding-Ausnahmen** (Vorrang vor `CONVENTIONS_COMMON.md` §2, sonst gilt UTF-8 ohne BOM):
  - **`.ps1`-Quellcode bleibt ASCII.** Ist Nicht-ASCII unvermeidbar (z. B. deutsche Meldungstexte), dann UTF-8
    **mit BOM** — Windows PowerShell 5.1 liest BOM-loses UTF-8 als ANSI und zeigt Umlaute falsch an.
    *Bestand:* `trace_start.ps1`/`trace_stop.ps1` enthalten Umlaute ohne BOM (KNOWN_ISSUES K5);
    `Show-TraceStructure.ps1` hat ein BOM, ist aber ASCII.
  - **Testdateien mit Nicht-ASCII-Zeichen** (deutsche `It`-Texte) als UTF-8 **mit BOM** — sonst meldet
    PSScriptAnalyzer `PSUseBOMForUnicodeEncodedFile`. Details: `testing/UNIT_TESTS.md` 7.6.
  - **Zeilenenden:** `.ps1`, `.psm1` und `.psd1` mit LF sind unkritisch (PowerShell liest beides), es gilt
    `CONVENTIONS_COMMON.md` §2. Ausnahme: Authenticode-signierte Dateien — die Signatur gilt für die Bytes, sie
    bleiben wie signiert (in `.gitattributes` als `binary`).

## 4. Prozessweite Side-Effects — Save/Restore-Pflicht

PowerShell-Skripte mutieren leicht **prozessweite** Zustände, die die gesamte Session überleben. Relevant für
dieses Projekt (Skripte werden interaktiv in der Nutzer-Session ausgeführt):

- `Set-Location` (CWD) ohne `Push-Location`/`Pop-Location`
- `$ErrorActionPreference`, `$ProgressPreference`, `$VerbosePreference` global statt lokal
- `$env:*` (z. B. falls künftig `ISC_USER`/`ISC_PASSWORD` für Firebird-Werkzeuge gesetzt würden — dann im `finally` entfernen)
- `Add-Type` für anonyme Typen (lassen sich nicht entfernen — beim zweiten Lauf nur über Typ-Existenz-Check schützen)

**Pflicht-Pattern:** vor der Mutation den alten Wert einmalig in einem skript-skopierten `$script:`-Slot sichern,
am Ende (`finally`) restaurieren. Mehrfach-Aufrufe nicht den bereits mutierten Wert sichern lassen (Flag-Guard).

```powershell
$oldEap = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Stop'
    # … Arbeit …
}
finally {
    $ErrorActionPreference = $oldEap
}
```

## 5. Pfade & Dateisystem

- **Pfade immer als `[System.IO.Path]`-Methoden** oder `Join-Path` — nie String-Konkatenation mit `\`
  (*Bestand:* `"$MyPfad\fbtracemgr"` in beiden Trace-Skripten, TODO I5).
- **`Test-Path` vor Zugriff:** Eingabedatei, `fbtracemgr.exe`, Trace-Konfiguration und Ausgabeverzeichnis vor Verwendung prüfen.
- **Große Eingabedateien:** Trace-Logs können mehrere GB groß sein — zeilenweise lesen (StreamReader) statt
  `Get-Content -Raw` (*Bestand:* `-Raw`, KNOWN_ISSUES K2).
- **Credentials niemals in `$env:`-Variablen oder Kommandozeilenargumenten ablegen**, wenn es eine Alternative gibt
  (`architecture/CREDENTIAL_STRATEGY.md`).

## 6. Security-Checkliste vor jedem Commit

- [ ] Keine Hardcoded-Credentials — ausschließlich über Credential Store / ACL-geschützte Datei (`architecture/CREDENTIAL_STRATEGY.md`)
- [ ] `config.json` und andere Konfigurationsdateien mit Credentials in `.gitignore` (Stand: `config*.json`, `/config.ps1`)
- [ ] Kein Passwort als Kommandozeilenargument an externe Programme (`fbtracemgr -PASS`) — *Bestand verletzt das, TODO I4*
- [ ] Kein `Invoke-Expression` mit nicht-validierten Strings (Command-Injection)
- [ ] Logging/Statusausgaben: keine Passwörter, keine Trace-Inhalte (SQL-Texte, Parameter) in Meldungen
- [ ] Test-Fixtures und Beispiele enthalten nur **fiktive** Trace-Daten (keine echten Benutzer, Hosts, IPs, Datenbankpfade)
- [ ] Änderungen am Pseudonymisierer: Feldabdeckung in `features/PSEUDONYMIZATION.md` nachgeführt; kein Feld fällt still in den Klartext zurück
- [ ] Prozessweite State-Mutationen (`$env:`, Preferences, `Set-Location`) haben Save/Restore (siehe Sektion 4)
- [ ] **Defense-in-Depth für Konfig-Credentials**: gitignore + Runtime-Existenz-Guard + Test, dass `config.json` nicht getrackt ist (siehe 6.1.1)

## 6.1 Sicherheits-Patterns (mit Code-Skeletten)

### 6.1.1 Defense-in-Depth für Konfig-Credentials (3 Schichten)

`config.json` enthält heute das Firebird-Passwort im Klartext (bis I4). Ein `.gitignore`-Eintrag allein reicht
nicht; drei Schichten zusammen machen versehentliche Commits praktisch unmöglich:

1. **Statisch (Prevention):** `.gitignore` enthält `config*.json` (mit Ausnahme `!/config.sample.json`) und ist vor
   dem Doku-Commit committet (siehe `BOOTSTRAP.md`).
2. **Runtime (Fail-Fast):** Die Trace-Skripte prüfen die Existenz **vor** dem Lesen und brechen mit klarer Meldung ab
   (Bestand: `exit 1` mit Hinweis „config.json fehlt").
3. **Regression (ab I2):** Pester-Test (Tag `Unit`) prüft `git ls-files`:
   ```powershell
   It 'config.json ist NICHT in git getrackt' {
       (& git ls-files 'config.json') | Should -BeNullOrEmpty
   }
   ```

---

## 7. Autonomes Arbeiten & Fehlerbehebung

- Bei Fehlern: nicht sofort abbrechen. `$Error[0]` und Stack-Trace lesen.
- Nur Dateien verändern, die für das aktuelle Inkrement relevant sind.
- Am Ende jedes Inkrements: `docs/TODO.md`, `docs/CHANGELOG.md`, `docs/STATE.md` aktualisieren.
- Echte Trace-Dateien, die ein Nutzer zur Fehlersuche bereitstellt, nur lokal lesen — nie in `docs/`, Tests,
  Commit-Messages oder Chat-Ausgaben zitieren (`security/DATA_HANDLING.md`).

---

## 8. Dokumentationspflichten (Trigger-Regeln)

### Neuer Parameter / Konfigurationsoption
→ `README.md` **und** `README.de.md` + `docs/features/` (+ `docs/architecture/CONFIGURATION.md` bei `config.json`-Schlüsseln)

### Neue oder umbenannte Ausgabe-Property des Parsers
→ `docs/features/TRACE_PARSING.md` (Feldliste) + `docs/features/PSEUDONYMIZATION.md` (Feldabdeckung) + beide READMEs

### Neue externe Abhängigkeit (Modul, Binary, API)
→ `docs/architecture/DEPENDENCIES.md`

### STATE.md (immer nach jedem Inkrement)
1. Freitext "Letztes abgeschlossenes Inkrement: …"
2. Tabelle: neue Zeile `| I# | Titel | Datum | Commit-Hash |`

---

## 9. Quality Gates — pre-commit (Definition of Done)

Für PowerShell greifen zwei der vier Gates der Definition of Done. **Stand I1: noch nicht eingerichtet** — Werkzeuge,
Settings-Datei und Tests entstehen in I2; bis dahin ist nur Gate 1 lokal ausführbar (ohne Settings-Datei).

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning                   # Gate 1 — Linter (PSScriptAnalyzer)
Invoke-Pester ./tests -ExcludeTag Integration -Output Detailed            # Gate 4 — Unit-Tests (Pester), ab I2
```

Ab I2 mit `-Settings ./PSScriptAnalyzerSettings.psd1`. Projekt-eigene pre-commit-Prüfungen gehören nach
`tools/git-hooks/pre-commit.local` (der Interna-Hook ruft sie auf, `CONVENTIONS_COMMON.md` 3.1).

Gate 2 (Formatter) und Gate 3 (statische Typanalyse) haben in PowerShell kein eigenständiges Standard-Werkzeug;
PSScriptAnalyzer-Regeln decken Stilfragen mit ab.
