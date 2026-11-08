# Projekt-Layout – PSFirebirdTraceParser

Ordnerstruktur und Schichten-Modell. Das Projekt ist bewusst flach: vier eigenständige Skripte im Repo-Root,
die über die PowerShell-Pipeline kombiniert werden. Es gibt kein Modul und keine Unterordner für Quellcode.

Verbindet sich mit den Prinzipien [[SEPARATION_OF_CONCERNS]] und [[ORTHOGONALITY]].

---

## Schichten-Modell

```mermaid
flowchart TD
    P[Präsentation<br/>Skript-Parameter · Out-GridView / Export-Csv des Nutzers]
    A[Anwendung<br/>Show-TraceStructure.ps1 · Pseudonymize-FirebirdTrace.ps1<br/>trace_start.ps1 · trace_stop.ps1]
    D[Domäne<br/>Trace-Block-Objekt · Pseudonymisierungsregeln]
    I[Infrastruktur<br/>Dateisystem · config.json · fbtracemgr.exe]

    P --> A
    A --> D
    A --> I
```

**Regeln für Abhängigkeiten:**

- Pfeile zeigen erlaubte Aufrufrichtung (nur nach unten / nach innen).
- **Ist-Zustand:** Domäne und Anwendung sind je Skript nicht getrennt — Regex-Definitionen, Mapping und
  Ein-/Ausgabe stehen im selben Skriptkörper. Die Pester-Tests (seit I9) rufen die Skripte als Ganzes auf — mit
  synthetischen Fixture-Dateien bzw. Objekten; ein Schnitt der Logik in eigene Funktionsdateien war dafür bisher nicht nötig.
- Die Skripte rufen sich gegenseitig **nicht** auf; die Kopplung läuft ausschließlich über die Pipeline und die
  Property-Namen der Trace-Objekte (`features/TRACE_PARSING.md`).
- **Composition Root:** Der Nutzer bzw. die Pipeline-Zeile (`.\Show-TraceStructure.ps1 … | .\Pseudonymize-FirebirdTrace.ps1 …`).

---

## Ist-Layout

```
PSFirebirdTraceParser/
├── Show-TraceStructure.ps1         # Parser
├── Pseudonymize-FirebirdTrace.ps1  # Pseudonymisierer (Pipeline-Filter)
├── trace_start.ps1                 # Trace-Session starten (PowerShell 7.4+)
├── trace_stop.ps1                  # Trace-Session stoppen
├── TraceCommon.ps1                 # seit I4/I5: gemeinsame Funktionen beider Trace-Skripte (Dot-Sourcing)
├── fbtrace50.conf                  # seit I4/I5: Trace-Konfiguration Firebird 4.0/5.0 (Vorlage)
├── fbtrace30.conf                  # ältere Trace-Konfiguration
├── config.sample.json              # Vorlage; lokale config.json ist gitignored
├── README.md / README.de.md        # Nutzerdoku (englisch/deutsch)
├── AGENTS.md / CLAUDE.md           # Einstieg für Agenten → docs/KICKOFF.md
├── tools/git-hooks/                # Interna-Hook (pre-commit, commit-msg)
├── tools/Invoke-QualityGate.ps1    # seit I14: Linter und Tests, lokal und in CI gleich
├── PSScriptAnalyzerSettings.psd1   # seit I14: Linter-Regeln für Gate 1
├── .github/workflows/ci.yml        # seit I14: CI bei Push und Pull Request (PS 7 und 5.1)
├── src/FirebirdTraceParser/        # seit I16: C#-Parser (Cmdlet ConvertFrom-FirebirdTrace, net8.0, ADR-003)
├── global.json                     # seit I16: Mindestversion des .NET SDK
├── bin/                            # Build-Ausgabe des C#-Parsers (gitignored, tools/Invoke-QualityGate.ps1 -Gate Build)
├── tests/                          # seit I9: Pester-Tests, je Skript eine *.Tests.ps1
│   ├── RequiredModules.psd1        # gepinnte Versionen von Pester und PSScriptAnalyzer
│   ├── TraceParity.ps1             # seit I16: strenger Vergleich der Objekte beider Parser (Dot-Sourcing)
│   └── fixtures/                   # synthetische Trace-Dateien mit fiktiven Daten
└── docs/                           # Dieses Doku-Set (docs/local/ gitignored)
```

## Regeln

- **Ein Skript pro Aufgabe** im Repo-Root; neue Aufgaben als neues Skript mit genehmigtem Verb (`CONVENTIONS.md` §2).
- **Gemeinsam genutzte Logik** der Trace-Skripte liegt in `TraceCommon.ps1` (Dot-Sourcing, kein Modul; ADR-002). Ein
  Modul (`.psm1` mit Manifest) erst, wenn Code außerhalb dieses Ordners die Funktionen braucht ([[DRY]] vs. [[YAGNI]]).
- **Tests parallel zur Quellstruktur:** `tests/<Skriptname>.Tests.ps1`; für den C#-Parser
  `tests/FirebirdTraceParser.*.Tests.ps1` (nur PowerShell 7).
- **C#-Parser** (seit I16): je Verantwortung eine Datei in `src/FirebirdTraceParser/` (Cmdlet, Stück-Schleife,
  Block-Parser, Regex, Feldliste). Er überträgt `Show-TraceStructure.ps1` wörtlich (ADR-003); Änderungen am Parsing in
  beiden Parsern im selben Commit.
- **Keine Laufzeitdaten im Repo:** Trace-Logs, Exporte und `config.json` bleiben außerhalb der Versionierung
  (`.gitignore`: `**/*.log`, `trace_output*`, `/*.csv`, `config*.json`).

---

## Schichtregel als ausführbarer Check

Derzeit nicht nötig: Es gibt keine Module und keine Imports zwischen den Skripten. Sobald ein `.psm1` oder
Dot-Sourcing eingeführt wird, kommt ein Pester-Test über den AST hinzu (Dot-Sourcing/`Import-Module` nur in
Richtung Infrastruktur → keine Rückwärtskanten), Teil von Gate 4 (`CONVENTIONS_COMMON.md` §5).

---

## Anti-Pattern

- **Skripte, die sich gegenseitig per Dateipfad aufrufen**, statt über die Pipeline zu kombinieren.
- **Ausgabe-Properties nebenbei umbenennen** — bricht Pseudonymisierer und Nutzer-Exporte still.
- **„Utils"-Skript als Sammelbecken** für Hilfsfunktionen ohne klare Aufgabe.

---

## Pflege

Trigger (siehe `KICKOFF.md` Phase 3a): neues Skript / Modul / Testordner oder Verschiebung von Logik zwischen
Skripten → diese Datei aktualisieren.
