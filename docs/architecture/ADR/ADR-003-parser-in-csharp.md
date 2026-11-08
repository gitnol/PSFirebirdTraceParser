# ADR-003: Parser in C# parallel zum PowerShell-Parser

**Status:** Accepted
**Datum:** 2026-11-08

## 1. Kontext & Problem

`Show-TraceStructure.ps1` liest Trace-Logs in PowerShell. Ein Versuch außerhalb des Repos (2026-11-07, nur
synthetische Daten) zeigte: Ein Parser in C# mit denselben Regex liefert dieselben Daten, ist etwa 30-mal schneller und
braucht ein Drittel bis ein Fünftel des Speichers. Große Logs (mehrere hundert MB) dauern in PowerShell Minuten.

**Entscheidung des Owners (2026-11-08):** Den Parser jetzt in C# neu bauen. Beide Parser laufen parallel und verhalten
sich immer gleich, bis C# den PowerShell-Parser ohne Änderung für Nutzer ersetzen kann; danach steuert PowerShell nur
noch den C#-Code. Die Qualitätsregeln werden dafür nicht gelockert.

Randbedingungen: Parser und Pseudonymisierer müssen unter Windows PowerShell 5.1 (.NET Framework 4.8) und PowerShell 7
laufen (`architecture/OVERVIEW.md`). Die Ausgabe-Objekte sind Vertrag (`features/TRACE_PARSING.md`): Namen,
Reihenfolge und Typen der 46 Felder, `TableCounts` als `object[]` von Objekten, Warnungen und Verbose-Meldungen.

## 2. Betrachtete Alternativen

* **A — Binär-Cmdlet in einer .NET-Standard-2.0-Bibliothek**, das `PSCustomObject` (`PSObject` mit `PSNoteProperty`)
  erzeugt und Warnungen, Verbose und Fortschritt über die Cmdlet-Methoden schreibt.
* **B — Statische C#-API mit eigener Klasse je Ereignis**, aufgerufen aus dem Skript. Eine Klasse hat Properties statt
  NoteProperties (`Get-Member`, `PSObject.TypeNames` und `Select-Object *` verhalten sich anders); Warnungen müssten über
  Rückruf oder Warteschlange zurück ins Skript.
* **C — `Add-Type` mit C#-Quelltext im Skript.** Übersetzt bei jedem neuen Prozess (Sekunden), unter 5.1 nur C# 5,
  ein Typ lässt sich in der Sitzung nicht ersetzen (`CONVENTIONS.md` §4).
* **D — Zwei Builds (`net48` und `net8.0`+).** Mehr Aufwand und zwei Binaries ohne Nutzen: .NET Standard 2.0 lädt in
  beiden Laufzeiten.

## 3. Entscheidung

Wir nehmen **A**:

- Projekt `src/FirebirdTraceParser/` (`netstandard2.0`), einziges Paket `PowerShellStandard.Library` 5.1.1 nur zum
  Übersetzen (`PrivateAssets=all`); zur Laufzeit gilt das `System.Management.Automation` der aufrufenden PowerShell.
  Paketversionen fest über `packages.lock.json`, gebaut mit `RestoreLockedMode`.
- Cmdlet `ConvertFrom-FirebirdTrace -Path -MaxBlockLines -RegexTimeoutSeconds` (gleiche Prüfungen wie das Skript).
  Es gibt Objekt für Objekt aus (Streaming) und schreibt Warnungen und Verbose-Meldungen mit denselben Texten.
- Gebaut wird nach `bin/` im Repo (`tools/Invoke-QualityGate.ps1 -Gate Build`, in CI beide Jobs). `bin/` und `obj/`
  sind nicht versioniert; im Repo liegt nie ein Binary.
- **Gleichheit durch wörtliche Übertragung:** dieselben Regex-Muster und Optionen und dieselben .NET-Aufrufe wie im
  Skript, auch wo PowerShell kulturabhängig vergleicht (`IndexOf(string)`, Hashtables ohne Groß-/Kleinschreibung,
  `-eq`). Zahlen, die nicht nur aus Ziffern bestehen, wandelt das Cmdlet wie PowerShell um (`LanguagePrimitives`).
  Da beide Parser in derselben Laufzeit laufen, nutzen sie dieselbe Regex-Engine.
- **Ratsche:** ein Pester-Paritätstest lässt beide Parser über alle Fixtures und erzeugte Grenzfälle laufen und
  vergleicht jedes Feld jedes Objekts (Wert, Typ, `$null` gegen leer) sowie Warnungen; jeder Unterschied ist rot. Fehlt
  die DLL, ist der Test rot, nicht übersprungen.
- `Show-TraceStructure.ps1` bekommt in I19 `-Engine Auto|PowerShell|CSharp` (Auto: C#, wenn die DLL gefunden wird).
  Ob der PowerShell-Parser danach als Fallback und Orakel bleibt oder entfällt, entscheidet I20 mit Belegen.
- SDK: `global.json` verlangt mindestens 9.0.300 und nimmt die höchste installierte Hauptversion (`latestMajor`); CI
  baut mit .NET SDK 10 (LTS). Das Ergebnis hängt nicht von der SDK-Version ab (Ziel .NET Standard 2.0).

## 4. Begründung

- Nur A erzeugt echte `PSCustomObject` mit NoteProperties — dieselben Objekte wie heute; der Pseudonymisierer
  (`Select-Object *`) und Nutzer-Exporte sehen keinen Unterschied.
- Warnungen und Verbose laufen über die normalen Streams des Cmdlets und gehorchen `-WarningAction`/`-Verbose` des
  Skripts, ohne Rückrufe.
- Eine DLL für beide Laufzeiten hält Build, CI und Doku klein.
- Wörtliches Übertragen statt „idiomatischem" C# macht die Gleichheit prüfbar: Eine Abweichung ist ein Fehler, keine
  Auslegungsfrage. Verbesserungen am Verhalten kommen erst nach I20, dann nur an einer Stelle.

## 5. Konsequenzen

* **Positiv:** Laufzeit und Speicher deutlich kleiner (Messung in I19); der Vertrag bleibt; Umstellung Schritt für
  Schritt (I16–I20) mit Paritätstest als Sicherung.
* **Negativ/Risiken:** Zwei Implementierungen bis I20 — jede Parser-Änderung muss in beiden gemacht werden (der
  Paritätstest erzwingt das). Neuer Build-Schritt mit .NET SDK und NuGet (Lieferkette: `security/DEPENDENCY_AUDIT.md`).
  Eine geladene DLL ist bis zum Ende des Prozesses gesperrt; ein Neubau braucht einen neuen PowerShell-Prozess. Nutzer
  ohne .NET SDK bekommen die DLL nur gebaut oder aus einem Release (Verteilung noch offen, I20).
