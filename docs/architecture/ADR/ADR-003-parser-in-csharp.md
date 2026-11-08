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

**Korrektur des Owners (2026-11-08, gleicher Tag): Priorität ist PowerShell 7.** Windows PowerShell 5.1 ist für den
C#-Kern nicht Pflicht; dort bleibt der PowerShell-Parser als Rückfall.

Randbedingungen: Parser und Pseudonymisierer müssen weiter unter Windows PowerShell 5.1 (.NET Framework 4.8) und
PowerShell 7 laufen (`architecture/OVERVIEW.md`) — unter 5.1 mit der PowerShell-Engine. Die Ausgabe-Objekte sind Vertrag (`features/TRACE_PARSING.md`): Namen,
Reihenfolge und Typen der 46 Felder, `TableCounts` als `object[]` von Objekten, Warnungen und Verbose-Meldungen.

## 2. Betrachtete Alternativen

* **A — Binär-Cmdlet in einer Bibliothek für .NET 8 (`net8.0`)**, das `PSCustomObject` (`PSObject` mit `PSNoteProperty`)
  erzeugt und Warnungen, Verbose und Fortschritt über die Cmdlet-Methoden schreibt.
* **B — Statische C#-API mit eigener Klasse je Ereignis**, aufgerufen aus dem Skript. Eine Klasse hat Properties statt
  NoteProperties (`Get-Member`, `PSObject.TypeNames` und `Select-Object *` verhalten sich anders); Warnungen müssten über
  Rückruf oder Warteschlange zurück ins Skript.
* **C — `Add-Type` mit C#-Quelltext im Skript.** Übersetzt bei jedem neuen Prozess (Sekunden), unter 5.1 nur C# 5,
  ein Typ lässt sich in der Sitzung nicht ersetzen (`CONVENTIONS.md` §4).
* **D — .NET Standard 2.0** (lädt auch unter 5.1). Erst so angelegt, nach der Korrektur des Owners verworfen: Unter
  5.1 bleibt ohnehin die PowerShell-Engine; .NET Standard 2.0 sperrt neuere APIs (`Span`, Regex-Quellgenerator,
  Nullable-Annotationen der Laufzeit) und zieht das Paket `NETStandard.Library` mit.
* **E — `net10.0`** (Laufzeit der installierten PowerShell 7.6). Läuft nicht unter PowerShell 7.4/7.5 (.NET 8/9);
  `net8.0` ist das kleinste LTS-Ziel, das alle PowerShell-Versionen ab 7.4 laden.

## 3. Entscheidung

Wir nehmen **A**:

- Projekt `src/FirebirdTraceParser/` (`net8.0`: kleinstes LTS-Ziel für PowerShell 7.4+, geprüft: PowerShell 7.6.9
  läuft auf .NET 10.0.14 und lädt die DLL; Windows PowerShell 5.1 lädt sie nicht), einziges Paket `PowerShellStandard.Library` 5.1.1 nur zum
  Übersetzen (`PrivateAssets=all`); zur Laufzeit gilt das `System.Management.Automation` der aufrufenden PowerShell.
  Paketversionen fest über `packages.lock.json`, gebaut mit `RestoreLockedMode`.
- Cmdlet `ConvertFrom-FirebirdTrace -Path -MaxBlockLines -RegexTimeoutSeconds` (gleiche Prüfungen wie das Skript).
  Es gibt Objekt für Objekt aus (Streaming) und schreibt Warnungen und Verbose-Meldungen mit denselben Texten.
- Gebaut wird nach `bin/` im Repo (`tools/Invoke-QualityGate.ps1 -Gate Build`, in CI beide Jobs). `bin/` und `obj/`
  sind nicht versioniert; im Repo liegt nie ein Binary.
- **Gleichheit durch wörtliche Übertragung:** dieselben Regex-Muster und Optionen und dieselben .NET-Aufrufe wie im
  Skript, auch wo PowerShell kulturabhängig vergleicht (`IndexOf(string)`, `-eq`).
  **Hashtable-Schlüssel (gemessen I23, 2026-11-08):** `@{}` vergleicht unter PowerShell 7.6.9 mit `OrdinalIgnoreCase`
  (Reflection auf `_keycomparer`), unter Windows PowerShell 5.1.26100 mit `CultureAwareComparer`. Die erste Fassung
  (I17) nahm `CurrentCultureIgnoreCase` an, das war falsch für PowerShell 7. Folge: Das Kelvin-Zeichen U+212A und das
  Ångström-Zeichen U+212B sind mit der Kultur (de-DE) gleich K bzw. Å/å, mit Ordinal verschieden; ein Aktionsname
  mit diesen Zeichen (`\S+` im Kopf) wurde im C#-Parser mit dem ASCII-Namen zusammengezählt, im Skript nicht. C#
  nimmt jetzt `OrdinalIgnoreCase`; ein Paritätstest und eine Ratsche auf den Vergleicher halten das fest. Türkisches
  i, ß/ss und Vollbreiten-Zeichen sind mit beiden Vergleichern verschieden (kein Unterschied). Die übrigen Schlüssel
  (Transaktionsoptionen) sind ASCII ohne K und Å, dort gab es nie einen Unterschied. Zahlen, die nicht nur aus Ziffern bestehen, wandelt das Cmdlet wie PowerShell um (`LanguagePrimitives`).
  Da beide Parser in derselben Laufzeit laufen, nutzen sie dieselbe Regex-Engine.
- **Ratsche:** ein Pester-Paritätstest lässt beide Parser über alle Fixtures und erzeugte Grenzfälle laufen und
  vergleicht jedes Feld jedes Objekts (Wert, Typ, `$null` gegen leer) sowie Warnungen; jeder Unterschied ist rot. Fehlt
  die DLL, ist der Test rot, nicht übersprungen.
- **Begründung „Eigentümer: Priorität PowerShell 7":** C#-Engine nur unter PowerShell 7; unter Windows PowerShell 5.1
  wählt `-Engine Auto` die PowerShell-Engine. Der 5.1-CI-Job baut nichts und testet weiter die PowerShell-Engine; die
  Tests des C#-Parsers und die Paritätstests laufen nur unter PowerShell 7 (unter 5.1 übersprungen).
- `Show-TraceStructure.ps1` bekommt in I19 `-Engine Auto|PowerShell|CSharp` (Auto: C#, wenn PowerShell 7 läuft und die
  DLL gefunden wird).
  **Entscheidung I20 (Owner, 2026-11-08):** Der PowerShell-Parser bleibt — als Rückfall unter Windows PowerShell 5.1
  und ohne gebaute DLL sowie als Orakel der Paritätstests. Belege: erster CI-Lauf mit Build grün (beide Jobs,
  Lauf 42504200600), Parität auf 5 Fixtures, 10 Grenzfällen und einem echten Log ohne Unterschied. Neu bewertet wird,
  sobald 5.1 nicht mehr unterstützt werden soll; dann entfällt der Rückfall, und die Paritätstests brauchen ein
  anderes Orakel (z. B. eingefrorene Soll-Ausgaben).
- SDK: `global.json` verlangt mindestens 9.0.300 und nimmt die höchste installierte Hauptversion (`latestMajor`); CI
  baut mit .NET SDK 10 (LTS). Zur Laufzeit gilt die .NET-Version der aufrufenden PowerShell (7.6: .NET 10), nicht die
  Zielversion; das Supportende von .NET 8 am 2026-11-10 betrifft nur Nutzer, die noch PowerShell 7.4 einsetzen.

## 4. Begründung

- Nur A erzeugt echte `PSCustomObject` mit NoteProperties — dieselben Objekte wie heute; der Pseudonymisierer
  (`Select-Object *`) und Nutzer-Exporte sehen keinen Unterschied.
- Warnungen und Verbose laufen über die normalen Streams des Cmdlets und gehorchen `-WarningAction`/`-Verbose` des
  Skripts, ohne Rückrufe.
- Ein Ziel (`net8.0`) für alle PowerShell-7-Versionen hält Build, CI und Doku klein; 5.1 braucht keinen zweiten Build,
  weil dort die PowerShell-Engine bleibt (Owner: Priorität PowerShell 7).
- Wörtliches Übertragen statt „idiomatischem" C# macht die Gleichheit prüfbar: Eine Abweichung ist ein Fehler, keine
  Auslegungsfrage. Verbesserungen am Verhalten kommen erst nach I20, dann nur an einer Stelle.

## 5. Konsequenzen

* **Positiv:** Laufzeit und Speicher deutlich kleiner (Messung in I19); der Vertrag bleibt; Umstellung Schritt für
  Schritt (I16–I20) mit Paritätstest als Sicherung.
* **Negativ/Risiken:** Zwei Implementierungen bis I20 — jede Parser-Änderung muss in beiden gemacht werden (der
  Paritätstest erzwingt das). Neuer Build-Schritt mit .NET SDK und NuGet (Lieferkette: `security/DEPENDENCY_AUDIT.md`).
  Eine geladene DLL ist bis zum Ende des Prozesses gesperrt; ein Neubau braucht einen neuen PowerShell-Prozess. Nutzer
  ohne .NET SDK bekommen die DLL nur gebaut oder aus einem Release (Verteilung noch offen, I22). Unter Windows
  PowerShell 5.1 bleibt es bei der Laufzeit des PowerShell-Parsers; solange er Rückfall ist, bleiben beide Parser zu
  pflegen.
