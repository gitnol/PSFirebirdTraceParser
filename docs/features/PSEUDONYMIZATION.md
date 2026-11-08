# Feature: Pseudonymisierung (`Pseudonymize-FirebirdTrace.ps1`)

---

## Zweck

Ersetzt in den Objekten von `Show-TraceStructure.ps1` identifizierende Werte durch kurze Hash-Pseudonyme, damit
Trace-Daten für externe Analysen weitergegeben werden können; `-AnalyzeOnly` zeigt vorab, was ersetzt würde.

---

## Technologie / Abhängigkeiten

- PowerShell 5.1 / 7, `System.Security.Cryptography.HMACSHA256` (seit I3), .NET-Regex
- Eingabe ausschließlich über die Pipeline (`ValueFromPipeline`); keine Dateien, kein Netz

---

## Parameter

| Parameter | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `-InputObject` | `[PSObject]` | über Pipeline | — | — | Trace-Objekt aus `Show-TraceStructure.ps1` |
| `-SensitiveKeywords` | `[string[]]` | Nein | leer | — | Begriffe (case-insensitiv, Teilstring); Treffer im Literal → Literal pseudonymisieren; Treffer im Statement → letzte WHERE/HAVING-Klausel komplett ersetzen |
| `-RedactLiterals` | Switch | Nein | `$false` | — | alle nicht leeren String-Literale (reine `%` ausgenommen) und Zahlen im SQL pseudonymisieren (seit I2) |
| `-AnalyzeOnly` | Switch | Nein | `$false` | — | keine Objekte ausgeben, nur Bericht (Top 50 je Kategorie) |
| `-HashLength` | `[int]` | Nein | `12` | `[ValidateRange(8, 64)]` | Länge des hexadezimalen Pseudonyms |
| `-KeyFile` | `[string]` | Nein (empfohlen) | Zufallsschlüssel je Lauf (Warnung) | Base64, ≥ 32 Byte | geheimer HMAC-Schlüssel; fehlt die Datei, wird sie mit 32 Zufallsbytes angelegt (Rechte nur aktueller Benutzer) |
| `-MappingFile` | `[string]` | Nein | — | — | CSV `Pseudonym;Original` für den Verantwortlichen (Rechte nur aktueller Benutzer, meldet Kollisionen) |

---

## Feldabdeckung (Vertrag, Stand I11 2026-11-08)

Jedes Feld ist entschieden: pseudonymisiert oder begründet im Klartext. Neue Felder des Parsers müssen hier
eingetragen werden, bevor sie ausgeliefert werden.

| Property | Behandlung | Begründung / Restrisiko |
|---|---|---|
| `User` | Pseudonym (inkl. Rolle) | identifiziert Personen |
| `ClientIP` und IP in `ProtocolInfo` | Pseudonym; Protokoll und Port bleiben | identifiziert Rechner/Personen |
| `ApplicationPath` | Pseudonym | Pfade enthalten oft Windows-Benutzernamen |
| `DatabasePath` | Pseudonym (seit I2) | Server-, Ordner- und Kundennamen |
| `Params` | Werte in `"…"` → Pseudonym, Typ bleibt | Firebird schreibt jeden Wert in Anführungszeichen (`param%d = %s, "%s"`, TracePluginImpl.cpp 5.0.4) |
| `SqlStatement` | mit `-RedactLiterals`: alle nicht leeren Zeichenketten (auch Einzelzeichen, seit I2) und Zahlen (seit I2) → `<HASH:…>`; Ziffern in Bezeichnern bleiben; reine `%`-Muster bleiben. Mit `-SensitiveKeywords`: Literale mit Stichwort; steht das Stichwort außerhalb von Literalen, wird **alles ab der ersten** WHERE/HAVING-Klausel ersetzt (seit I2) | ohne Schalter Klartext — für Weitergabe immer `-RedactLiterals` |
| `ErrorMessages` | mit `-RedactLiterals`: Schlüsselwerte `("SPALTE" = wert)` und Zeichenketten → Pseudonym; Constraint-/Tabellennamen bleiben | andere Wertformen in Fehlertexten nicht abgedeckt |
| `SqlPlan`, `TableStats`, `TableCounts` (seit I11), Tabellen-/Indexnamen | Klartext (Entscheidung I2) | Schema-Namen sind keine Personendaten, aber Geschäftsinterna; für die Analyse (Index-Empfehlungen) nötig. `-SensitiveKeywords` verbirgt sie **nicht** (wirkt nur auf `SqlStatement`, geprüft 2026-11-08); wer Tabellennamen verbergen muss, lässt diese Felder vor der Weitergabe weg (`Select-Object -ExcludeProperty SqlPlan, TableStats, TableCounts`). `TableCounts` gibt der Pseudonymisierer als eigene Kopie aus, das Eingabeobjekt bleibt unverändert |
| `ServiceName`, `ServiceID`, `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` (seit I15) | Klartext | feste Dienstnamen von Firebird, technische Adresse und Transaktionszähler; Benutzer, IP und Programm der Dienstzeile laufen über die bestehenden Felder (Pseudonym). Die Schalterzeile mit Dateipfaden liest der Parser nicht |
| `ClientPort`, `ProcessID`, `SessionID`, `AttachID`, `TransactionID`, `RootTxID`, `ApplicationPID`, `ErrorSource`, `ErrorCodes` | Klartext | technische IDs/Codes; erlauben Verknüpfung innerhalb des Traces, keine direkte Identifikation |
| `Timestamp`, `Action`, `TransactionOptions`, Zähler | Klartext | Analysezweck |
| `RecordsFetched`, `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` (seit I11) | Klartext | Zähler und feste Firebird-Schlüsselwörter, Teile von `TransactionOptions`; keine Personendaten |

Hash-Verfahren seit I3: HMAC-SHA256 mit geheimem Schlüssel, gekürzt auf `-HashLength` (ADR-001). Ohne Schlüssel nicht vorausberechenbar;
mit Schlüssel prüfbar — Schlüssel und Zuordnungsdatei bleiben beim Verantwortlichen.

---

## Kritische Patterns

- Arbeitet auf einer Kopie (`$InputObject | Select-Object *`) — das Original darf nie verändert werden.
- Gleiches Eingabewort → gleiches Pseudonym bei gleichem Schlüssel — ermöglicht Gruppieren; Wörterbuchangriffe nur mit dem Schlüssel (ADR-001).
- Das Ergebnis bleibt personenbezogen (`security/DATA_HANDLING.md`); README warnt ausdrücklich vor Wörterbuchangriffen.

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| In `ErrorMessages` werden nur Schlüsselwerte (`("ID" = 42)`) und String-Literale gehasht, andere Wertformen nicht | Muster aus dem Firebird-Quellcode, kein echtes Log mit Fehlern (I10) | akzeptiert, bei echtem Beleg nachziehen |

---

## Bekannte Fallstricke

- `-SensitiveKeywords` ist eine Teilstring-Suche: kurze Begriffe treffen sehr viele Statements und ersetzen ganze Klauseln.
- `-AnalyzeOnly` gibt Klartext-Literale und -Klauseln auf der Konsole aus — Bildschirmfreigaben/Mitschnitte vermeiden.
- Die Ausgabe ist kein Trace-Rohformat mehr; Dienste, die Original-Trace-Dateien erwarten, können sie nicht verarbeiten.

---

## Teststrategie

- Zugehörige Testdatei: `tests/Pseudonymize-FirebirdTrace.Tests.ps1` (seit I10: Fehlertexte; übrige Felder folgen mit I2)
- Pester-Beschreibung: `Describe 'Pseudonymize-FirebirdTrace' { ... }`
- Eingaben als `[pscustomobject]` im Test gebaut (fiktive Werte), kein Fixture-File nötig
- Kritische Testfälle: Original bleibt unverändert; jede Zeile der Feldabdeckung mit exaktem Erwartungswert;
  `-AnalyzeOnly` gibt keine Trace-Objekte aus; gleicher Wert → gleiches Pseudonym; `-HashLength` 8/64/65
