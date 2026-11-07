# Feature: Trace-Parsing (`Show-TraceStructure.ps1`)

---

## Zweck

Zerlegt ein Firebird-Trace-Log in Blöcke (ein Block je Zeitstempel-Zeile) und gibt je Block ein
`PSCustomObject` mit Verbindungs-, Transaktions-, SQL- und Performance-Feldern aus.

---

## Technologie / Abhängigkeiten

- PowerShell 5.1 / 7, .NET-Regex (kompiliert), `Get-Content -Raw`
- Lokales Dateisystem (Trace-Datei); keine Module, kein Netz

---

## Parameter

| Parameter | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `-Path` | `[string]` | Ja (Position 0) | — | keine (nur `Test-Path` im Rumpf) | Pfad zur Trace-Datei |

Kein `-WhatIf` (das Skript schreibt nichts). Kein `[CmdletBinding()]` → `-Verbose` u. ä. wirken nicht (TODO I6).

---

## Ablauf (Ist)

1. Ganze Datei als ein String lesen (`Get-Content -Raw`).
2. Split vor jeder Zeile, die mit `JJJJ-MM-TTThh:mm:ss.ffff` beginnt; leere Teile und Teile ohne Zeitstempel verwerfen.
3. Je Block neun kompilierte Regex anwenden (Header, Datenbank/Verbindung, Anwendung, Transaktion, SQL, Parameter,
   Plan, Tabellenstatistik, Performance); fehlende Treffer lassen das Feld leer bzw. auf dem Default.
4. Alle Objekte in einer `List[PSObject]` sammeln und **am Ende** gesammelt zurückgeben (`return $results`).
5. Status über `Write-Host`, Fortschritt alle 5000 Blöcke über `Write-Progress`.

## Ausgabe-Vertrag (Properties, Reihenfolge wie im Code)

| Property | Typ | Default | Quelle im Block |
|---|---|---|---|
| `Timestamp` | string | `$null` | Zeitstempel der Kopfzeile (nicht als `[datetime]`) |
| `Action` | string | `$null` | Ereignisname der Kopfzeile (z. B. Statement-, Transaktions-, Verbindungsereignis); `FAILED …`/`UNAUTHORIZED …` vollständig (seit I10); bei `ERROR AT …`/`WARNING AT …` nur `ERROR`/`WARNING` |
| `ProcessID`, `SessionID` | string | `$null` | `(PID:Adresse)` der Kopfzeile; die Adresse ist plattformabhängig: Windows `000001A2B3C4D5E0`, Linux `0x7f3a1c2b4d10` (beide werden erkannt, unverändert übernommen) |
| `DatabasePath` | string | `$null` | Verbindungszeile, Pfad bis `.FDB`; jede Endung, jede Rolle, auch `<internal>` und Protokolle ohne Port (seit K3-Fix 2026-11-07) |
| `AttachID` | string | `$null` | `ATT_<n>` |
| `User` | string | `$null` | Benutzer **inklusive** `:NONE` (Rolle) |
| `ProtocolInfo` | string | `$null` | z. B. `TCPv4:<ip>/<port>` |
| `ClientIP`, `ClientPort` | string | `$null` | aus `ProtocolInfo` |
| `ApplicationPath`, `ApplicationPID` | string | `$null` | Zeile `<Laufwerk-/UNC-Pfad>:<pid>` |
| `TransactionID` | string | `$null` | `TRA_<n>` |
| `RootTxID` | string | `"NoTx"` | `INIT_<n>`, sonst `TransactionID` |
| `TransactionOptions` | string | `$null` | Optionen in der Transaktionszeile |
| `Params` | string | `$null` | zusammenhängende `paramN = …`-Zeilen |
| `SqlStatement` | string | `$null` | Text nach `Statement <n>:` und Trennlinie bis Plan/Parameter/Statistik |
| `SqlPlan` | string | `$null` | zusammenhängende `PLAN …`-Zeilen |
| `TableStats` | string | `$null` | Tabellenstatistik ab `Table … Natural`, **ungetrimmt** (Spaltenausrichtung) |
| `ErrorSource` | string | `$null` | Komponente aus `ERROR AT <Komponente>` bzw. `WARNING AT …` (seit I10) |
| `ErrorCodes` | string | `$null` | Fehlercodes der Zeilen `%9lu : <Text>`, mit `, ` verbunden (nur bei `ERROR`/`WARNING`) |
| `ErrorMessages` | string | `$null` | Fehlertexte derselben Zeilen, mit ` \| ` verbunden; können Werte enthalten (`Problematic key value is (…)`) |
| `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks` | int | `0` | Performance-Zeile `<n> ms, … read(s), … write(s), … fetch(es), … mark(s)` |

Die Property-Namen sind Eingabe von `Pseudonymize-FirebirdTrace.ps1` und von Nutzer-Exporten — Änderungen nur
gemeinsam (`CONVENTIONS.md` §8). Die READMEs nennen teils abweichende Namen (K1).

---

## Kritische Patterns

- Regex-Objekte einmal vor der Schleife bauen (`Compiled`) — nicht pro Block.
- Fehlende Felder sind kein Fehler: ein Objekt wird immer ausgegeben (auch für unbekannte Ereignisarten).
- `TableStats` bewusst nicht trimmen.

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| Speicherbedarf ein Vielfaches der Dateigröße; Ausgabe erst nach komplettem Parsen | `Get-Content -Raw`, Split-Array, `return $results` (K2) | I6 |
| Verbindungsfelder leer bei Rolle ≠ `NONE`, kleingeschriebener Endung `.fdb` oder Nicht-TCP-Protokollen | Regex `rxDb` (K3) | I6 |
| `Timestamp` ist Text, kein `[datetime]` | Regex-Gruppe ohne Konvertierung | Akzeptiert (BACKLOG) |
| Statusmeldungen über `Write-Host`, Meldung „Legacy Mode" | historisch | I6 |

---

## Bekannte Fallstricke

- README beschreibt „line-by-line (low memory)" — gilt für den aktuellen Code nicht (K1/K2).
- Ein Block ohne `Statement`-Abschnitt (z. B. Verbindungs- oder Transaktionsereignis) liefert `SqlStatement = $null` — beim Gruppieren berücksichtigen.

---

## Teststrategie

- Zugehörige Testdatei: `tests/Show-TraceStructure.Tests.ps1` (I6)
- Pester-Beschreibung: `Describe 'Show-TraceStructure' { ... }`
- Fixture: synthetische Trace-Datei mit **fiktiven** Werten unter `tests/fixtures/` (je Ereignisart mindestens ein Block)
- Kritische Testfälle: jede Property aus der Tabelle oben mit exaktem Wert; Block ohne SQL; Rolle ≠ `NONE`;
  fehlende Datei → Fehler; Zähler > Int32; leere Datei → keine Objekte
