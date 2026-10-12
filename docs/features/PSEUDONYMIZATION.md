# Feature: Pseudonymisierung (`Pseudonymize-FirebirdTrace.ps1`)

---

## Zweck

Ersetzt in den Objekten von `Show-TraceStructure.ps1` identifizierende Werte durch kurze Hash-Pseudonyme, damit
Trace-Daten für externe Analysen weitergegeben werden können; `-AnalyzeOnly` zeigt vorab, was ersetzt würde.

---

## Technologie / Abhängigkeiten

- PowerShell 5.1 / 7, `System.Security.Cryptography.SHA256`, .NET-Regex
- Eingabe ausschließlich über die Pipeline (`ValueFromPipeline`); keine Dateien, kein Netz

---

## Parameter

| Parameter | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `-InputObject` | `[PSObject]` | über Pipeline | — | — | Trace-Objekt aus `Show-TraceStructure.ps1` |
| `-SensitiveKeywords` | `[string[]]` | Nein | leer | — | Begriffe (case-insensitiv, Teilstring); Treffer im Literal → Literal pseudonymisieren; Treffer im Statement → letzte WHERE/HAVING-Klausel komplett ersetzen |
| `-RedactLiterals` | Switch | Nein | `$false` | — | alle String-Literale mit ≥ 2 Zeichen (ohne `%`) pseudonymisieren |
| `-AnalyzeOnly` | Switch | Nein | `$false` | — | keine Objekte ausgeben, nur Bericht (Top 50 je Kategorie) |
| `-HashLength` | `[int]` | Nein | `12` | `[ValidateRange(8, 64)]` | Länge des hexadezimalen Pseudonyms |

---

## Feldabdeckung (Ist, Init 2026-10-11)

| Property | Behandlung | Bewertung |
|---|---|---|
| `User` | SHA-256-Pseudonym (inkl. `:NONE`) | umkehrbar per Wörterbuch bekannter Benutzer (Bedrohung 2) |
| `ClientIP` und IP in `ProtocolInfo` | SHA-256-Pseudonym | IPv4-Raum vollständig durchrechenbar (Bedrohung 2) |
| `ApplicationPath` | SHA-256-Pseudonym | ok (Pfade enthalten oft Windows-Benutzernamen) |
| `Params` | Werte in doppelten Anführungszeichen → Pseudonym | Werte ohne Anführungszeichen bleiben stehen — gegen echtes Trace-Format zu prüfen (I2) |
| `SqlStatement` | String-Literale `'…'` nur bei `-RedactLiterals` bzw. Keyword-Treffer; bei Keyword-Treffer zusätzlich letzte WHERE/HAVING-Klausel → `<REDACTED_CLAUSE:…>` | **numerische Literale bleiben Klartext**; frühere WHERE-Klauseln (Unterabfragen, UNION) bleiben stehen (I2) |
| `DatabasePath` | **unverändert** | Server-/Datenbank-/Kundennamen im Klartext (I2) |
| `ClientPort`, `ProcessID`, `SessionID`, `AttachID`, `TransactionID`, `RootTxID`, `ApplicationPID` | unverändert | technische IDs; erlauben Verknüpfung, aber keine direkte Identifikation |
| `SqlPlan`, `TableStats` | unverändert | Tabellen-/Indexnamen (Schema-Interna) im Klartext — Entscheidung in I2 |
| `Timestamp`, `Action`, `TransactionOptions`, Zähler | unverändert | Analysezweck |

Ohne Schalter werden String-Literale **nicht** pseudonymisiert — nur `User`, IP, `ApplicationPath` und `Params`.

**Beim Init nachgeprüft** (2026-10-11, PowerShell 7.6, Aufruf mit einem fiktiven Objekt, kein echter Trace):
`-RedactLiterals` ließ `WHERE ID = 4711` und `DatabasePath` im Klartext; `ClientIP` ergab exakt die ersten 12 Hex-Zeichen
von SHA-256 des Klartexts (also per Vorausberechnung umkehrbar); das Eingabeobjekt blieb unverändert. Die
Bulk-Redaktion greift nur, wenn das Schlüsselwort **nach** der Literal-Ersetzung noch im Statement steht (z. B. als
Tabellenname) — steht es nur in einem Literal, wird nur das Literal ersetzt. Greift sie, ersetzt sie alles nach dem
**letzten** `WHERE` (inklusive `ORDER BY`); frühere Bedingungen (`WHERE ID = 4711 UNION …`) bleiben stehen.

---

## Kritische Patterns

- Arbeitet auf einer Kopie (`$InputObject | Select-Object *`) — das Original darf nie verändert werden.
- Gleiches Eingabewort → gleiches Pseudonym (deterministisch, ungesalzen) — ermöglicht Gruppieren, ermöglicht aber auch Wörterbuchangriffe.
- Das Ergebnis bleibt personenbezogen (`security/DATA_HANDLING.md`); README warnt ausdrücklich vor Wörterbuchangriffen.

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| Numerische SQL-Literale, `DatabasePath`, `SqlPlan`/`TableStats` im Klartext | nur `'…'`-Literale und vier Felder werden behandelt | I2 |
| Bulk-Redaktion erfasst nur die letzte WHERE/HAVING-Klausel | gieriges Muster `.*` vor dem letzten `where`/`having` im Ersetzungs-Regex | I2 |
| Ungesalzener, gekürzter SHA-256 | kein geheimer Schlüssel | I3 |
| `$matches` (automatische Variable) wird überschrieben | Variablenname im `-AnalyzeOnly`-Zweig (K6) | I2 |

---

## Bekannte Fallstricke

- `-SensitiveKeywords` ist eine Teilstring-Suche: kurze Begriffe treffen sehr viele Statements und ersetzen ganze Klauseln.
- `-AnalyzeOnly` gibt Klartext-Literale und -Klauseln auf der Konsole aus — Bildschirmfreigaben/Mitschnitte vermeiden.
- Die Ausgabe ist kein Trace-Rohformat mehr; Dienste, die Original-Trace-Dateien erwarten, können sie nicht verarbeiten.

---

## Teststrategie

- Zugehörige Testdatei: `tests/Pseudonymize-FirebirdTrace.Tests.ps1` (I2)
- Pester-Beschreibung: `Describe 'Pseudonymize-FirebirdTrace' { ... }`
- Eingaben als `[pscustomobject]` im Test gebaut (fiktive Werte), kein Fixture-File nötig
- Kritische Testfälle: Original bleibt unverändert; jede Zeile der Feldabdeckung mit exaktem Erwartungswert;
  `-AnalyzeOnly` gibt keine Trace-Objekte aus; gleicher Wert → gleiches Pseudonym; `-HashLength` 8/64/65
