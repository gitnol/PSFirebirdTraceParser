# Benutzerhandbuch – PSFirebirdTraceParser

Für Analystinnen und Analysten, die ein Firebird-Trace-Log auswerten: Trace einlesen, die Objekte lesen und
filtern, für eine Weitergabe pseudonymisieren und an den Report-Generator übergeben. Aufzeichnen und Einrichten
steht im [Adminhandbuch](ADMINHANDBUCH.md); die vollständige Feldliste in
[`features/TRACE_PARSING.md`](../features/TRACE_PARSING.md).

Alle Beispiele nutzen erfundene Namen und Werte (`SAMPLE.FDB`, `USER1`, Adressen aus `192.0.2.0/24`).

---

## 1. Was das Werkzeug macht

```
Trace-Log (Textdatei) ──► Show-TraceStructure.ps1 ──► Objekte (1 je Ereignis) ──► deine Auswertung
                                                      │
                                                      └─► Pseudonymize-FirebirdTrace.ps1 ──► Export zur Weitergabe
                                                      └─► New-TraceReport.ps1 (Report-Generator, Schwester-Repo)
```

* **`Show-TraceStructure.ps1`** liest die Trace-Datei in Stücken (Speicher bleibt begrenzt, auch bei Gigabyte-Dateien) und
  gibt je Ereignis ein `[PSCustomObject]` mit 46 Properties in die Pipeline.
* **`Pseudonymize-FirebirdTrace.ps1`** ersetzt identifizierende Werte durch Pseudonyme (Kapitel 6).
* Eine Auswertung im engeren Sinn (Diagramme, Empfehlungen) gehört **nicht** zu diesem Repository. Dafür gibt es den
  [firebird-trace-report-generator](https://github.com/gitnol/firebird-trace-report-generator) (Kapitel 7).

## 2. Voraussetzungen

* PowerShell 7.6 (empfohlen); der Parser läuft auch unter Windows PowerShell 5.1.
* Eine Trace-Datei, die ein Administrator aufgezeichnet hat (Firebird 4.0/5.0; Firebird 3 mit der älteren
  Vorlage `fbtrace30.conf`; das Format der Fixtures deckt auch einen Firebird-3-Kopf ab)
* Sonst nichts: keine Module, kein Netzwerk. Für die schnellere C#-Variante muss ein Administrator die DLL gebaut haben
  (Adminhandbuch, Kapitel 4); ohne sie läuft automatisch der PowerShell-Parser mit demselben Ergebnis.

Skripte, die aus dem Internet geladen wurden, müssen einmal entsperrt werden: `Get-ChildItem *.ps1 | Unblock-File`
(Adminhandbuch, Kapitel 3).

---

## 3. Erster Lauf

```powershell
# Im Ordner des Repositories
.\Show-TraceStructure.ps1 -Path C:\daten\trace.log -Verbose | Out-GridView
```

`-Verbose` zeigt, was passiert: welche Engine läuft (`Engine: CSharp` oder `Engine: PowerShell`), je Ereignisart eine Zeile
`Summary: <Action> = <Anzahl>`, die Anzahl der Warnungen und die Laufzeit (`Parsed <n> events in <s> seconds.`).

Wichtige Parameter:

| Parameter | Wirkung |
|---|---|
| `-Path` (Pflicht) | Trace-Datei |
| `-Engine Auto\|PowerShell\|CSharp` | `Auto` (Standard) nimmt unter PowerShell 7 den C#-Parser, wenn `FirebirdTraceParser.dll` neben dem Skript oder in `bin\` liegt; sonst den PowerShell-Parser. Beide liefern dieselben Objekte, Warnungen und Meldungen |
| `-MaxBlockLines` (Standard 100000) | Obergrenze Zeilen je Ereignis; längere Ereignisse werden gekürzt (Warnung) |
| `-RegexTimeoutSeconds` (Standard 2) | Zeitlimit je Feld; danach bleiben die übrigen Felder des Ereignisses leer (Warnung) |

Die Warnungen nennen die Zeilennummer und einen festen Text, nie Trace-Inhalt. Typische Fälle: `Unknown event …`, eine
nicht lesbare Kopfzeile, Text vor dem ersten Ereignis, ein gekürztes Ereignis.

**Große Dateien:** Das Skript gibt jedes Objekt sofort aus. Wer es in eine Variable sammelt (`$ev = … | …`), hält alle
Ereignisse im Speicher; für sehr große Dateien lieber direkt weiterreichen (`… | Export-Csv`, `… | ForEach-Object { … }`)
und Zwischenergebnisse (Zähler, Summen) mitführen.

---

## 4. Die Objekte lesen

Jedes Objekt entspricht einem Ereignis (einem Block der Trace-Datei). Es hat **immer alle 46 Properties**; nicht
zutreffende sind `$null`, Zähler `0`.

### 4.1 Die wichtigsten Felder

| Gruppe | Felder |
|---|---|
| Ereignis | `Timestamp` (**Text** `JJJJ-MM-TTThh:mm:ss.ffff`), `Action` (Ereignisart), `ProcessID`, `SessionID` |
| Verbindung | `AttachID` (nur die Nummer, ohne `ATT_`), `User` (mit Rolle: `USER1:NONE`), `ClientIP`, `ClientPort`, `ProtocolInfo`, `DatabasePath` |
| Programm | `ApplicationPath`, `ApplicationPID` |
| Transaktion | `TransactionID`, `RootTxID` (Ursprungstransaktion, `NoTx` ohne), `TransactionOptions` und davon abgeleitet `TxIsolation`, `TxReadMode`, `TxWaitMode`, `TxLockTimeout`, `TxAccessMode` |
| SQL | `SqlStatement`, `SqlPlan`, `Params` (`param0 = integer, "42"`) |
| Leistung | `DurationMs`, `Reads`, `Writes`, `Fetches`, `Marks`, `RecordsFetched` (gelieferte Zeilen; `Fetches` sind Seitenzugriffe) |
| Tabellenstatistik | `TableStats` (Text) und `TableCounts` (Liste, je Tabelle ein Objekt mit `Natural`, `Index`, `Update`, `Insert`, `Delete`, `Backout`, `Purge`, `Expunge`) |
| Fehler | `ErrorSource`, `ErrorCodes` (`a, b, c`), `ErrorMessages` (`x \| y \| z`) |
| Routinen | `RoutineType`, `RoutineName`, `TriggerTable`, `TriggerTime`, `TriggerEvent` |
| Sonstiges | `ConnectionDurationMs` (nur bei `DETACH_DATABASE`), `ServiceName`, `ServiceID`, `SweepOIT`, `SweepOAT`, `SweepOST`, `SweepNext` |

### 4.2 Welche Felder bei welchem Ereignis gefüllt sind

Nicht jedes Ereignis hat jedes Feld. Die Kurzfassung:

| Ereignis (`Action`) | Was Sie erwarten dürfen |
|---|---|
| `EXECUTE_STATEMENT_FINISH` | SQL, Plan, Parameter, Tabellenstatistik, Leistung, Transaktion, Verbindung |
| `EXECUTE_PROCEDURE_FINISH`, `…FUNCTION…`, `…TRIGGER…` | Routinenname, Parameter, Leistung; **kein** `SqlStatement` |
| `START_/COMMIT_/ROLLBACK_TRANSACTION`, `COMMIT_RETAINING` | Transaktion, Verbindung; bei Ende zusätzlich `Fetches`, `Marks` (`Writes`) |
| `ATTACH_DATABASE`, `DETACH_DATABASE` | Verbindung, Programm; beim Detach `ConnectionDurationMs` |
| `ERROR`, `WARNING` | Verbindung, Fehlerquelle, Fehlercodes, Fehlermeldungen; **kein** SQL, **keine** Transaktion |
| `FAILED EXECUTE_STATEMENT_FINISH` | SQL und Parameter, aber **kein** Fehlertext |
| `*_SERVICE`, `SWEEP_*` | Dienst- bzw. Sweep-Felder |

Die vollständige Tabelle (mit allen Ausnahmen) steht in `features/TRACE_PARSING.md` → „Felder je Ereignistyp“. Ob ein
Ereignis überhaupt im Log vorkommt, entscheidet die Trace-Konfiguration: Prozeduren, Funktionen und Trigger erscheinen nur,
wenn der Administrator `log_procedure_finish` und Verwandte eingeschaltet hat (Adminhandbuch, Kapitel 5).

---

## 5. Auswertungen in PowerShell

Die Beispiele laufen mit der Pipeline auf `$ev` (Ereignisse in einer Variable; bei großen Dateien siehe Kapitel 3).

```powershell
$ev = .\Show-TraceStructure.ps1 -Path C:\daten\trace.log
```

**Welche Ereignisse enthält das Log?**
```powershell
$ev | Group-Object Action | Sort-Object Count -Descending | Select-Object Count, Name
```

**Die langsamsten Statements**
```powershell
$ev | Where-Object Action -eq 'EXECUTE_STATEMENT_FINISH' |
    Sort-Object DurationMs -Descending | Select-Object -First 20 DurationMs, User, SqlStatement
```

**Fehler und Warnungen**
```powershell
$ev | Where-Object { $_.Action -in 'ERROR', 'WARNING' } |
    Select-Object Timestamp, AttachID, ErrorSource, ErrorCodes, ErrorMessages
```

**Tabellen, die ohne Index gelesen wurden** (`Natural`, aufsummiert)
```powershell
$ev | Where-Object TableCounts | ForEach-Object { $_.TableCounts | Where-Object Natural -gt 0 } |
    Group-Object Table |
    ForEach-Object { [pscustomobject]@{ Table = $_.Name; Natural = ($_.Group | Measure-Object Natural -Sum).Sum } } |
    Sort-Object Natural -Descending | Select-Object -First 20
```

**Lange Verbindungen**
```powershell
$ev | Where-Object Action -eq 'DETACH_DATABASE' | Sort-Object ConnectionDurationMs -Descending |
    Select-Object -First 10 User, AttachID, ConnectionDurationMs
```

**Zeit rechnen:** `Timestamp` ist Text; mit `[datetime]$_.Timestamp` wird er zum Datum, z. B. für Auswertungen je Minute
(`Group-Object { ([datetime]$_.Timestamp).ToString('yyyy-MM-dd HH:mm') }`).

**Prozeduren, Funktionen, Trigger**
```powershell
$ev | Where-Object RoutineType | Group-Object RoutineType, RoutineName |
    Select-Object Count, Name | Sort-Object Count -Descending
```

**Als CSV für Excel**
```powershell
$ev | Where-Object Action -eq 'EXECUTE_STATEMENT_FINISH' |
    Select-Object Timestamp, DurationMs, Reads, Fetches, User, SqlStatement |
    Export-Csv -Path auswertung.csv -NoTypeInformation
```
`TableCounts` ist eine Liste und lässt sich nicht als Spalte exportieren (es käme `System.Object[]`); entweder die Liste
aufklappen (Beispiel oben) oder `TableStats` (Text) exportieren.

---

## 6. Pseudonymisieren für die Weitergabe

Trace-Rohdaten enthalten Benutzer, Adressen, Pfade, SQL-Texte und Parameter mit Inhalten der Datenbank. Vor einer
Weitergabe an Dritte:

```powershell
# 1. Vorschau: was würde ersetzt? (gibt Klartext auf der Konsole aus – Bildschirmfreigaben vermeiden)
.\Show-TraceStructure.ps1 -Path trace.log | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals -AnalyzeOnly

# 2. Pseudonymisieren und exportieren (Schlüsseldatei: gleiche Pseudonyme über mehrere Läufe)
.\Show-TraceStructure.ps1 -Path trace.log |
    .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals -KeyFile C:\schluessel\trace.key |
    Export-Csv -Path ..\trace_pseudonymisiert.csv -NoTypeInformation
```

| Parameter | Wirkung |
|---|---|
| `-RedactLiterals` | **für jede Weitergabe empfohlen:** alle Zeichenketten und Zahlen im SQL werden Pseudonyme; ohne den Schalter bleibt der SQL-Text im Klartext |
| `-SensitiveKeywords "A","B"` | Literale mit diesen Begriffen, und Klauseln (`WHERE`/`HAVING`) mit ihnen, werden ersetzt (Teilstring-Suche; kurze Begriffe treffen viel) |
| `-KeyFile` | geheimer Schlüssel (Base64, mindestens 32 Byte); fehlt die Datei, wird sie angelegt. **Ohne** Schlüsseldatei gilt ein Zufallsschlüssel nur für diesen Lauf (Warnung) |
| `-MappingFile` | optionale CSV `Pseudonym;Original` für Sie als Verantwortliche zum Rückführen; enthält Klartext |
| `-HashLength` (8–64, Standard 12) | Länge des Pseudonyms |
| `-AnalyzeOnly` | gibt nur den Bericht aus (Klartext!), keine Objekte |

**Was ersetzt wird:** `User`, `ClientIP` (auch in `ProtocolInfo`), `ApplicationPath`, `DatabasePath`, die Werte in `Params`;
mit `-RedactLiterals` zusätzlich Literale in `SqlStatement` und Werte in `ErrorMessages`.
**Was im Klartext bleibt** (bewusst, für die Analyse nötig): Plan, Tabellenstatistik, **Tabellen-, Index- und
Routinennamen** (auch `-SensitiveKeywords` verbirgt sie nicht), technische IDs, Zeitstempel, Zähler, Fehlercodes. Wer
Tabellennamen verbergen muss, lässt die Felder weg:
`… | Select-Object -Property * -ExcludeProperty SqlPlan, TableStats, TableCounts, RoutineName, TriggerTable`.

> **Pseudonymisierung ist keine Anonymisierung.** Wer den Schlüssel hat, kann vermutete Werte prüfen; die Daten bleiben
> personenbezogen. Schlüsseldatei und Zuordnungsdatei **nie** weitergeben. Vor jeder Weitergabe die Vorschau
> (`-AnalyzeOnly`) ansehen und eine Stichprobe des Exports lesen. Vollständige Feldliste und Restrisiken:
> `features/PSEUDONYMIZATION.md`. Aufbewahrung und Rotation des Schlüssels: Adminhandbuch, Kapitel 8.

---

## 7. Weitergabe an den Report-Generator

Der [firebird-trace-report-generator](https://github.com/gitnol/firebird-trace-report-generator) erzeugt aus den Objekten
einen eigenständigen HTML-Bericht mit Diagrammen und Empfehlungen:

```powershell
.\Show-TraceStructure.ps1 -Path trace.log | ..\firebird-trace-report-generator\New-TraceReport.ps1 -FilePath Report.html
```

Pseudonymisiert, wenn der Bericht das Haus verlässt:

```powershell
.\Show-TraceStructure.ps1 -Path trace.log | .\Pseudonymize-FirebirdTrace.ps1 -RedactLiterals -KeyFile C:\schluessel\trace.key |
    ..\firebird-trace-report-generator\New-TraceReport.ps1 -FilePath Report_pseudonymisiert.html
```

Optionen, Bedienung des Berichts und Grenzen stehen in der README und im Benutzerhandbuch des Generators. Der Generator
erwartet genau das Ausgabeformat dieses Parsers (Feldnamen wie `Timestamp`, `Action`, `SqlStatement`, `ErrorCodes`); das
Format ist Vertrag (`features/TRACE_PARSING.md`).

---

## 8. Grenzen und Fallstricke

* **Ein Fehlerereignis hat kein Statement.** `ERROR`/`WARNING` tragen Verbindung, Fehlerquelle, Codes und Meldungen, aber
  weder SQL noch Transaktion. Der Parser verknüpft sie nicht mit einem Statement; im Trace gibt es dafür keinen Verweis.
  Die Zuordnung über `AttachID` und `Timestamp` ist eine Näherung und Sache der Auswertung (der Report-Generator macht
  sie so). Beobachtungen aus Praxis-Traces, nicht aus dem Firebird-Quelltext geprüft: bei `ErrorSource` `…::prepare` und
  `…::openCursor` fehlt das auslösende Statement im Trace meist ganz (es wurde nie als beendet protokolliert), bei
  `…::fetchNext` steht es in der Regel **davor** auf derselben Verbindung.
* **`FAILED EXECUTE_STATEMENT_FINISH` enthält keinen Fehlertext;** der Fehler steht in einem eigenen `ERROR`-Ereignis.
* **`0` ist doppeldeutig:** Zähler sind `0`, wenn die Zeile im Trace fehlt. `RecordsFetched = 0` heißt nicht immer „null
  Zeilen“ (Firebird lässt die Zeile bei Prozeduren mit 0 Zeilen weg).
* **`SqlStatement` ist leer** bei Verbindungs-, Transaktions-, Prozedur- und Fehlerereignissen; beim Gruppieren
  berücksichtigen.
* **IDs sind Texte ohne Präfix:** `AttachID` `399921`, nicht `ATT_399921`; `TransactionID`, `RootTxID` ebenso.
* **`Timestamp` ist Text**, kein `[datetime]` (Sortierung als Text stimmt, Rechnen braucht die Umwandlung).
* **Prozeduren und Trigger können doppelt zählen:** ruft eine Prozedur andere auf, steckt deren Zeit vermutlich auch in
  ihrer eigenen Laufzeit (nicht geprüft); Summen über `RoutineType` mit Vorsicht lesen.
* **`ConnectionDurationMs`** steht am `DETACH_DATABASE`, nicht am `ATTACH_DATABASE`, und fehlt, wenn die Verbindung vor
  dem Trace begann (oder die Datei in Teilen gelesen wird).
* **Gekürzte Ereignisse** (`-MaxBlockLines`) haben nur die Felder der ersten Zeilen, meist ohne Laufzeit.
* **Trace-Dateien und Exporte sind vertraulich** (`security/DATA_HANDLING.md`): nicht in Repositories, nicht auf offene
  Laufwerke, nach der Auswertung löschen.

---

## 9. Wenn etwas nicht stimmt

| Beobachtung | Ursache / Maßnahme |
|---|---|
| `File not found: …` | Pfad prüfen (`-Path` ist ein Dateipfad relativ zum aktuellen Ordner) |
| Skript startet nicht („Ausführung von Skripts deaktiviert“) | Execution Policy: Adminhandbuch, Kapitel 3 |
| Sehr langsam | Mit `-Verbose` prüfen, ob `Engine: PowerShell` läuft; C#-Parser lässt sich vom Administrator bauen (Adminhandbuch, Kapitel 4). Ausgabe direkt weiterleiten statt in Variablen sammeln |
| `Line <n>: …`-Warnungen | Format weicht ab oder Datei ist abgeschnitten; Zeilen `n` der Datei ansehen (Inhalt vertraulich behandeln); bei neuen Formen mit einer **erfundenen** Beispielzeile melden |
| Felder wie `User`, `DatabasePath` leer | Der Block hat keine Verbindungszeile (z. B. manche Sweep- oder Fehlerereignisse) |
| Meldung „Engine CSharp needs PowerShell 7.4“ | `-Engine CSharp` läuft nur unter PowerShell 7; `-Engine Auto` nehmen |
| Leere Ausgabe | Datei leer oder keine Zeitstempelzeilen; bei Trace ohne Statements ≥ `time_threshold` (Adminhandbuch) |

Weitere Hilfe: `operations/RUNBOOK.md` (Troubleshooting, Exit-Codes der Trace-Skripte).
