# Glossar – PSFirebirdTraceParser

Ubiquitous Language für dieses Projekt. Jeder Begriff hat genau eine Bedeutung.
Synonyme oder doppelt belegte Begriffe schaffen Drift und werden vermieden.

LLM-Agenten konsultieren dieses Glossar, **bevor** sie Begriffe im Code, in
Commit-Messages oder in Doku verwenden.

---

## Begriffe

| Begriff | Bedeutung | Wo verwendet | Nicht zu verwechseln mit |
|---|---|---|---|
| Trace-Session | Vom Firebird-Server geführte Protokollierung, gestartet per `fbtracemgr -START`, identifiziert durch die Trace-Session-ID | `trace_start.ps1`, `trace_stop.ps1` | Datenbankverbindung (Attachment); Property `SessionID` |
| Trace-Session-ID | Nummer aus der ersten Zeile der Trace-Ausgabe (`Trace session ID <n> started`), nötig für `-STOP -ID` | `trace_stop.ps1` (`$MyTraceId`) | Property `SessionID` der Trace-Objekte |
| Trace-Konfiguration | Datei mit Regeln, was der Server protokolliert (`fbtrace30.conf`) | `config.json` → `TraceConfigFilename` | `config.json` (Skript-Konfiguration) |
| Trace-Log | Textdatei mit der Ausgabe einer Trace-Session (Rohdaten, vertraulich) | `E:\trace_output_*.log`, Parameter `-Path` | Konsolenmeldungen der Skripte |
| Trace-Block | Abschnitt eines Trace-Logs von einer Zeitstempel-Zeile bis vor die nächste; ein Ereignis | `Show-TraceStructure.ps1` (`$logBlocks`) | Zeile; Statement |
| Trace-Objekt | `PSCustomObject`, das der Parser je Trace-Block ausgibt; Property-Namen sind Vertrag | `features/TRACE_PARSING.md` | Rohtext des Blocks |
| Action | Ereignisname der Kopfzeile eines Blocks (z. B. Ende eines Statements, Transaktionsstart) | Property `Action` | Skript-Aktion (Start/Stopp) |
| `SessionID` (Property) | Zweiter, hexadezimaler Wert in der Klammer der Kopfzeile `(PID:…)` | Property `SessionID` | Trace-Session-ID |
| Attachment | Datenbankverbindung eines Clients (`ATT_<n>`) | Property `AttachID` | Trace-Session |
| RootTxID | Ursprungs-Transaktion: `INIT_<n>` falls vorhanden, sonst die eigene `TRA_<n>`, sonst `NoTx` | Property `RootTxID` | `TransactionID` |
| Pseudonym | Gekürzter Hex-Hash, der einen Klartextwert ersetzt (`<HASH:…>` in SQL, sonst nur der Hex-Wert) | `Pseudonymize-FirebirdTrace.ps1` (`Get-ShortHash`) | Anonymisierung |
| Pseudonymisierung | Ersetzen identifizierender Werte durch Pseudonyme; Ergebnis bleibt personenbezogen | `Pseudonymize-FirebirdTrace.ps1`, README | Anonymisierung |
| Literal | In einfache Anführungszeichen gesetzter Wert in einem SQL-Statement (`'…'`); numerische Werte zählen im Bestand nicht dazu | `$RxStringLiteral` | Parameter (`paramN = …`) |
| Bulk-Redaktion | Ersetzen der (letzten) WHERE/HAVING-Klausel durch `<REDACTED_CLAUSE:…>`, wenn ein sensibles Schlüsselwort vorkommt | `-SensitiveKeywords` | Literal-Pseudonymisierung |
| Feldabdeckung | Liste, welche Property wie pseudonymisiert wird bzw. bewusst im Klartext bleibt | `features/PSEUDONYMIZATION.md` | — |
| Service-Manager | Firebird-Services-API-Endpunkt (`service_mgr`), über den `fbtracemgr` Traces verwaltet | Trace-Skripte | Datenbankdatei |

---

## Verbotene Synonyme

Begriffe, die im Projekt-Kontext **nicht** mehr verwendet werden dürfen,
auch wenn sie umgangssprachlich gleichbedeutend wirken:

| Verbotener Begriff | Korrekt | Grund |
|---|---|---|
| Anonymisierung / anonymisiert | Pseudonymisierung / pseudonymisiert | Das Verfahren ist deterministisch und (ohne Schlüssel) umkehrbar; „anonym" würde eine falsche Datenschutz-Zusage machen |
| Session (ohne Zusatz) | Trace-Session **oder** Attachment **oder** Property `SessionID` | drei verschiedene Dinge |
| Log (ohne Zusatz) | Trace-Log | im Projekt gibt es kein Anwendungs-Log; „Log" verwischt die Sensitivität der Rohdaten |

---

## Pflege

- Neuer Domänenbegriff im Code → **vor dem Commit** hier ergänzen.
- Begriff wird umbenannt → alter Eintrag bleibt mit Vermerk „ersetzt durch …"
  stehen (mindestens eine Inkrement-Generation als Übergangsphase).
- Begriff entfällt → Eintrag mit „deprecated" und Datum markieren, nicht löschen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
