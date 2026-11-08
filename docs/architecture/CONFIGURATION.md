# Konfiguration – PSFirebirdTraceParser

Wo Werte herkommen, in welcher Reihenfolge sie überschreiben, und wie sie
validiert werden. Verbindet sich mit den Prinzipien [[EXPLICIT_OVER_IMPLICIT]]
und [[FAIL_FAST]].

---

## Quellen-Hierarchie (Präzedenz, höchste zuerst)

Das Projekt hat zwei getrennte Konfigurationswege:

**Parser und Pseudonymisierer** (`Show-TraceStructure.ps1`, `Pseudonymize-FirebirdTrace.ps1`):

1. **Skript-Parameter** (`-Path`, `-SensitiveKeywords`, `-RedactLiterals`, `-AnalyzeOnly`, `-HashLength`)
2. **Code-Defaults** (z. B. `-HashLength 12`, Regex-Muster im Skript)

Keine Konfigurationsdatei, keine Umgebungsvariablen.

**Trace-Skripte** (`trace_start.ps1`, `trace_stop.ps1`):

1. **Parameter** (nur `trace_stop.ps1 -Id`)
2. **Konfigurationsdatei** `config.json` neben den Skripten (`$PSScriptRoot`), lokal und gitignored;
   Vorlage `config.sample.json`. `%VAR%` in `FirebirdPath`, `PasswordFile`, `OutputDirectory` wird ersetzt.
3. **Fest im Code** (`TraceCommon.ps1`, keine Überschreibung): Dienstname `service_mgr`, Dateinamensmuster
   `trace_output_<yyyyMMdd_HHmmss>.log`, Zustandsdatei `trace_session.json` neben den Skripten

Die Trace-Regeln selbst stehen in der Datei, die `TraceConfigFilename` benennt (Vorlage `fbtrace50.conf`).

---

## Validierung beim Laden

- **Trace-Skripte (seit I5):** Existenz von `config.json` (sonst Exit 1), JSON-Syntax und jeder Schlüssel (vorhanden,
  nicht leer, Pfade existieren, `SessionName` nur `A–Z a–z 0–9 _ -`, kein `Password`) — alle Fehler zusammen, Exit 2,
  vor dem ersten Aufruf von `fbtracemgr`. Ergebnis ist ein Objekt, das danach nicht mehr verändert wird.
- **Ist (Parser):** `-Path` ist Pflicht; existiert die Datei nicht, gibt das Skript einen nicht-terminierenden Fehler
  aus und kehrt zurück (`architecture/ERROR_HANDLING.md`).

---

## Secrets gehören NICHT in normale Konfigurationsdateien

- Secrets immer über eine sichere Quelle: Credential Store, DPAPI, `SecretManagement`
  (`architecture/CREDENTIAL_STRATEGY.md`).
- Details: `docs/operations/SECRETS_MANAGEMENT.md`.
- Seit I4 steht in `config.json` nur der **Pfad** der Passwortdatei (`PasswordFile`); ein Schlüssel `Password`
  lässt die Skripte abbrechen (ADR-002).

---

## Konfigurationsobjekt — Verwendung

- Funktionen erhalten Konfigwerte als **Parameter**, nicht über globalen Zugriff. Siehe [[EXPLICIT_OVER_IMPLICIT]].
- Das Konfigurationsobjekt wird **einmal** gebaut (`Read-TraceConfig` in `TraceCommon.ps1`) und als Parameter an
  `Start-TraceSession`/`Stop-TraceSession` gereicht, nicht weiter verändert.
- Der Parser und der Pseudonymisierer kennen `config.json` nicht und sollen sie auch künftig nicht kennen.

---

## Konfigurations-Tabelle (Pflicht ausfüllen)

| Schlüssel | Typ | Default | Quelle(n) | Beschreibung |
|---|---|---|---|---|
| `-Path` | `string` | kein (Pflicht) | Parameter | Pfad zur Trace-Datei (`Show-TraceStructure.ps1`) |
| `-SensitiveKeywords` | `string[]` | leer | Parameter | Begriffe, deren Vorkommen Literale bzw. ganze WHERE/HAVING-Klauseln pseudonymisiert |
| `-RedactLiterals` | `switch` | aus | Parameter | Alle String-Literale ab 2 Zeichen (ohne `%`) pseudonymisieren |
| `-AnalyzeOnly` | `switch` | aus | Parameter | Nur Bericht über Literale/Klauseln, keine Ausgabe von Objekten |
| `-HashLength` | `int` (8–64) | `12` | Parameter | Länge des hexadezimalen Pseudonyms |
| `Firebird.FirebirdPath` | `string` | kein | FILE (`config.json`) | Installationsordner mit `fbtracemgr.exe` (Vorlage: `…\Firebird_5_0`) |
| `Firebird.Username` | `string` | kein | FILE (`config.json`) | Firebird-Benutzer (Vorlage: `TRACE_USER`); entfällt mit `UseTrustedAuth` |
| `Firebird.PasswordFile` | `string` | kein | FILE (`config.json`) | Datei mit dem Passwort (erste Zeile), `-FETCH_PASSWORD`; entfällt mit `UseTrustedAuth` |
| `Firebird.UseTrustedAuth` | `bool` | `false` | FILE (`config.json`) | Windows-Anmeldung (`-TRUSTED`) |
| `Firebird.Role` | `string` | leer | FILE (`config.json`) | Rolle mit `TRACE_ANY_ATTACHMENT` (`-ROLE`, Vorlage: `TRACER`) |
| `Firebird.TraceConfigFilename` | `string` | kein | FILE (`config.json`) | Trace-Konfiguration relativ zu `$PSScriptRoot` (Vorlage: `fbtrace50.conf`) |
| `Firebird.OutputDirectory` | `string` | kein | FILE (`config.json`) | Ordner für `trace_output_<Zeitstempel>.log` |
| `Firebird.SessionName` | `string` | kein | FILE (`config.json`) | Präfix des Sitzungsnamens (`-NAME <präfix>_<Zeitstempel>`) |
| `Firebird.Password` | — | — | — | **nicht mehr erlaubt** (Exit 2, ADR-002) |
| `-Id` | `int` (≥ 1) | keiner | Parameter (`trace_stop.ps1`) | bestimmte Trace-ID stoppen, ohne Suche |

### Trace-Regeln (`fbtrace50.conf` = Vorlage, `fbtrace30.conf` = älter)

| Schlüssel | Wert im Repo | Wirkung |
|---|---|---|
| `log_sweep` (nur `fbtrace50.conf`) | `true` | Sweeps mit Transaktionszählern (vom Parser gelesen, I15) |
| Abschnitt `services`: `log_services`, `log_errors` (nur `fbtrace50.conf`) | `true` | Dienste (Sicherung, Statistik, …) mit Dienstname und Verbindung (I15); `log_service_query = false` |
| `enabled` | `true` | Trace für alle Datenbanken (kein Datenbankfilter) |
| `time_threshold` | `100` | nur Statements ab 100 ms |
| `log_connections`, `log_transactions`, `log_statement_finish`, `log_errors` | `true` | Verbindungen, Transaktionen, beendete Statements, Fehler |
| `include_gds_codes` | nur `fbtrace30.conf`: `lock_conflict, deadlock` | nur diese Fehlercodes; `fbtrace50.conf` setzt es nicht (alle Fehler) |
| `print_plan`, `print_perf` | `true` | Ausführungsplan und Tabellenstatistik |
| `max_sql_length` / `max_arg_length` / `max_arg_count` | `65000` / `240` / `50` | Kürzungsgrenzen für SQL-Text und Parameter |
| `log_initfini` | `false` | keine Start-/Ende-Meldungen der Session |

---

## Anti-Pattern

- **Werte direkt aus `$env:VAR` mitten in der Logik lesen.** Versteckte Abhängigkeit.
- **Konfiguration zur Laufzeit mutieren.**
- **Magic Defaults im Code** statt zentralem Wert in `config.json` (früher: `E:\` in beiden Trace-Skripten).

---

## Pflege

Trigger (siehe `KICKOFF.md` Phase 3a): neue Konfig-Quelle / neuer Schlüssel / geänderte Präzedenz → diese Datei,
`config.sample.json` und beide READMEs aktualisieren.
