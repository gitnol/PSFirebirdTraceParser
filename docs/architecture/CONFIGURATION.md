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

1. **Konfigurationsdatei** `config.json` neben den Skripten (`$PSScriptRoot`), lokal und gitignored;
   Vorlage `config.sample.json`
2. **Fest im Code** (keine Überschreibung möglich): Ausgabeverzeichnis `E:\`, Dienstname `service_mgr`,
   Dateinamensmuster `trace_output_<yyyyMMdd_HHmmss>.log`

Die Trace-Regeln selbst stehen in der Datei, die `TraceConfigFilename` benennt (Standard `fbtrace30.conf`).

---

## Validierung beim Laden

- **Ist (Trace-Skripte):** Existenz von `config.json` (sonst Exit 1) und JSON-Syntax (sonst Exit 2). Die einzelnen
  Schlüssel werden **nicht** geprüft — fehlt z. B. `FirebirdPath`, scheitert erst der `fbtracemgr`-Aufruf.
- **Ist (Parser):** `-Path` ist Pflicht; existiert die Datei nicht, gibt das Skript einen nicht-terminierenden Fehler
  aus und kehrt zurück (`architecture/ERROR_HANDLING.md`).
- **Soll (I5):** alle Schlüssel beim Laden prüfen (vorhanden, nicht leer, Pfade existieren), Werte einmal in ein
  schreibgeschütztes Objekt übernehmen; Fehler vor dem ersten externen Aufruf.

---

## Secrets gehören NICHT in normale Konfigurationsdateien

- Secrets immer über eine sichere Quelle: Credential Store, DPAPI, `SecretManagement`
  (`architecture/CREDENTIAL_STRATEGY.md`).
- Details: `docs/operations/SECRETS_MANAGEMENT.md`.
- **Abweichung im Bestand:** `config.json` enthält heute das Firebird-Passwort im Klartext (Schlüssel `Password`).
  Die Datei ist gitignored, liegt aber unverschlüsselt neben den Skripten. Ablösung in I4.

---

## Konfigurationsobjekt — Verwendung

- Funktionen erhalten Konfigwerte als **Parameter**, nicht über globalen Zugriff. Siehe [[EXPLICIT_OVER_IMPLICIT]].
- Das Konfigurationsobjekt wird **einmal** im Skriptkopf gebaut (heute: `$Config = Get-Content … | ConvertFrom-Json`)
  und nicht weiter verändert.
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
| `Firebird.Username` | `string` | kein | FILE (`config.json`) | Firebird-Benutzer für `fbtracemgr` (Vorlage: SYSDBA) |
| `Firebird.Password` | `string` | kein | FILE (`config.json`) | Passwort im Klartext — Abweichung, siehe oben (I4) |
| `Firebird.FirebirdPath` | `string` | kein | FILE (`config.json`) | Installationsverzeichnis mit `fbtracemgr.exe` |
| `Firebird.TraceConfigFilename` | `string` | kein | FILE (`config.json`) | Dateiname der Trace-Konfiguration relativ zu `$PSScriptRoot` (Vorlage: `fbtrace30.conf`) |

### Trace-Regeln (`fbtrace30.conf`, Abschnitt `database`)

| Schlüssel | Wert im Repo | Wirkung |
|---|---|---|
| `enabled` | `true` | Trace für alle Datenbanken (kein Datenbankfilter) |
| `time_threshold` | `100` | nur Statements ab 100 ms |
| `log_connections`, `log_transactions`, `log_statement_finish`, `log_errors` | `true` | Verbindungen, Transaktionen, beendete Statements, Fehler |
| `include_gds_codes` | `lock_conflict, deadlock` | nur diese Fehlercodes |
| `print_plan`, `print_perf` | `true` | Ausführungsplan und Tabellenstatistik |
| `max_sql_length` / `max_arg_length` / `max_arg_count` | `65000` / `240` / `50` | Kürzungsgrenzen für SQL-Text und Parameter |
| `log_initfini` | `false` | keine Start-/Ende-Meldungen der Session |

---

## Anti-Pattern

- **Werte direkt aus `$env:VAR` mitten in der Logik lesen.** Versteckte Abhängigkeit.
- **Konfiguration zur Laufzeit mutieren.**
- **Magic Defaults im Code** (heute: `E:\` in zwei Skripten) statt zentralem Wert in `config.json`.

---

## Pflege

Trigger (siehe `KICKOFF.md` Phase 3a): neue Konfig-Quelle / neuer Schlüssel / geänderte Präzedenz → diese Datei,
`config.sample.json` und beide READMEs aktualisieren.
