# Feature: Trace-Erfassung (`trace_start.ps1`, `trace_stop.ps1`)

---

## Zweck

Startet auf dem Firebird-Server eine benannte Trace-Sitzung mit den Regeln aus der Trace-Konfiguration
(`fbtrace50.conf`, für Firebird 4.0 und 5.0) und schreibt deren Ausgabe in eine Datei mit Zeitstempel; ein zweites
Skript findet genau diese Sitzung wieder und stoppt sie. Seit I4/I5 ohne Passwort in der Befehlszeile
(`architecture/ADR/ADR-002-trace-anmeldung.md`).

---

## Technologie / Abhängigkeiten

- PowerShell **7.4 oder neuer** (nur dann landet die Ausgabe byte-genau in der Datei; ADR-002)
- `fbtracemgr.exe` aus der Firebird-Installation (`FirebirdPath` in `config.json`), lokal über `service_mgr`
- `TraceCommon.ps1`: gemeinsame Funktionen, beide Skripte laden es per Dot-Sourcing

---

## Parameter und Konfiguration

`trace_start.ps1` hat keine Parameter. `trace_stop.ps1 -Id <n>` stoppt eine bestimmte Sitzung ohne Suche.
Alle übrigen Werte kommen aus `config.json` neben den Skripten (Vorlage `config.sample.json`,
`architecture/CONFIGURATION.md`). Alle Fehler werden vor dem ersten Aufruf von `fbtracemgr` gesammelt gemeldet.

| Schlüssel (`Firebird.…`) | Typ | Pflicht | Prüfung | Beschreibung |
|---|---|---|---|---|
| `FirebirdPath` | string | Ja | `fbtracemgr.exe` existiert dort | Ordner der Firebird-Installation; `%VAR%` wird ersetzt |
| `Username` | string | ohne `UseTrustedAuth` | nicht leer | Firebird-Benutzer (SYSDBA oder Trace-Benutzer) |
| `PasswordFile` | string | ohne `UseTrustedAuth` | Datei existiert | Datei mit dem Passwort in der ersten Zeile; `%VAR%` wird ersetzt |
| `UseTrustedAuth` | bool | Nein | — | `true` = Windows-Anmeldung (`-TRUSTED`) statt Benutzer/Passwortdatei |
| `Role` | string | Nein | — | Rolle mit `TRACE_ANY_ATTACHMENT` (`-ROLE`), sonst leer |
| `TraceConfigFilename` | string | Ja | Datei neben den Skripten existiert | z. B. `fbtrace50.conf` |
| `OutputDirectory` | string | Ja | Ordner existiert | Ziel der Logdatei; `%VAR%` wird ersetzt |
| `SessionName` | string | Ja | nur `A–Z a–z 0–9 _ -` | Präfix des Sitzungsnamens |
| `Password` | — | **verboten** | Abbruch mit Exit-Code 2 | Altschlüssel; der Wert wird nie ausgegeben |

---

## Ablauf

- **Start:** Konfiguration prüfen → Name `<SessionName>_<yyyyMMdd_HHmmss>`, Logdatei
  `<OutputDirectory>\trace_output_<yyyyMMdd_HHmmss>.log` → ist `trace_session.json` schon da, Abbruch (Exit 2) →
  `trace_session.json` schreiben (Name, Logdatei, Startzeit) → Hinweise ausgeben →
  `fbtracemgr -SE service_mgr <Anmeldung> -START -NAME <name> -CONFIG <conf> > <logdatei>`. Der Aufruf blockiert, bis
  die Sitzung gestoppt wird; danach wird `trace_session.json` gelöscht.
- **Stopp:** Konfiguration prüfen → `-Id`, sonst die ID aus der ersten Zeile der gemerkten Logdatei
  (`Trace session ID <n> started`), sonst `fbtracemgr -LIST` nach Sitzungen, deren Name mit dem gemerkten Namen (ohne
  Zustandsdatei: mit `SessionName`) beginnt → genau eine: `-STOP -ID <n>`, Bestätigung `Trace session ID <n> stopped`
  prüfen, Zustandsdatei löschen; keine: Exit 3 (Zustandsdatei wird gelöscht); mehrere: Exit 4 mit Liste.
- **Anmeldung** (`<Anmeldung>`): `-USER <Username> -FETCH_PASSWORD <PasswordFile>` oder `-TRUSTED`, jeweils mit
  `-ROLE <Role>`, wenn gesetzt.

Exit-Codes: `architecture/ERROR_HANDLING.md`. Die Optionen der Trace-Konfiguration (`fbtrace50.conf`/`fbtrace30.conf`), den
Betrieb einer Aufzeichnung und die Einrichtung eines Trace-Benutzers fasst das [Adminhandbuch](../handbuch/ADMINHANDBUCH.md)
(Kapitel 5 bis 7) zusammen.

---

## Kritische Patterns

- Alle Aufrufe von `fbtracemgr` laufen über `Invoke-FbTraceMgr` — die einzige Stelle, die Tests ersetzen.
- Fehler laufen als `TraceException` mit Exit-Code hoch; nur die beiden Skripte rufen `exit`.
- Die Trace-Datei enthält personenbezogene und vertrauliche Daten (`security/DATA_HANDLING.md`).

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---|---|---|
| Passwortdatei ist Klartext auf der Platte | `fbtracemgr` liest das Passwort nur aus einer Datei (ADR-002) | akzeptiert; Rechte nur eigenes Konto, nach Gebrauch löschen |
| Nur lokaler Service-Manager (`service_mgr`) | fest im Code | bewusst; Remote-Trace ist nicht vorgesehen |
| `-TRUSTED` und Rolle `TRACER` nicht gegen einen echten Server geprüft | kein Testserver mit dieser Einstellung | offen |
| Windows PowerShell 5.1 wird für die Trace-Skripte abgelehnt | `>` schreibt dort UTF-16 mit CRLF (ADR-002) | bewusst |

---

## Bekannte Fallstricke

- `trace_start.ps1` blockiert die Konsole; Stoppen aus einer zweiten Konsole (`operations/RUNBOOK.md`).
- Während der Aufzeichnung ist die Logdatei oft noch **leer**: PowerShell schreibt die Ausgabe gepuffert (gemessen mit
  einem Ersatzprogramm: 0 Byte nach 4 s). Der Stopp findet die Sitzung dann über `-LIST` und den Namen.
- Wird das Startfenster hart geschlossen, bleibt `trace_session.json` liegen; der nächste Start bricht mit Exit 2 ab.
  `trace_stop.ps1` aufrufen (stoppt die Sitzung oder räumt die Datei auf).
- Eine laufende Session schreibt weiter, bis sie gestoppt wird — Plattenplatz im Ausgabeordner beobachten
  (`operations/MONITORING.md`).
- `include_gds_codes` in der Trace-Konfiguration beschränkt `log_errors` auf die genannten Codes; `fbtrace50.conf` setzt
  es deshalb nicht (`fbtrace30.conf` setzt es noch).

---

## Teststrategie

- Testdatei: `tests/TraceCommon.Tests.ps1` (seit I4/I5).
- `Invoke-FbTraceMgr` wird gemockt; Ordner, `config.json`, Passwortdatei und ein leeres `fbtracemgr.exe` liegen in
  `TestDrive:`.
- Abgedeckt: Konfigurationsprüfung (alle Fehler zusammen, Passwort abgelehnt, `%VAR%`), Anmeldeargumente ohne Passwort,
  Start (Argumente, Zustandsdatei, Zweitstart, Fehler), Stopp (erste Logzeile, `-LIST`, `-Id`, Exit 3/4/5), Exit-Codes
  als Prozess, byte-genaue Logdatei (nur PowerShell 7.4+), Vorlage ohne Passwort, `config.json` nicht in git.
- Nicht automatisch testbar: echter Service-Manager — Lauf gegen einen Server, im CHANGELOG vermerken.
