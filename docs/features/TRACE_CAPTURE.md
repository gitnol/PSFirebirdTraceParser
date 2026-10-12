# Feature: Trace-Erfassung (`trace_start.ps1`, `trace_stop.ps1`)

---

## Zweck

Startet auf dem Firebird-Server eine Trace-Session mit den Regeln aus `fbtrace30.conf` und schreibt deren
Ausgabe in eine Datei mit Zeitstempel; ein zweites Skript stoppt die Session wieder.

---

## Technologie / Abhängigkeiten

- `fbtracemgr.exe` aus der Firebird-Installation (Pfad aus `config.json`)
- Firebird Services API, lokal `service_mgr`
- Lokales Laufwerk `E:\` für die Ausgabe (fest im Code)

---

## Parameter

Beide Skripte haben **keine** Parameter; alle Werte kommen aus `config.json` (`architecture/CONFIGURATION.md`).

| Schlüssel (`config.json`) | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `Firebird.Username` | string | Ja | — | keine | Benutzer für den Service-Manager |
| `Firebird.Password` | string | Ja | — | keine | Passwort im Klartext (I4) |
| `Firebird.FirebirdPath` | string | Ja | — | keine | Verzeichnis mit `fbtracemgr.exe` |
| `Firebird.TraceConfigFilename` | string | Ja (nur Start) | — | keine | Trace-Konfiguration relativ zum Skriptverzeichnis |

---

## Ablauf (Ist)

- **Start:** Konfiguration laden → Dateiname `E:\trace_output_<yyyyMMdd_HHmmss>.log` → Hinweise ausgeben →
  `fbtracemgr -SE service_mgr -USER … -PASS … -START -CONFIG <conf> > <datei>`. Der Aufruf läuft im Vordergrund,
  bis die Session gestoppt wird; die erste Zeile der Datei enthält die Session-ID.
- **Stopp:** Konfiguration laden → neueste `E:\*.log` → erste Zeile auf `Trace session ID <n> started` prüfen →
  `fbtracemgr -SE service_mgr -USER … -PASS … -STOP -ID <n>`.

---

## Kritische Patterns

- Session-ID kommt aus der Kopfzeile der Ausgabedatei — Start und Stopp hängen über die Datei zusammen.
- Exit-Codes 1–4 sind dokumentiert (`architecture/ERROR_HANDLING.md`).
- Die Trace-Datei enthält personenbezogene und vertrauliche Daten (`security/DATA_HANDLING.md`).

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| Passwort in der Kommandozeile, Klartext in `config.json`, Vorlage mit SYSDBA | Bestandsdesign | I4 |
| Ausgabeverzeichnis `E:\` fest | Magic String | I5 |
| Stopp wählt die neueste `*.log` auf `E:\` — andere Logdateien dort führen zu Exit 4 oder falscher Session | Heuristik statt gespeicherter ID (K4) | I5 |
| Hinweistext nennt `trace-stop.ps1`, Datei heißt `trace_stop.ps1` | Tippfehler (K4) | I5 |
| Umlaute ohne BOM → falsche Zeichen unter Windows PowerShell 5.1 | Encoding (K5) | I5 |
| `$LASTEXITCODE` von `fbtracemgr` wird nicht geprüft | fehlende Fehlerbehandlung | I5 |

---

## Bekannte Fallstricke

- `trace_start.ps1` blockiert die Konsole; Stoppen aus einer zweiten Konsole (`operations/RUNBOOK.md`).
- Eine laufende Session schreibt weiter, bis sie gestoppt wird — Plattenplatz auf `E:\` beobachten (`operations/MONITORING.md`).
- Unter Windows PowerShell 5.1 schreibt die Umleitung `>` standardmäßig UTF-16 LE — Dateigröße und Weiterverarbeitung
  durch Fremdwerkzeuge beachten (ungeprüft, I5).

---

## Teststrategie

- Zugehörige Testdateien: `tests/trace_start.Tests.ps1`, `tests/trace_stop.Tests.ps1` (I5)
- Pester-Beschreibung: `Describe 'trace_stop' { ... }`
- `fbtracemgr` hinter einer Wrapper-Funktion kapseln und mocken; Dateien in `TestDrive:`
- Kritische Testfälle: fehlende/ungültige `config.json` → Exit 1/2; keine Logdatei → Exit 3; Kopfzeile ohne ID → Exit 4;
  Passwort erscheint in keiner Ausgabe und in keinem Kommandozeilenargument (ab I4)
