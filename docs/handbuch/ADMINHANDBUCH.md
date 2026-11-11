# Adminhandbuch – PSFirebirdTraceParser

Für Administratorinnen und Administratoren: Installation, Trace aufzeichnen, C#-Parser bauen, Schlüssel und Zugänge
verwalten, Aktualisierung und Qualitätssicherung. Die Bedienung für Analysten steht im
[Benutzerhandbuch](BENUTZERHANDBUCH.md). Dieses Handbuch fasst zusammen und verweist; die Begründungen stehen in den ADR
(`architecture/ADR/`), die Einzelheiten in `operations/` und `features/`.

Namen in den Beispielen sind erfunden (`TRACE_USER`, `TRACER`, `D:\FirebirdTrace`).

---

## 1. Überblick

| Baustein | Aufgabe | Läuft wo |
|---|---|---|
| `trace_start.ps1`, `trace_stop.ps1`, `TraceCommon.ps1` | Trace-Sitzung auf dem Firebird-Server starten und stoppen (`fbtracemgr`) | Datenbankserver, PowerShell 7.4+ |
| `fbtrace50.conf` / `fbtrace30.conf` | Regeln: was der Server protokolliert | neben den Skripten |
| `config.json` (aus `config.sample.json`) | Ort von Firebird, Benutzer, Passwortdatei, Ausgabeordner | neben den Skripten, nie im Repository |
| `Show-TraceStructure.ps1` (+ optional `FirebirdTraceParser.dll`) | Trace-Datei in Objekte zerlegen | Analyse-Rechner |
| `Pseudonymize-FirebirdTrace.ps1` | Objekte vor der Weitergabe pseudonymisieren | Analyse-Rechner |

Es gibt keinen Dienst, keine Datenbank und kein Modul; die Skripte laufen interaktiv. Datenfluss:
`architecture/OVERVIEW.md`.

---

## 2. Voraussetzungen

| Wofür | Was |
|---|---|
| Trace aufzeichnen | PowerShell **7.4 oder neuer** (7.6 LTS empfohlen; nur dann landet die Ausgabe byte-genau in der Datei, ADR-002), `fbtracemgr.exe` der Firebird-Installation (4.0 oder 5.0), Zugang zum Service-Manager, Ausgabeordner mit ausreichend Platz |
| Auswerten (Parser, Pseudonymisierer) | PowerShell 7.x oder Windows PowerShell 5.1; keine Module, kein Netz |
| C#-Parser bauen | .NET SDK; `global.json` verlangt mindestens 9.0.300 und lässt neuere Hauptversionen zu (`rollForward: latestMajor`); die CI baut mit 10.0.x. Der Parser selbst zielt auf `net8.0` und lädt in PowerShell 7.4 und neuer |
| Entwickeln und prüfen | Pester und PSScriptAnalyzer in den gepinnten Versionen (`tests/RequiredModules.psd1`) |

Aktuelle Patchstände (PowerShell, .NET) und Supportenden: `operations/SETUP.md` und `security/DEPENDENCY_AUDIT.md`;
sie ändern sich häufiger als dieses Handbuch.

---

## 3. Installation

### 3.1 Auf den Rechner bringen

Repository klonen oder die Dateien eines Tags/Commits kopieren. Auf einen **Datenbankserver** gehören nur:
`trace_start.ps1`, `trace_stop.ps1`, `TraceCommon.ps1`, die Trace-Konfiguration (`fbtrace50.conf`), `config.json` — in einen
Ordner mit eingeschränkten NTFS-Rechten. Parser und Pseudonymisierer gehören auf einen
Analyse-Rechner, nicht auf den Datenbankserver.

### 3.2 PowerShell und Ausführungsrichtlinie

```powershell
winget install Microsoft.PowerShell                                   # PowerShell 7
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser # einmalig, aktueller Benutzer
Get-ChildItem *.ps1 | Unblock-File                                    # aus dem Internet geladene Skripte entsperren
```

### 3.3 Konfiguration anlegen

```powershell
Copy-Item config.sample.json config.json   # config.json ist gitignoriert; sie enthält kein Passwort
```

Schlüssel (alle unter `Firebird`):

| Schlüssel | Bedeutung |
|---|---|
| `FirebirdPath` | Ordner mit `fbtracemgr.exe`; `%VAR%` wird ersetzt |
| `Username` / `PasswordFile` | Firebird-Benutzer und Passwortdatei (Kapitel 6) |
| `UseTrustedAuth` | `true` = Windows-Anmeldung statt Benutzer und Passwortdatei |
| `Role` | optionale Rolle mit dem Systemrecht `TRACE_ANY_ATTACHMENT` |
| `TraceConfigFilename` | Trace-Regeln neben den Skripten, z. B. `fbtrace50.conf` |
| `OutputDirectory` | Ordner der Logdatei `trace_output_<Zeitstempel>.log` |
| `SessionName` | Präfix des Sitzungsnamens (nur `A–Z a–z 0–9 _ -`) |

Ein Schlüssel `Password` ist **verboten**: die Skripte brechen mit Exit-Code 2 ab, ohne den Wert zu nennen (ADR-002). Alle
Konfigurationsfehler werden gemeinsam gemeldet, bevor `fbtracemgr` aufgerufen wird. Einzelheiten:
`architecture/CONFIGURATION.md`, `features/TRACE_CAPTURE.md`.

---

## 4. C#-Parser bauen und bereitstellen (optional, empfohlen)

Der C#-Parser (`src/FirebirdTraceParser`, Cmdlet `ConvertFrom-FirebirdTrace`, ADR-003) liefert **dieselben** Objekte,
Warnungen und Meldungen wie der PowerShell-Parser (ein Paritätstest vergleicht jedes Feld) und ist deutlich schneller. An
einer synthetischen 15-MB-Datei gemessen: 1,6 s statt 13–14 s, Spitzenspeicher 196 MB statt 287 MB (Messung vom
2026-11-08, README). Er läuft nur unter PowerShell 7.

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build     # erzeugt bin\FirebirdTraceParser.dll
.\Show-TraceStructure.ps1 -Path trace.log -Verbose        # meldet "Engine: CSharp"
```

* **Fundort:** `Show-TraceStructure.ps1 -Engine Auto` (Standard) sucht `FirebirdTraceParser.dll` neben dem Skript, dann in
  `bin\`. Fehlt sie oder läuft Windows PowerShell 5.1, läuft der PowerShell-Parser (gleiches Ergebnis, langsamer).
  `-Engine CSharp` ohne DLL oder unter 5.1 ist ein Fehler; `-Engine PowerShell` erzwingt den Rückfall.
* **Gebaut wird reproduzierbar:** NuGet-Pakete sind über `src/FirebirdTraceParser/packages.lock.json` festgelegt (die CI
  baut im gesperrten Modus), Compilerwarnungen sind Fehler.
* **Sperre:** Ein PowerShell-Prozess, der die DLL geladen hat, sperrt sie. Vor einem Neubau diesen Prozess beenden.
* **Verteilung:** Die DLL wird bisher **nicht** ausgeliefert, nur lokal gebaut (offen: `TODO.md` → I22, Entscheidung
  Release mit Prüfsumme oder weiter selbst bauen). Wer kein .NET SDK hat, arbeitet mit dem PowerShell-Parser oder kopiert
  eine selbst gebaute DLL nach `bin\` (nur von einer vertrauenswürdigen eigenen Quelle).
* **Nach einem Update** des Quellcodes die DLL neu bauen; sonst läuft ein älterer C#-Parser neben neueren Skripten. Prüfen:
  `Show-TraceStructure.ps1 -Engine PowerShell` und `-Engine CSharp` über dieselbe kleine Datei sollen dieselbe Zahl
  Objekte liefern (`(… | Measure-Object).Count`); die Paritätstests prüfen jedes Feld (`-Gate Test`).

---

## 5. Trace-Konfiguration

Die Regeln stehen in der Datei, die `TraceConfigFilename` nennt. Mitgeliefert:

* **`fbtrace50.conf`** für Firebird 4.0 und 5.0 (Vorlage; alle Optionen existieren unverändert in der 5.0.4-Vorlage von
  Firebird):

| Option | Wert | Wirkung / Hinweis |
|---|---|---|
| `time_threshold` | `100` | nur Statements ab 100 ms; 0 = alles (Log wird sehr groß) |
| `log_connections`, `log_transactions` | `true` | Verbindungs- und Transaktionsereignisse |
| `log_statement_finish` | `true` | beendete Statements mit Dauer und Zählern |
| `log_errors` | `true` | **alle** Fehler. Nicht `include_gds_codes` setzen: dann schreibt Firebird **nur** die genannten Codes. Unerwünschte Fehler mit `exclude_gds_codes` ausblenden |
| `log_sweep` | `true` | Sweeps mit Transaktionszähler OIT/OAT/OST/Next |
| `print_plan` | `true` | klassischer Plan (`explain_plan` aus lassen — der Parser liest nur `PLAN (...)`) |
| `print_perf` | `true` | Tabellenstatistik (Natural/Index/…) |
| `max_sql_length` | `65000` | sonst schneidet Firebird den SQL-Text nach 300 Zeichen ab |
| `max_arg_length`, `max_arg_count` | `240`, `50` | Länge und Anzahl der Parameter |
| `log_initfini` | `false` | Start/Ende der Sitzung selbst |
| Abschnitt `services` | `log_services = true`, `log_service_query = false` | Dienste (Backup, Restore, …) ohne Statusabfragen |
| `log_procedure_finish`, `log_function_finish`, `log_trigger_finish` | auskommentiert | Prozeduren, Funktionen, Trigger; Trigger feuern je Datensatz und können das Log sehr groß machen; `time_threshold` gilt auch hier |

* **`fbtrace30.conf`** (älter): nur Fehler `lock_conflict` und `deadlock` über `include_gds_codes`; für bestehende
  Installationen.

**Datenminimierung:** So kurz und so schmal wie möglich aufzeichnen (Schwellwert, Dauer, ggf. Datenbankfilter), weil das
Log personenbezogene Daten enthält (Kapitel 9). Eine Option für den Datenbankfilter ist noch nicht als Vorlage vorhanden
(`BACKLOG.md`).

---

## 6. Zugang: Benutzer und Anmeldung (ADR-002)

Die Skripte melden sich am **Service-Manager** des lokalen Servers an (`-SE service_mgr`); es gibt keinen Fernzugriff. Das
Passwort steht nie in `config.json`, nie in der Befehlszeile, nie in einer Meldung.

| Weg | Konfiguration | Hinweis |
|---|---|---|
| Benutzer + **Passwortdatei** | `Username`, `PasswordFile` | `fbtracemgr` liest die Datei selbst (`-FETCH_PASSWORD`, erste Zeile); in der Befehlszeile steht nur der Pfad |
| **Windows-Anmeldung** | `"UseTrustedAuth": true` | Server braucht `AuthServer = Srp256, Win_Sspi` in `firebird.conf` (Neustart) und ein Mapping des Windows-Kontos auf einen Firebird-Benutzer; bisher nicht gegen einen echten Server geprüft |

Passwortdatei anlegen, nur für das eigene Konto lesbar, außerhalb des Repositories (Befehle in `operations/SETUP.md`);
**nach der Aufzeichnung löschen**.

**Eigener Trace-Benutzer statt SYSDBA** (empfohlen): Ein normaler Benutzer darf fremde Verbindungen tracen, wenn eine Rolle
mit dem Systemrecht `TRACE_ANY_ATTACHMENT` aktiv ist. Als SYSDBA, in der Datenbank, die aufgezeichnet wird:

```sql
CREATE USER TRACE_USER PASSWORD '<neues Passwort>';
CREATE ROLE TRACER SET SYSTEM PRIVILEGES TO TRACE_ANY_ATTACHMENT;
GRANT DEFAULT TRACER TO USER TRACE_USER;
```

Die Rolle gibt nur dieses eine Systemrecht, keine Tabellenrechte; sie liegt in der Datenbank, in der sie angelegt wurde.
In `config.json`: `"Username": "TRACE_USER"`, `"Role": "TRACER"`, dazu die Passwortdatei von `TRACE_USER`. Mit diesen
Skripten gegen einen echten Server noch nicht geprüft (bisher SYSDBA ohne Rolle). Stand das SYSDBA-Passwort je auf einer
Befehlszeile (früher `fbtracemgr -PASS`), das Passwort ändern.

Secrets-Regeln, Ablagen, Rotation: `operations/SECRETS_MANAGEMENT.md`, `architecture/CREDENTIAL_STRATEGY.md`,
`security/AUTHENTICATION.md`.

---

## 7. Eine Aufzeichnung betreiben

```powershell
pwsh -File .\trace_start.ps1     # Fenster 1: bleibt belegt, solange die Sitzung läuft
pwsh -File .\trace_stop.ps1      # Fenster 2: stoppt die gemerkte Sitzung (oder: -Id <n>)
```

* **Name und Datei:** Sitzung `<SessionName>_<yyyyMMdd_HHmmss>`, Ausgabe
  `<OutputDirectory>\trace_output_<yyyyMMdd_HHmmss>.log`; die laufende Sitzung merkt sich `trace_session.json` neben den
  Skripten.
* **Dauer festlegen:** Eine Sitzung schreibt, bis sie gestoppt wird. Verantwortliche und Dauer vorab bestimmen,
  Plattenplatz im Ausgabeordner beobachten (Warnsignale: `operations/MONITORING.md`).
* **Die Datei ist während der Aufzeichnung oft noch leer** (PowerShell puffert). Das ist normal.
* **Fenster hart geschlossen:** `trace_session.json` bleibt liegen; der nächste Start bricht mit Exit 2 ab. Dann
  `trace_stop.ps1` aufrufen (stoppt die Sitzung oder räumt auf).
* **Alle Sitzungen ansehen:**
  `fbtracemgr -SE service_mgr -USER <name> -FETCH_PASSWORD <datei> -LIST` (Anmeldung wie in Kapitel 6).

Exit-Codes der Trace-Skripte:

| Code | Bedeutung |
|---|---|
| 0 | ok |
| 1 | `config.json` fehlt |
| 2 | Konfiguration ungültig (alle Fehler in der Meldung) oder beim Start: noch eine gemerkte Sitzung |
| 3 | `trace_stop.ps1`: keine passende laufende Sitzung |
| 4 | `trace_stop.ps1`: mehrere passende Sitzungen (dann `-Id`) |
| 5 | `fbtracemgr` meldet einen Fehler bzw. bestätigt den Stopp nicht |
| 6 | unerwarteter Fehler |

Checkliste für den Einsatz auf einem Datenbankserver: `operations/RUNBOOK.md` → Deployment-Checkliste.

---

## 8. Der Pseudonymisierungsschlüssel (ADR-001)

`Pseudonymize-FirebirdTrace.ps1` bildet Pseudonyme als gekürzten **HMAC-SHA256** über den Klartext mit einem geheimen
Schlüssel. Ohne Schlüssel kann ein Empfänger Pseudonyme weder vorausberechnen noch gezielt prüfen; wer den Schlüssel hat,
kann Vermutungen bestätigen.

* **Schlüsseldatei (`-KeyFile`):** Base64, mindestens 32 Byte. Fehlt die Datei, legt das Skript sie mit 32 Zufallsbytes an
  und beschränkt die Rechte auf den aktuellen Benutzer (Warnung bei der Erzeugung). Ohne `-KeyFile`: Zufallsschlüssel nur
  für diesen Lauf — Pseudonyme sind dann in diesem Lauf konsistent, über Läufe hinweg nicht vergleichbar und für niemanden
  umkehrbar.
* **Aufbewahrung:** beim Datenverantwortlichen, **nicht** zusammen mit den Exporten, nie im Repository, nie weitergeben. Eine
  Sicherung des Schlüssels getrennt vom Export aufbewahren, solange Ergebnisse auf Klartext zurückgeführt werden sollen.
* **Gleicher Schlüssel = gleiche Pseudonyme:** nötig für Vorher/Nachher-Vergleiche und Trends über mehrere Läufe.
* **Rotation:** Ein neuer Schlüssel macht alle Pseudonyme neu; Exporte mit altem und neuem Schlüssel sind **nicht**
  vergleichbar. Alten Schlüssel und alte `-MappingFile` so lange aufheben, wie Ergebnisse alter Exporte zugeordnet werden
  müssen. Rotieren bei Verdacht auf Offenlegung oder wenn Empfänger wechseln, denen die Vergleichbarkeit nicht mehr zustehen
  soll.
* **Zuordnungsdatei (`-MappingFile`)** `Pseudonym;Original`: enthält Klartext, gleich schützen wie die Rohdaten.
* Es bleibt **Pseudonymisierung**, keine Anonymisierung; die Daten bleiben personenbezogen. Feldabdeckung und Restrisiken:
  `features/PSEUDONYMIZATION.md`.

---

## 9. Daten, Aufbewahrung, Datenschutz

Trace-Rohdaten und Exporte sind mindestens **vertraulich** (Benutzer, Adressen, Programmpfade, SQL-Texte, Parameter);
wird eine Datenbank mit Personal- oder besonders geschützten Daten aufgezeichnet, **streng vertraulich**. Pseudonymisierte
Exporte bleiben personenbezogen. Regeln: `security/DATA_HANDLING.md` (Klassen, Speicherorte, Löschfristen).

* Rohdaten nur auf dem Datenbankserver oder einem zugriffsgeschützten Analyseplatz, nicht auf breit zugänglichen Laufwerken.
* Rohdatei und Passwortdatei löschen, sobald die Analyse abgeschlossen ist.
* `.gitignore` schützt `**/*.log`, `trace_output*`, `config*.json` und `trace_session.json`; ein Test prüft, dass `config.json`
  nicht in git ist. Eine **interne Denylist** (`.internal-terms`, lokal und gitignoriert) und die Hooks in
  `tools/git-hooks/` (`git config core.hooksPath tools/git-hooks`) verhindern, dass interne Begriffe in Commits landen.
* Bei einem Vorfall (Daten im öffentlichen Repo, Klartext-Reste in einem Export): `operations/INCIDENT_RESPONSE.md`.

---

## 10. Aktualisieren, Veröffentlichen, prüfen

**Aktualisieren:** `git pull` (oder neuen Stand kopieren), DLL neu bauen (Kapitel 4), `config.json` bleibt. Bisher gibt es keine
Tags oder Releases; Nutzer verwenden `main`. Vor einem Release: Dependency-Audit und Security-Abgleich mit datiertem Eintrag in
`security/DEPENDENCY_AUDIT.md`, Gates grün, READMEs gegen den Code geprüft, Tag `vMAJOR.MINOR.PATCH` (`operations/DEPLOYMENT.md`).
**Zurückrollen:** `git checkout <tag>` bzw. `git revert` (kein Force-Push auf `main`); danach Gates und Stichprobe mit einem
synthetischen Trace.

**Qualitätssicherung lokal und in der CI** (dieselben Befehle, `.github/workflows/ci.yml`: PowerShell 7 mit Build, Lint und
Tests; Windows PowerShell 5.1 mit Tests):

```powershell
pwsh -File ./tools/Invoke-QualityGate.ps1                 # Build + Lint + Test, je in eigenem Prozess
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Build     # nur dotnet build nach bin\
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Lint      # PSScriptAnalyzer
pwsh -File ./tools/Invoke-QualityGate.ps1 -Gate Test      # Pester
```

Das Skript importiert **genau** die Modulversionen aus `tests/RequiredModules.psd1` (fehlt eine, bricht es ab) — nicht
ein bloßes `Invoke-Pester` verwenden. Exit-Codes: 0 grün, 1 Analyzer-Befunde, 2 fehlgeschlagene Tests, 3 gepinntes Modul
fehlt, 4 Build fehlgeschlagen oder `dotnet` fehlt. Die Tests des C#-Parsers brauchen den Build.

**Sicherheitsabgleich:** Kadenz-Sweep alle 14 Tage (Marker im Kopf von `STATE.md`); Befehle und Befunde:
`security/DEPENDENCY_AUDIT.md`, Prinzip `principles/SECURITY_CURRENCY.md`.

---

## 11. Virenscanner-Fehlalarme bei Testdateien

PowerShell-Testdateien, die Sonderzeichen aus Zeichencodes zur Laufzeit zusammensetzen (`[char]`-Umwandlungen,
`[char]::ConvertFromUtf32`, Reflection), meldet mancher Virenscanner als Schadcode und entfernt sie. Beobachtet am
2026-11-10: G DATA entfernte `tests/FirebirdTraceParser.Diagnostics.Parity.Tests.ps1` (Heuristik-Treffer, Fehlalarm; ein
Teilfix genügte nicht). Die Datei schreibt die Zeichen seither als `` `u{…} ``-Escapes (Lehre `LESSONS_LEARNED.md` L12).

Wenn eine Testdatei fehlt oder in Quarantäne liegt:

1. Datei aus git wiederherstellen (`git checkout -- <datei>`).
2. Fehlalarm beim Hersteller des Scanners melden (Datei, Scanner, Signaturname).
3. Tritt er erneut auf, das Muster in der Datei **vollständig** ersetzen (nicht nur einen Teil) statt das ganze Repository
   dauerhaft von der Prüfung auszunehmen.

Bisher betraf es nur eine Testdatei, keines der ausgelieferten Skripte.

---

## 12. Fehlersuche

| Beobachtung | Ursache / Maßnahme |
|---|---|
| Skripte starten nicht („Ausführung deaktiviert“) | Ausführungsrichtlinie und `Unblock-File` (Kapitel 3.2) |
| Trace-Skript meldet „PowerShell 7.4 nötig“ | mit `pwsh` starten, nicht mit `powershell.exe` |
| Exit 1/2 beim Start | `config.json` fehlt bzw. ungültig; Meldung nennt alle Fehler; bei Exit 2 auch: gemerkte Sitzung → `trace_stop.ps1` |
| Exit 3/4 beim Stopp | keine bzw. mehrere passende Sitzungen → `-LIST`, dann `-Id <n>` |
| Exit 5 / leere Datei nach dem Stopp | Anmeldung, Rechte oder Erreichbarkeit (Meldung auf der Konsole); leere Datei: keine Statements über `time_threshold` |
| `-TRUSTED` scheitert | Server erlaubt keine Windows-Anmeldung (`AuthServer = Srp256, Win_Sspi`) |
| Parser sehr langsam | `-Verbose`: läuft `Engine: PowerShell`? DLL bauen (Kapitel 4) |
| Build schlägt fehl | `dotnet` fehlt oder DLL gesperrt (PowerShell-Prozess beenden); SDK-Version laut `global.json` |
| Tests laufen nicht | gepinnte Module installieren (`operations/SETUP.md`); Gate-Skript statt `Invoke-Pester` |
| Datei einer Testsuite fehlt | Virenscanner (Kapitel 11) |

Weitere Fälle: `operations/RUNBOOK.md` (Troubleshooting), `architecture/ERROR_HANDLING.md` (Fehlerarten und Exit-Codes).
