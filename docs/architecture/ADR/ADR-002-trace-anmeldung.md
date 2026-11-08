# ADR-002: Anmeldung der Trace-Skripte über Passwortdatei oder Windows-Anmeldung

**Status:** Accepted
**Datum:** 2026-11-08

## 1. Kontext & Problem

`trace_start.ps1` und `trace_stop.ps1` lasen Benutzer und Passwort im Klartext aus `config.json` und gaben beides als
`fbtracemgr -USER … -PASS …` weiter. Die Befehlszeile ist für Administratoren und Überwachungswerkzeuge sichtbar und
landet bei Befehlszeilen-Protokollierung in zentralen Logs; die Vorlage nannte SYSDBA mit dem bekannten
Standardpasswort (`security/THREAT_MODEL.md` Bedrohung 3). Der Owner hat eine Fassung für Firebird 5.0.4 entworfen und
damit echte Traces aufgezeichnet; sie wird mit diesem ADR übernommen.

## 2. Betrachtete Alternativen

* **Passwort per `-PASS`** (Bestand): Passwort in der Befehlszeile — verworfen.
* **Passwortdatei, die `fbtracemgr` selbst liest** (`-FETCH_PASSWORD <datei>`, erste Zeile): Die Befehlszeile enthält
  nur den Pfad. Die Datei legt der Nutzer einmal an und schränkt die Rechte auf sein Konto ein.
* **DPAPI-Datei (`Export-Clixml`) + kurzlebige Passwortdatei:** Das Skript entschlüsselt und schreibt die Datei nur für
  den Aufruf. `trace_start.ps1` blockiert aber während der ganzen Aufzeichnung; die Datei müsste Stunden liegen oder
  über einen eigenen Prozessstart (`Start-Process`) früher gelöscht werden, der die byte-genaue Umleitung der Ausgabe
  verliert. Gewinn gegenüber einer dauerhaft ACL-geschützten Datei klein, Aufwand und Fehlerquellen größer.
* **Windows-Anmeldung** (`-TRUSTED`): kein Firebird-Passwort; braucht `AuthServer = Srp256, Win_Sspi` und ein
  Benutzer-Mapping auf dem Server.
* **Umgebungsvariable `ISC_PASSWORD`:** für andere Prozesse desselben Benutzers lesbar, prozessweiter Zustand — verworfen.

## 3. Entscheidung

1. Anmeldung entweder mit `-USER <name> -FETCH_PASSWORD <datei>` (Schlüssel `Username`, `PasswordFile`) oder mit
   `-TRUSTED` (`UseTrustedAuth: true`). Das Passwort steht nie in `config.json`, nie in der Befehlszeile, nie in einer
   Meldung.
2. Steht noch ein Schlüssel `Password` in `config.json`, brechen die Skripte mit Exit-Code 2 ab (der Wert wird nicht
   genannt) — so bleibt kein altes Klartext-Passwort unbemerkt liegen.
3. Optional `-ROLE <rolle>` (Schlüssel `Role`): Trace-Benutzer mit einer Rolle, die das Systemrecht
   `TRACE_ANY_ATTACHMENT` hat, statt SYSDBA. Vorlage: `TRACE_USER` / `TRACER` (fiktiv).
4. Die Passwortdatei liegt außerhalb des Repos (Vorlage: `%LOCALAPPDATA%\PSFirebirdTraceParser\`); Rechte nur für den
   ausführenden Benutzer (`operations/SETUP.md`). Die Skripte prüfen nur, dass sie existiert.

Randentscheidungen derselben Übernahme (keine eigene Architekturfrage, hier mit festgehalten):

* Die Trace-Skripte verlangen **PowerShell 7.4+** (`#Requires -Version 7.4`). Gemessen 2026-11-08: dieselben drei Bytes
  `C3 A4 0A` (UTF-8 „ä" + LF) landen unter 7.6 unverändert in der Datei, unter Windows PowerShell 5.1 als
  `FF FE E4 00 0D 00 0A 00` (UTF-16 mit BOM, CRLF). Parser und Pseudonymisierer bleiben 5.1-fähig.
* Gemeinsame Logik liegt in `TraceCommon.ps1`, das beide Skripte per Dot-Sourcing laden — kein Modul (`.psm1` mit
  Manifest), solange nur die zwei Skripte im selben Ordner es nutzen.

## 4. Begründung

* Die Befehlszeile ist der Kanal, über den das Passwort bisher abfloss; mit Datei oder Windows-Anmeldung enthält sie
  keins mehr. Das ist mit `fbtracemgr` selbst prüfbar (Tests: nur der Pfad geht an das Programm).
* Die Datei-Variante ist mit echten Traces gegen Firebird 5.0.4 benutzt (Owner, 2026-11-07/08; drei Logs, jedes beginnt
  mit `Trace session ID … started`) und ohne Zusatzwerkzeug verständlich. Benutzt wurde sie mit SYSDBA und ohne Rolle.

## 5. Folgen

* Positiv: kein Passwort in Befehlszeile, `config.json` oder Repo; Least Privilege über die Rolle möglich.
* Negativ / Restrisiko: Die Passwortdatei ist Klartext auf der Platte; Schutz nur über die Dateirechte (Administratoren
  und Sicherungen sehen sie). Nach der Aufzeichnung löschen oder das Passwort rotieren. Das bisher per `-PASS` genutzte
  Passwort rotieren (`operations/SECRETS_MANAGEMENT.md`).
* Ungeprüft: `-TRUSTED` und die Rolle `TRACER` gegen einen echten Server.
