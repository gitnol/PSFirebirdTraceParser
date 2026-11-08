# Threat Model & Mitigationen – PSFirebirdTraceParser

---

Leitfragen zum Finden von Bedrohungen: `security/THREAT_MODEL_GUIDE.md` (vom Template gepflegt).
Öffentliches oder potenziell öffentliches Repo: keine internen Hosts, Versionen oder Betroffenheiten konkreter Systeme —
die gehören nach `docs/local/` (`CONVENTIONS_COMMON.md` 3.1).

Stand: Init 2026-10-11, abgeleitet aus dem Code (`Pseudonymize-FirebirdTrace.ps1`, `trace_start.ps1`,
`trace_stop.ps1`, `Show-TraceStructure.ps1`, `config.sample.json`) und dem Security-Currency-Abgleich
(`security/DEPENDENCY_AUDIT.md` → Befunde).

**Schutzgüter:** (a) Inhalte der Trace-Logs — SQL-Texte mit Literalen und Parametern, Benutzer, Client-IP-Adressen,
Anwendungspfade, Datenbankpfade; (b) das Firebird-Admin-Credential der Trace-Skripte; (c) Verfügbarkeit des
Datenbankservers (Plattenplatz, Trace-Last).

---

## 1. Klartext-Reste in „pseudonymisierten" Exporten

**Gefahr:** Nutzer geben die Ausgabe von `Pseudonymize-FirebirdTrace.ps1` laut README an Dritte weiter
(„safe sharing … for external analysis"). Im Ergebnis bleiben identifizierende Daten im Klartext:
numerische Literale im SQL (`WHERE <Kundennummer> = 4711` — nur `'…'`-Literale werden behandelt,
`$RxStringLiteral`), `DatabasePath` (Server-/Datenbank-/Kundennamen), `SqlPlan`/`TableStats`/`TableCounts` sowie seit I12 `RoutineName`/`TriggerTable` (Schema-Interna; `-SensitiveKeywords` wirkt darauf nicht).
Ohne `-RedactLiterals` bleiben zudem alle String-Literale stehen. Bei `-SensitiveKeywords` ersetzt die Bulk-Redaktion
nur die **letzte** WHERE/HAVING-Klausel (gieriges `.*` im Ersetzungs-Regex), Bedingungen in Unterabfragen oder
früheren UNION-Teilen bleiben sichtbar. Weitergegebene Daten sind nicht rückholbar.

**Mitigation:**
- Umgesetzt in I2 (2026-11-07): numerische Literale und Einzelzeichen mit `-RedactLiterals`, `DatabasePath` immer,
  Bulk-Redaktion ab der ersten WHERE/HAVING-Klausel; Feldabdeckung als Vertrag in `features/PSEUDONYMIZATION.md`;
  15 Tests, Mutationsprüfung 11/11.
- Bis dahin: vor jeder Weitergabe `-AnalyzeOnly` laufen lassen und den Export stichprobenartig prüfen;
  Weitergabe nur nach Freigabe (`security/DATA_HANDLING.md` → Weitergabe).
- README um eine Liste der **nicht** pseudonymisierten Felder ergänzen (I2).

**Restrisiko:** Mittel – Freitext in SQL bleibt schwer vollständig erkennbar; ohne `-RedactLiterals` bleiben Literale Klartext.

---

## 2. Umkehrbare Pseudonyme (ungesalzener, gekürzter SHA-256)

**Gefahr:** `Get-ShortHash` berechnet `SHA256(UTF8(Wert))` ohne Schlüssel und kürzt auf `-HashLength` Hex-Zeichen
(Default 12). Für kleine Wertebereiche ist das umkehrbar: alle IPv4-Adressen (2^32) lassen sich in kurzer Zeit
vorausberechnen; Benutzernamen aus einem bekannten Verzeichnis per Wörterbuch. Das Pseudonym ist zudem über alle
Läufe und Nutzer gleich, damit sind Datensätze verschiedener Weitergaben verknüpfbar. Die README warnt vor
Wörterbuchangriffen, die Default-Nutzung schützt aber IP-Adressen praktisch nicht. Die EDPB-Leitlinien 01/2025 zur
Pseudonymisierung nennen schlüsselbasierte Verfahren (MAC/HMAC) als stärkere Technik (Quelle: Befunde in
`security/DEPENDENCY_AUDIT.md`).

**Mitigation:**
- Umgesetzt in I3 (2026-11-07, ADR-001): HMAC-SHA256 mit Schlüssel aus `-KeyFile` (≥ 32 Byte, Rechte nur aktueller Benutzer)
  bzw. Zufallsschlüssel je Lauf; optionale Zuordnungsdatei nur beim Verantwortlichen; 8 Tests, Mutationsprüfung 5/5.

**Restrisiko:** Gering – abhängig vom Schutz der Schlüssel- und Zuordnungsdatei; bei Abfluss des Schlüssels sind vermutete Werte prüfbar.

---

## 3. Exposition des Firebird-Admin-Passworts

**Gefahr:** `trace_start.ps1` und `trace_stop.ps1` lesen Benutzer und Passwort im Klartext aus `config.json` und
übergeben sie als Argumente (`-USER … -PASS …`) an `fbtracemgr`. Kommandozeilen sind für Administratoren und
Überwachungswerkzeuge des Hosts einsehbar und landen bei aktivierter Befehlszeilen-Protokollierung (Prozess-Audit, EDR)
in zentralen Logs. Die Vorlage
`config.sample.json` setzt den höchstprivilegierten Benutzer und das allgemein bekannte Firebird-Standardpasswort ein —
das ermutigt zu Standard-Zugangsdaten. `config.json` ist zwar gitignored, liegt aber unverschlüsselt im Skriptverzeichnis.

**Mitigation (seit I4, ADR-002):**
- `fbtracemgr -FETCH_PASSWORD <datei>` oder `-TRUSTED` statt `-PASS`: Die Befehlszeile enthält nur den Pfad der
  Passwortdatei (Test: das Passwort erscheint in keinem Argument). Ein `Password`-Schlüssel in `config.json` bricht ab.
- Optional Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` statt SYSDBA (`-ROLE`, Firebird ≥ 4; `operations/SETUP.md`).
- Vorlage ohne Passwort und ohne SYSDBA.
- Nach der Umstellung das bisher genutzte Passwort rotieren (`operations/SECRETS_MANAGEMENT.md`).

**Restrisiko:** Gering bis Mittel – die Passwortdatei ist Klartext, geschützt nur durch Dateirechte; im echten Einsatz
bisher mit SYSDBA ohne Rolle (voller DB-Zugriff, wenn die Datei abfließt). Mit Trace-Benutzer und Rolle: Gering.

---

## 4. Unkontrollierte Trace-Rohdaten auf dem Server

**Gefahr:** Die Trace-Session protokolliert **alle** Datenbanken des Servers (`fbtrace50.conf`/`fbtrace30.conf`:
`database` ohne Filter) inklusive SQL-Texten bis 65 000 Zeichen und Parametern; die Ausgabe liegt unverschlüsselt und
ohne Aufbewahrungsregel als `<OutputDirectory>\trace_output_*.log`. Eine vergessene Session schreibt unbegrenzt weiter
(Plattenplatz, Server-Last).

**Mitigation:**
- Trace nur zeitlich begrenzt; Stopp und Löschung der Rohdatei als Teil des Ablaufs (`operations/RUNBOOK.md`).
- Retention und Zugriffsschutz der Rohdateien: `security/DATA_HANDLING.md` §3/§5.
- Seit I5: Ausgabeordner aus `config.json`, Stopp über den gemerkten Sitzungsnamen (nicht mehr „neueste Logdatei");
  ein zweiter Start wird abgelehnt, solange eine Sitzung gemerkt ist.
- Offen: Datenbankfilter (`include_filter`) in der Trace-Konfiguration als Option dokumentieren (`BACKLOG.md`).

**Restrisiko:** Mittel – organisatorisch beherrschbar; vergessene Sitzungen und Rohdateien bleiben ein Ablaufthema.

---

## 5. Interna im öffentlichen Repository

**Gefahr:** Das Repository ist öffentlich. Ältere Commits enthalten in Kommentar-Beispielen echte Verbindungsdaten
aus einer realen Umgebung (Einzelheiten bewusst nur in `docs/local/ENVIRONMENT.md`). Neue Beispiele, Test-Fixtures
oder Doku könnten erneut echte Trace-Auszüge enthalten.

**Mitigation:**
- Interna-Hook (`tools/git-hooks/`, Denylist `.internal-terms`) in jedem Klon aktivieren (`CONVENTIONS_COMMON.md` 3.1);
  im Arbeitsklon des Owners seit 2026-11-08 aktiv. Er prüft nur neue Commits, nicht die History.
- Fixtures und Beispiele nur mit fiktiven Werten (`CONVENTIONS.md` §6).
- Owner-Entscheidung 2026-11-08: History **nicht** bereinigen (zwei interne Begriffe in je zwei Commits, kein echtes
  Passwort; ein Force-Push bräche Klone, Caches und Forks behielten die alten Stände). Ausgleich: SYSDBA-Passwort ändern.

**Restrisiko:** Mittel, akzeptiert (2026-11-08) – die veröffentlichte History bleibt abrufbar.

---

## 6. Trace-Inhalte als untrusted Input

**Gefahr:** Trace-Logs enthalten beliebige SQL-Texte aller Clients des Servers. Für die Skripte ist das nur Text
(keine Ausführung, kein `Invoke-Expression`); Risiken sind Ressourcenverbrauch (sehr große Blöcke, sehr große Dateien,
siehe K2) und — wenn Trace-Ausgaben später von LLM-Agenten ausgewertet werden — Anweisungstexte in SQL-Kommentaren
oder Literalen (Prompt-Injection). Im analysierten Repository selbst wurden beim Init keine Anweisungstexte an Agenten gefunden.

**Mitigation:**
- Kein `Invoke-Expression` auf Trace-Inhalten (`CONVENTIONS.md` §6).
- Streaming statt Gesamtdatei (I6); Regex ohne katastrophales Backtracking (`architecture/ERROR_HANDLING.md`); seit I13
  Zeitlimit je Regex-Auswertung und Obergrenze Zeilen je Ereignis (`-RegexTimeoutSeconds`, `-MaxBlockLines`), Warnungen
  ohne Trace-Inhalt.
- Agenten behandeln Trace-Inhalte als Daten, nie als Anweisung (`principles/UNTRUSTED_DOCUMENT_CONTENT.md`).

**Restrisiko:** Gering.

---

## Hinweise

- Dieses Dokument wird bei jeder neuen Funktion geprüft, die externe Eingaben verarbeitet
  oder auf sensible Ressourcen zugreift — anhand der Leitfragen in `security/THREAT_MODEL_GUIDE.md`.
- Neue Bedrohungen als ADR dokumentieren wenn sie eine Architekturentscheidung auslösen.
- Server-seitige Firebird-Schwachstellen (CVE-Liste) betreffen den Betrieb des Datenbankservers, nicht den Code
  dieses Projekts; sie sind in `security/DEPENDENCY_AUDIT.md` → Befunde festgehalten.
