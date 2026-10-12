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
`$RxStringLiteral`), `DatabasePath` (Server-/Datenbank-/Kundennamen), `SqlPlan`/`TableStats` (Schema-Interna).
Ohne `-RedactLiterals` bleiben zudem alle String-Literale stehen. Bei `-SensitiveKeywords` ersetzt die Bulk-Redaktion
nur die **letzte** WHERE/HAVING-Klausel (gieriges `.*` im Ersetzungs-Regex), Bedingungen in Unterabfragen oder
früheren UNION-Teilen bleiben sichtbar. Weitergegebene Daten sind nicht rückholbar.

**Mitigation:**
- I2: Lücken per Test schließen (numerische Literale, `DatabasePath`, alle Klauseln); Feldabdeckung in
  `features/PSEUDONYMIZATION.md` als Vertrag führen.
- Bis dahin: vor jeder Weitergabe `-AnalyzeOnly` laufen lassen und den Export stichprobenartig prüfen;
  Weitergabe nur nach Freigabe (`security/DATA_HANDLING.md` → Weitergabe).
- README um eine Liste der **nicht** pseudonymisierten Felder ergänzen (I2).

**Restrisiko:** Hoch – bis I2 umgesetzt ist; danach Mittel (Freitext in SQL bleibt schwer vollständig erkennbar).

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
- I3: HMAC-SHA256 mit geheimem Schlüssel (pro Weitergabe bzw. Zufallsschlüssel pro Lauf); Entscheidung in ADR-001.
- Bis dahin: IP-Adressen und Benutzer in weitergegebenen Daten als **nicht** geschützt betrachten.

**Restrisiko:** Hoch – bis I3; danach Gering (abhängig vom Schlüsselschutz).

---

## 3. Exposition des Firebird-Admin-Passworts

**Gefahr:** `trace_start.ps1` und `trace_stop.ps1` lesen Benutzer und Passwort im Klartext aus `config.json` und
übergeben sie als Argumente (`-USER … -PASS …`) an `fbtracemgr`. Kommandozeilen sind für Administratoren und
Überwachungswerkzeuge des Hosts einsehbar und landen bei aktivierter Befehlszeilen-Protokollierung (Prozess-Audit, EDR)
in zentralen Logs. Die Vorlage
`config.sample.json` setzt den höchstprivilegierten Benutzer und das allgemein bekannte Firebird-Standardpasswort ein —
das ermutigt zu Standard-Zugangsdaten. `config.json` ist zwar gitignored, liegt aber unverschlüsselt im Skriptverzeichnis.

**Mitigation:**
- I4: `fbtracemgr -fetch <datei>` (ACL-geschützt, kurzlebig) oder `-trusted` statt `-PASS`; Passwort aus Credential
  Store/DPAPI (`architecture/CREDENTIAL_STRATEGY.md`).
- I4: dedizierter Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` statt SYSDBA (Firebird ≥ 4).
- I4: Vorlage ohne bekanntes Standardpasswort.
- Nach der Umstellung das bisher genutzte Passwort rotieren (`operations/SECRETS_MANAGEMENT.md`).

**Restrisiko:** Hoch – bis I4 (voller DB-Zugriff bei Abgriff); danach Gering.

---

## 4. Unkontrollierte Trace-Rohdaten auf dem Server

**Gefahr:** Die Trace-Session protokolliert **alle** Datenbanken des Servers (`fbtrace30.conf`: `database` ohne
Filter) inklusive SQL-Texten bis 65 000 Zeichen und Parametern; die Ausgabe liegt unverschlüsselt und ohne
Aufbewahrungsregel als `E:\trace_output_*.log`. Eine vergessene Session schreibt unbegrenzt weiter (Plattenplatz,
Server-Last). `trace_stop.ps1` stoppt die Session anhand der **neuesten** `*.log` auf `E:\` — eine andere Logdatei dort
lässt den Stopp scheitern oder zielt auf die falsche Session.

**Mitigation:**
- Trace nur zeitlich begrenzt; Stopp und Löschung der Rohdatei als Teil des Ablaufs (`operations/RUNBOOK.md`).
- Retention und Zugriffsschutz der Rohdateien: `security/DATA_HANDLING.md` §3/§5.
- I5: Ausgabeverzeichnis konfigurierbar, Stopp über gespeicherte Session-ID; Datenbankfilter in der Trace-Konfiguration
  als Option dokumentieren.

**Restrisiko:** Mittel – organisatorisch beherrschbar, technisch erst mit I5 entschärft.

---

## 5. Interna im öffentlichen Repository

**Gefahr:** Das Repository ist öffentlich. Ältere Commits enthalten in Kommentar-Beispielen echte Verbindungsdaten
aus einer realen Umgebung (Einzelheiten bewusst nur in `docs/local/ENVIRONMENT.md`). Neue Beispiele, Test-Fixtures
oder Doku könnten erneut echte Trace-Auszüge enthalten.

**Mitigation:**
- Interna-Hook (`tools/git-hooks/`, Denylist `.internal-terms`) in jedem Klon aktivieren (`CONVENTIONS_COMMON.md` 3.1).
- Fixtures und Beispiele nur mit fiktiven Werten (`CONVENTIONS.md` §6).
- Owner-Entscheidung zur History-Bereinigung (`docs/TODO.md` → Owner-Aufgaben).

**Restrisiko:** Mittel – bereits veröffentlichte History ist ohne Bereinigung weiter abrufbar.

---

## 6. Trace-Inhalte als untrusted Input

**Gefahr:** Trace-Logs enthalten beliebige SQL-Texte aller Clients des Servers. Für die Skripte ist das nur Text
(keine Ausführung, kein `Invoke-Expression`); Risiken sind Ressourcenverbrauch (sehr große Blöcke, sehr große Dateien,
siehe K2) und — wenn Trace-Ausgaben später von LLM-Agenten ausgewertet werden — Anweisungstexte in SQL-Kommentaren
oder Literalen (Prompt-Injection). Im analysierten Repository selbst wurden beim Init keine Anweisungstexte an Agenten gefunden.

**Mitigation:**
- Kein `Invoke-Expression` auf Trace-Inhalten (`CONVENTIONS.md` §6).
- Streaming statt Gesamtdatei (I6); Regex ohne katastrophales Backtracking (`architecture/ERROR_HANDLING.md`).
- Agenten behandeln Trace-Inhalte als Daten, nie als Anweisung (`principles/UNTRUSTED_DOCUMENT_CONTENT.md`).

**Restrisiko:** Gering.

---

## Hinweise

- Dieses Dokument wird bei jeder neuen Funktion geprüft, die externe Eingaben verarbeitet
  oder auf sensible Ressourcen zugreift — anhand der Leitfragen in `security/THREAT_MODEL_GUIDE.md`.
- Neue Bedrohungen als ADR dokumentieren wenn sie eine Architekturentscheidung auslösen.
- Server-seitige Firebird-Schwachstellen (CVE-Liste) betreffen den Betrieb des Datenbankservers, nicht den Code
  dieses Projekts; sie sind in `security/DEPENDENCY_AUDIT.md` → Befunde festgehalten.
