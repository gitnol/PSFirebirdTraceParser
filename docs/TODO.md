# TODO – PSFirebirdTraceParser

Einzige Quelle des Inkrementplans (KICKOFF verweist nur hierher). Pro Inkrement: Aufgaben und — falls über die
Standard-DoD hinaus nötig — zusätzliche Kriterien. Ein Inkrement gilt erst als erledigt, wenn die Standard-DoD
**und** seine eigenen Kriterien erfüllt sind.

Parkplatz für noch unspezifizierte Ideen: `BACKLOG.md`.
Bekannte Bugs ohne aktiven Fix: `KNOWN_ISSUES.md`.

---

## Standard-Definition of Done (gilt für jedes Inkrement — nicht abhaken, sie bleibt stehen)

- Code-Änderungen abgeschlossen, kein TODO-/FIXME-Kommentar offen
- Quality Gates grün (`CONVENTIONS_COMMON.md` §5; Befehle in `CONVENTIONS.md`)
- Integration-Tests grün, falls relevant
- Security-Checkliste aus `CONVENTIONS.md` durchgegangen (falls der Stack eine liefert)
- Trigger-Matrix in `KICKOFF.md` Phase 3a geprüft → alle relevanten Docs aktualisiert
  (`architecture/OVERVIEW.md`, `features/`, `architecture/`, `security/`, `GLOSSARY.md`, `KNOWN_ISSUES.md`, `LESSONS_LEARNED.md`)
- `STATE.md`: Tabellenzeile + „Nächster Schritt"-Abschnitt aktualisiert
- `CHANGELOG.md`: neuer Abschnitt mit Datum + Inkrement-Titel + Sections
  (Added / Changed / Fixed / Removed / Security / Confidence / Ungeprüft / Lessons Learned)
- KICKOFF Phase 3b vollständig (Struktur-Check, TODO-Verschiebung, Advocatus-Diaboli-Gate)
- Commit erstellt (`<type>(<scope>): <desc>`); Commit-Hash in `STATE.md` eingetragen

---

## Aktuell (Hohe Priorität)

### I2: Pseudonymisierung – Klartext-Lücken schließen (mit Pester-Grundgerüst)

Bedrohung 1 in `security/THREAT_MODEL.md`. Der Pseudonymisierer lässt Werte stehen, die Personen oder
Geschäftsvorgänge identifizieren können; Ergebnisse werden laut README an Dritte weitergegeben.

**Aufgaben:**

- [ ] Test-Grundgerüst: `tests/RequiredModules.psd1` (Pester-Version pinnen, Auswahl 5.x vs. 6.x laut
      `security/DEPENDENCY_AUDIT.md` begründen), `PSScriptAnalyzerSettings.psd1`, Gate-Befehle aus `CONVENTIONS.md` §9 lauffähig
- [ ] Charakterisierungstests für `Pseudonymize-FirebirdTrace.ps1` (Ist-Verhalten: User, ClientIP, ApplicationPath,
      ProtocolInfo, Params, String-Literale mit `-RedactLiterals`/`-SensitiveKeywords`, `-AnalyzeOnly`), Diskriminierung
      per Mutationsprüfung (`testing/UNIT_TESTS.md` 8.6)
- [ ] Rote Tests, dann Fix: numerische Literale in WHERE/HAVING werden bei `-RedactLiterals` pseudonymisiert
- [ ] Rote Tests, dann Fix: `DatabasePath` wird pseudonymisiert (Datenbank-/Kundennamen, Serverpfade)
- [ ] Rote Tests, dann Fix: Bulk-Redaktion bei `-SensitiveKeywords` erfasst **alle** WHERE/HAVING-Klauseln (heute nur die letzte)
- [ ] Zuweisung an die automatische Variable `$matches` im `-AnalyzeOnly`-Zweig entfernen (KNOWN_ISSUES K6)
- [ ] README.md/README.de.md: Liste der pseudonymisierten und **nicht** pseudonymisierten Felder ergänzen

**Zusätzliche DoD** (nur, was über die Standard-DoD hinausgeht):

- [ ] Kein Feld aus `features/PSEUDONYMIZATION.md` → „Feldabdeckung" steht mehr ohne Entscheidung (pseudonymisiert oder begründet im Klartext)

### I3: Pseudonymisierung – geheimer Schlüssel statt ungesalzenem SHA-256

Bedrohung 2 in `security/THREAT_MODEL.md`: ungesalzene, gekürzte SHA-256-Werte sind für kleine Wertebereiche
(IPv4-Adressen, bekannte Benutzerlisten) per Wörterbuch umkehrbar.

**Aufgaben:**

- [ ] ADR-001: Schlüsselverfahren (HMAC-SHA256), Schlüsselquelle (Parameter als `SecureString` bzw. Zufallsschlüssel pro
      Lauf), Konsistenz über mehrere Läufe, Verbleib des Schlüssels
- [ ] Rote Tests: gleicher Wert + anderer Schlüssel → anderes Pseudonym; ohne Schlüssel kein Klartext-Hash-Vergleich möglich
- [ ] `Get-ShortHash` auf HMAC umstellen; Schlüssel nie loggen oder ausgeben
- [ ] README-Sicherheitshinweis aktualisieren (Pseudonymisierung bleibt personenbezogen, `security/DATA_HANDLING.md`)

### I4: Trace-Credentials härten

Bedrohung 3 in `security/THREAT_MODEL.md`.

**Aufgaben:**

- [ ] Passwort nicht mehr per `-PASS` übergeben: Variante in ADR-002 festlegen (`fbtracemgr -fetch <datei>` mit
      ACL-geschützter Datei, `-trusted` mit Windows-Authentifizierung oder Credential-Store + kurzlebige Passwortdatei)
- [ ] Passwort nicht mehr im Klartext in `config.json` (`architecture/CREDENTIAL_STRATEGY.md`)
- [ ] Dedizierten Trace-Benutzer mit Rolle `TRACE_ANY_ATTACHMENT` statt SYSDBA dokumentieren (`operations/SETUP.md`)
- [ ] `config.sample.json` ohne bekanntes Standardpasswort (fiktiver Platzhalterwert, Hinweis auf Credential-Store)

---

## Mittlere Priorität

### I5: Trace-Skripte robust machen

**Aufgaben:**

- [ ] Ausgabeverzeichnis aus `config.json` statt fest `E:\` (beide Skripte)
- [ ] `trace_stop.ps1` ermittelt die Session über eine beim Start abgelegte ID bzw. `fbtracemgr -LIST` statt über „neueste `*.log` auf `E:\`"
- [ ] Hinweistext in `trace_start.ps1` nennt den richtigen Skriptnamen `trace_stop.ps1` (K4)
- [ ] `[CmdletBinding()]`, `$ErrorActionPreference = 'Stop'`, Existenzprüfung für `fbtracemgr.exe` und Trace-Konfiguration
- [ ] Encoding: Skripte ASCII bzw. UTF-8 mit BOM (K5); Ausgabe-Encoding der Trace-Datei unter Windows PowerShell 5.1 prüfen und festlegen
- [ ] Unit-Tests mit gemocktem `fbtracemgr`-Wrapper (`testing/UNIT_TESTS.md` 8.5)

### I6: Parser – Streaming und Regex-Abdeckung

**Aufgaben:**

- [ ] Synthetische Fixture-Trace (fiktive Daten) unter `tests/fixtures/` + Charakterisierungstests für `Show-TraceStructure.ps1`
- [ ] Zeilenweises Lesen (StreamReader) und Ausgabe pro Block in die Pipeline statt `Get-Content -Raw` + `return $results` (K2)
- [ ] Verbindungs-Regex: Rolle ≠ `NONE`, Dateiendung case-insensitiv, weitere Protokolle (K3)
- [ ] Statusausgaben über `Write-Verbose`/`Write-Information` statt `Write-Host`
- [ ] Zähler (`Reads`, `Writes`, `Fetches`, `Marks`) als `[long]`; Verhalten bei Werten > Int32 testen

---

## Niedrige Priorität

### I7: README-Drift beheben, Lizenzdatei klären

**Aufgaben:**

- [ ] README.md/README.de.md: Ausgabe-Properties an den Code angleichen (`ClientIP`, `ApplicationPath`, `Action`, `Params`, `TableStats`, `RootTxID`) (K1)
- [ ] Aussage „line-by-line (low memory)" erst nach I6 wieder treffen, bis dahin korrigieren
- [ ] README nennt „MIT License", eine `LICENSE`-Datei fehlt — Owner-Entscheidung einholen und Datei ergänzen

### I8: Laufzeit- und Beispielstände aus dem Security-Sweep 2026-10-23 nachziehen

Herkunft: `security/DEPENDENCY_AUDIT.md` → Kadenz-Sweep 2026-10-23.

**Aufgaben:**

- [ ] `config.sample.json`: `FirebirdPath` versionsneutral (Platzhalter statt `Firebird_4_0_3`), damit die Vorlage keinen verwundbaren Server-Stand (< 4.0.7 / 5.0.4) suggeriert; `operations/SETUP.md` Konfigurationstabelle angleichen
- [ ] Prüfen und entscheiden (YAGNI): Trace-Skripte warnen unter PowerShell 7 bei einer Version unter 7.6.7 / 7.5.12 / 7.4.21 oder auf 7.4/7.5 nach dem Supportende 2026-11-10 — sonst als bewusst dokumentiertes Restrisiko in `security/DEPENDENCY_AUDIT.md`
- [ ] MSRC Security Update Guide (Oktober 2026) auf Windows PowerShell 5.1 filtern und den Befund im Sweep-Protokoll nachtragen

**Zusätzliche Kriterien:**

- [ ] Kein Interna-Treffer im Diff (öffentliches Repo, `CONVENTIONS_COMMON.md` 3.1)

### Ohne Inkrement-Nummer (Owner-Aufgaben)

- [ ] Branch-History nach `CONVENTIONS_COMMON.md` 3.1 prüfen; Befund und Optionen in `docs/local/ENVIRONMENT.md` (Entscheidung Repo-Owner: History-Bereinigung oder dokumentierte Akzeptanz)
- [ ] Interna-Hook in jedem Klon aktivieren: `git config core.hooksPath tools/git-hooks` und `.internal-terms` anlegen

---

## Abgeschlossen

- I1 docs_template-Baseline eingeführt (Bestandscode dokumentiert) — [ABGESCHLOSSEN 2026-10-11]
