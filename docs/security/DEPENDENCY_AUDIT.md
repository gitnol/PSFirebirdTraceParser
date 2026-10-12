# Dependency-Audit – PSFirebirdTraceParser

Wann und wie Abhängigkeiten auf bekannte Schwachstellen geprüft werden.
Verbindet sich mit `architecture/DEPENDENCIES.md` (Was ist drin?) und
`security/THREAT_MODEL.md` (Bedrohung: Vulnerable Dependencies).

---

## Wann auditieren

| Auslöser | Pflicht? |
|---|---|
| Vor jedem Release (Tag) | Ja |
| Bei neuer oder aktualisierter Dependency (z. B. Pester, PSScriptAnalyzer ab I2) | Ja, die betroffene + Transitive |
| Nach Sicherheitsmeldung (CVE) für PowerShell, .NET oder Firebird | Ja, sofort |
| Kadenz-Sweep (Web-Advisory-/Best-Practice-Recherche für Base+Stack) | Default 14 Tage, Marker `**Nächster Security-Sweep:**` im `STATE.md`-Kopf — `principles/SECURITY_CURRENCY.md` |

---

## Audit-Befehle (dieses Projekt)

| Komponente | Befehl | Output | Bemerkung |
|---|---|---|---|
| PowerShell-Laufzeit | `$PSVersionTable.PSVersion` und Abgleich gegen die MSRC-Advisories | installierte Version | Windows PowerShell 5.1 wird über Windows Update gepatcht |
| Entwickler-Module | `Get-Module Pester, PSScriptAnalyzer -ListAvailable` + `Find-Module Pester, PSScriptAnalyzer` | installiert vs. aktuell | PSGallery hat keine integrierte CVE-DB — manuell prüfen |
| Firebird-Client-Werkzeug | `fbtracemgr -?` / Firebird-Version des Servers | Version | betrifft den Serverbetrieb; Abgleich gegen Firebird-Advisories |

> Ergebnis datiert in der Tabelle „Befunde" unten festhalten. Es gibt keine Lock-Datei; ab I2 ist
> `tests/RequiredModules.psd1` die Bestandsquelle für Entwickler-Module.

---

## Schweregrad-Politik

| Severity | Reaktion |
|---|---|
| Critical | Sofort patchen (innerhalb 24h) oder Mitigation (Feature deaktivieren); blockiert das Inkrement |
| High | Blockiert das aktuelle Inkrement, bis gepatcht oder mitigiert (`principles/SECURITY_CURRENCY.md`) |
| Medium | Im nächsten regulären Inkrement |
| Low | Backlog; bei nächstem Major-Upgrade mitziehen |

Mitigation kann auch sein: Nutzung der verwundbaren Funktion entfernen,
falls Update nicht möglich ist.

---

## Befunde (datiert)

Ablage für Scanner- und Recherche-Ergebnisse (`principles/SECURITY_CURRENCY.md` → Artefakt). Neueste oben.
Öffentliches oder potenziell öffentliches Repo: die Betroffenheit **konkreter interner Hosts** nur in `docs/local/`,
hier nur generisch (`CONVENTIONS_COMMON.md` 3.1).

Init-Abgleich 2026-10-11. Bestand: keine Laufzeit-Module; PowerShell 5.1/7.x; .NET-Kryptografie/Regex;
`fbtracemgr` einer Firebird-Installation (Vorlage nennt 4.0). Websuche, Treffer als untrusted behandelt und gegen
den Code geprüft; Versionsangaben aus Suchmaschinen-Snapshots sind vor Nutzung mit `Find-Module` bzw. den
Hersteller-Advisories zu bestätigen.

| Datum | Quelle (Scanner / URL) | Paket / Version | Befund | betrifft uns? (Begründung) | Maßnahme / Restrisiko |
|---|---|---|---|---|---|
| 2026-10-11 | [NVD CVE-2026-28224](https://nvd.nist.gov/vuln/detail/CVE-2026-28224), GitHub-Advisory GHSA-xrcw-wpjx-pr95 | Firebird-Server 3.0 < 3.0.14, 4.0 < 4.0.7, 5.0 < 5.0.4 | Null-Pointer bei `op_crypt_key_callback` vor Authentifizierung → Server-Absturz (DoS), CVSS 8.2 | Nicht der Code dieses Projekts; betrifft den Server, auf dem der Trace läuft | Betreiber: Server auf ≥ 4.0.7 / 5.0.4; Port 3050 nur aus vertrauenswürdigen Netzen. Betroffenheit konkreter Server nur in `docs/local/` |
| 2026-10-11 | Websuche (Feeds, Debian-Tracker) zu CVE-2026-28212 | Firebird < 3.0.14 / 4.0.7 / 5.0.4 | DoS über `op_slice`-Pakete vor Authentifizierung; CVE-Nummer in Quellen uneinheitlich | wie oben, Server-Betrieb | wie oben; Nummer gegen NVD/Firebird-Advisory bestätigen (Confidence) |
| 2026-10-11 | [NVD CVE-2025-24975](https://nvd.nist.gov/vuln/detail/CVE-2025-24975) | Firebird < 4.0.6 / 5.0.2 (Snapshots) | Externer Verbindungspool (`EXECUTE STATEMENT ON EXTERNAL`) → Absturz / Zugriff auf verschlüsselte DB | Server-Betrieb; Projekt nutzt keine externen Verbindungen | Server aktualisieren oder `ExtConnPoolSize = 0` |
| 2026-10-11 | Websuche CVE-2025-54989 (INCIBE) | Firebird < 3.0.13 / 4.0.6 / 5.0.3 | XDR-Parsing Null-Pointer → DoS, CVSS 5.3 | Server-Betrieb | durch obige Updates abgedeckt |
| 2026-10-11 | [Debian-Manpage fbtracemgr (firebird4.0-utils)](https://dyn.manpages.debian.org/trixie/firebird4.0-utils/fbtracemgr.1) | `fbtracemgr` 4.0 | Optionen `-fetch <datei>` (Passwort aus Datei) und `-trusted` vorhanden | Ja: Grundlage für I4 (Passwort nicht mehr per `-PASS`) | Best Practice übernommen in `architecture/CREDENTIAL_STRATEGY.md`; Windows-Build vor Umsetzung prüfen |
| 2026-10-11 | [Firebird-Doku „Trace configuration"](https://firebirdsql.org/docs/chunk/en/refdocs/fbconf/fbconf-trace.html) | Firebird ≥ 4 | Fremde Verbindungen tracen nur Admins oder Benutzer mit `TRACE_ANY_ATTACHMENT` | Ja: SYSDBA in der Vorlage ist unnötig hoch privilegiert | I4: dedizierter Trace-Benutzer |
| 2026-10-11 | Websuche MSRC-Advisories (u. a. CVE-2026-50523, CVE-2026-26143) | PowerShell 7.4/7.5/7.6 | Mehrere 2026er Schwachstellen; laut Advisories behoben in 7.4.19, 7.5.10, 7.6.5 | Indirekt: Laufzeit der Skripte, nicht der Code | Nutzer: aktuelle Patch-Version; einzelne CVE-Details gegen MSRC prüfen (Confidence) |
| 2026-10-11 | [PowerShell Support Lifecycle](https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle) | PowerShell 7.4, 7.5, 7.6; Windows PowerShell 5.1 | 7.4 und 7.5 Supportende 2026-11-10; 7.6 ist LTS; 5.1 folgt dem Windows-Lebenszyklus | Ja: unterstützte Laufzeiten | `operations/SETUP.md`: 7.6 LTS empfehlen, 5.1 weiter unterstützen |
| 2026-10-11 | PowerShell Gallery (Suchmaschinen-Snapshot) | Pester 6.2.0 / 5.9.1; PSScriptAnalyzer 1.25.0 | Pester 6 ist erschienen, 5.x wird weiter gepflegt | Ja: Auswahl der Test-Version in I2 | I2: Version bewusst wählen und pinnen; Snapshot per `Find-Module` bestätigen |
| 2026-10-11 | EDPB Guidelines 01/2025 on Pseudonymisation (Sekundärquellen zur Konsultationsfassung) | Verfahren des Pseudonymisierers | Schlüsselbasierte Verfahren (MAC/HMAC) stärker als einfache Hashes; pseudonymisierte Daten bleiben personenbezogen | Ja: ungesalzener SHA-256 im Code | Bedrohung 2, I3 (HMAC); Endfassung der Leitlinie bei I3 prüfen |

---

## SBOM (optional)

Nicht erforderlich: keine Laufzeit-Abhängigkeiten außer PowerShell/.NET und Firebird-Werkzeugen. Ab I2 genügt
`tests/RequiredModules.psd1` als Liste der Entwickler-Module.

---

## Was nicht ausreicht

- **„Wir nutzen nur populäre Bibliotheken"** — populär ≠ sicher (siehe
  `event-stream`, `colors.js`, `xz-utils`).
- **GitHub Dependabot allein** — erfasst weder PowerShell-Laufzeit noch Firebird-Binaries.
- **Einmaliger Audit beim Projektstart** — Audits müssen wiederholt werden,
  weil neue CVEs ständig erscheinen.
- **Scanner-Lauf allein** — findet keine Härtungs-Best-Practices und keine Advisories
  ohne CVE-Eintrag. Web-Recherche nach `principles/SECURITY_CURRENCY.md` ergänzt
  den Scanner, ersetzt ihn nicht (und umgekehrt).

---

## Pflege

Trigger (siehe `KICKOFF.md` Phase 3a): neue Dependency hinzugefügt /
CVE-Meldung erhalten / Audit-Tool geändert → diese Datei aktualisieren.
