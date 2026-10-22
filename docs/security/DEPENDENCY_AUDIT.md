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

### 2026-10-23 – Kadenz-Sweep (vorgezogen, fällig 2026-10-25)

Zeitraum seit dem Init-Abgleich 2026-10-11. Bestand: keine Laufzeit-Module, keine Manifest-/Lock-Datei, keine
NuGet-Pakete; Entwicklungsrechner PowerShell 7.6.7 (`pwsh -v`), lokal installiert Pester 6.1.0/5.7.1 und
PSScriptAnalyzer 1.25.0 (im Repo noch nicht genutzt, erst ab I2); `config.sample.json` zeigt auf ein
Firebird-4.0.3-Verzeichnis (`fbtracemgr` aus 4.0.x). Quellen als Liste abgerufen (Advisory-Dateien, Issue-Liste,
Release-Listen, GitHub-Advisories), Websuche nur ergänzend und als untrusted behandelt.

| Prüfgegenstand | Ergebnis | Bewertung (betrifft uns / nicht, Begründung) | Quelle |
|---|---|---|---|
| PowerShell-7-Advisories Oktober 2026 (Dateikanal) | CVE-2026-96251 (RCE, alle OS) und CVE-2026-96303 (Security Feature Bypass, nur Windows), beide 2026-10-13; behoben in 7.4.21 / 7.5.12 / 7.6.7. Ordner `pwsh/2026/09` existiert nicht | Betrifft uns indirekt: Laufzeit der Skripte, nicht der Code. Entwicklungsrechner 7.6.7 = gepatcht. Nutzer brauchen ≥ 7.6.7 (bzw. 7.5.12 / 7.4.21) | `gh api repos/PowerShell/Announcements/contents/pwsh/2026/10` |
| PowerShell-Advisories, Issue-Kanal | Letztes Issue #101 vom 2026-09-23; die beiden Oktober-Advisories fehlen dort | Kanallücke bestätigt (Template-Hinweis): künftig Dateikanal **und** Release-Liste abgleichen | `gh issue list -R PowerShell/Announcements --state all` |
| PowerShell-Advisories September 2026 (Nachtrag, Issues #98–#101) | CVE-2026-62801 und CVE-2026-40400 (RCE), CVE-2026-58649 (.NET Information Disclosure), CVE-2026-69806 (.NET EoP); behoben in 7.6.6 / 7.5.11 / 7.4.20 (40400: 7.4.18; 69806: 7.4 nicht betroffen) | Korrektur zum Init-Abgleich: die dort genannten Fix-Stände 7.4.19 / 7.5.10 / 7.6.5 waren zu niedrig. Durch die Mindestversion 7.6.7 / 7.5.12 / 7.4.21 vollständig abgedeckt | Issues #98–#101 in `PowerShell/Announcements` |
| PowerShell-Releases seit 2026-10-11 | 7.4.21, 7.5.12, 7.6.7 (2026-10-13, passend zu den Advisories); 7.6.8 (2026-10-22, aktuell): entfernt die Update-Benachrichtigung, .NET SDK 10.0.402, kein Sicherheits-Fix in den Release-Notes | Kein Sicherheits-Release ohne Advisory → keine Kanallücke. 7.6.8 nicht sicherheitsrelevant, Update empfohlen, nicht zwingend | `gh release list -R PowerShell/PowerShell`, Release-Notes v7.6.7/v7.6.8 |
| PowerShell-Lebenszyklus | 7.4 und 7.5 Supportende 2026-11-10 (in 18 Tagen) | Betrifft Nutzer auf 7.4/7.5: danach keine Fixes mehr; `operations/SETUP.md` empfiehlt bereits 7.6 LTS, jetzt mit Mindest-Patchstand | Init-Befund (PowerShell Support Lifecycle), unverändert |
| .NET Oktober-Servicing (2026-10-13) | Kein .NET-Projekt, keine NuGet-Pakete im Repo | Nicht anwendbar: `dotnet list package --vulnerable` hat nichts zu prüfen. .NET-Laufzeit kommt gebündelt mit PowerShell 7 (über dessen Patchstand abgedeckt) bzw. als .NET Framework über Windows Update (5.1) | Bestand `architecture/DEPENDENCIES.md` |
| Windows PowerShell 5.1 (Oktober-Patchday) | Websuche ohne Oktober-2026-Treffer für 5.1; ältere 5.1-CVEs (z. B. CVE-2025-54100) sind per Windows Update behoben | Nicht abschließend bewertet: MSRC Security Update Guide (Oktober 2026, Produkt Windows PowerShell) nicht direkt abgefragt → offen. Patch über Windows Update, nicht über das Projekt | Websuche 2026-10-23 |
| Firebird (GitHub-Advisories, Releases) | Kein neues Advisory seit 2026-10-11 (neueste vom 2026-04-17); aktuelle Releases 5.0.4 / 4.0.7 / 3.0.14 (2026-04-17) | Nachtrag zum Init-Abgleich, alle Server-Betrieb, behoben in 5.0.4 / 4.0.7 / 3.0.14: CVE-2026-40342 (Critical 9.9, Path Traversal bei externen Routinen → Codeausführung als Server-Konto), CVE-2026-35215, CVE-2026-34232, CVE-2026-33337 (Slice-/`op_response`-Pakete, DoS/Overflow), GHSA-6crx-4g37-7j49 (Pre-Auth-DoS), CVE-2026-28214 (DoS durch Benutzer mit INSERT-Recht), laut NVD zusätzlich CVE-2026-27890 (Pre-Auth-DoS). Init-Confidence aufgelöst: CVE-2026-28212 ist GHSA-9884-9qm3-hqch („One packet DoS"). Nicht der Code dieses Projekts; Betreiber: Server ≥ 4.0.7 / 5.0.4 | `gh api repos/FirebirdSQL/firebird/security-advisories`, `gh release list -R FirebirdSQL/firebird`, NVD CVE-2026-27890 |
| Firebird-Client (`fbtracemgr`) | CVE-2025-65104: Informationsleck im Client ≤ 3.0.13 gegen Server ≥ 4 | Betrifft uns nicht, solange `fbtracemgr` aus einer 4.x/5.x-Installation stammt (Vorlage). `config.sample.json` nennt aber ein 4.0.3-Verzeichnis — als Beispiel ungünstig, weil es einen verwundbaren Server-Stand suggeriert → I8 | GHSA-mfpr-9886-xjhg |
| Pester, PSScriptAnalyzer | Keine GitHub-Security-Advisories; aktuell Pester 6.2.0 (2026-09-09), PSScriptAnalyzer 1.25.0 (2026-03-20), per `Find-Module` bestätigt | Betrifft uns nicht (noch nicht verbaut). Init-Confidence „Snapshot per `Find-Module` bestätigen" erledigt; Versionswahl und Pinning bleiben Teil von I2 | `gh api repos/pester/Pester/security-advisories`, `…/PowerShell/PSScriptAnalyzer/security-advisories`, `Find-Module` |

Offen aus diesem Sweep: (1) MSRC Security Update Guide für Oktober 2026 auf Windows PowerShell 5.1 filtern und
bewerten (Websuche ergab keinen Beleg in beide Richtungen); (2) I8 — Beispielkonfiguration versionsneutral machen
und Mindest-Laufzeitstand in den Skripten prüfen. Kein Critical/High im Code dieses Projekts; die Critical/High-Befunde
betreffen Laufzeit (PowerShell, beim Entwickler gepatcht) und Firebird-Server-Betrieb.

### 2026-10-11 – Init-Abgleich

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
