# Datenschutz & Compliance – PSFirebirdTraceParser

Rahmen: **DSGVO** — Trace-Logs enthalten personenbezogene Daten (Benutzer, IP-Adressen, Anwendungspfade mit
Windows-Benutzernamen, SQL-Literale und Parameter mit Inhalten der Datenbank). Kein weiterer formaler Rahmen im
Repository; das Projekt ist öffentlich, deshalb kein `compliance-tisax`-Overlay. Nutzer, die es in einem
regulierten Umfeld einsetzen, ergänzen ihre Vorgaben lokal (`docs/local/`).

---

## Datenklassen (kanonisch)

Alle Overlays (`llm-integration`, `document-intelligence`, `compliance-tisax`) verwenden diese vier Klassen und
ergänzen nur ihre Erlaubnis-Matrix bzw. das TISAX-Mapping.

| Klasse | EN | Beispiele | An externe Dienste / Cloud-Modelle |
|---|---|---|---|
| Öffentlich | public | veröffentlichte Texte, Demo-Daten | erlaubt |
| Intern | internal | allgemeine Geschäftskommunikation, interne Prozessdokumente | nach Prüfung des Dienstes (Checkliste unten) |
| Vertraulich | confidential | Kunden- und Lieferantendaten, Verträge, Preise, Strategie | **nur mit dokumentierter Freigabe und Auftragsverarbeitungsvertrag (AVV)** |
| Streng vertraulich | restricted | Personalakten, besondere Kategorien personenbezogener Daten, Konstruktions-/Tarifgeheimnisse | **nein** — nur lokal/On-Prem; Ausnahme nur mit ausdrücklichem DSGVO-/TISAX-Sign-off |

**Projektzuordnung:** Trace-Rohdaten und Parser-Exporte sind mindestens **Vertraulich**; wird eine Datenbank mit
Personal- oder besonders geschützten Daten per Trace erfasst, **Streng vertraulich**. Pseudonymisierte Exporte bleiben
personenbezogen (EDPB-Leitlinien 01/2025) und damit **Vertraulich**.

---

## 1. Lokale Verarbeitung / Datenisolation

- Alle Skripte arbeiten lokal; es gibt keinen Netzwerkzugriff außer dem lokalen Firebird-Service-Manager.
- Zugriff auf Rohdaten hat, wer auf dem Datenbankserver Leserechte auf das Ausgabeverzeichnis (`E:\`) hat, und wer
  Exporte erhält.
- Keine Air-Gap-Anforderung im Projekt; Weitergabe ist ein bewusster, manueller Schritt des Nutzers.

---

## 2. Minimalprinzip (Data Minimization)

- **Erfassung begrenzen:** Trace nur so lange und so breit wie nötig (Datenbankfilter, Schwellwert
  `time_threshold`, `max_arg_length`/`max_arg_count` in der Trace-Konfiguration).
- **Vor Weitergabe:** immer `Pseudonymize-FirebirdTrace.ps1` mit `-RedactLiterals`; nicht benötigte Spalten vor dem
  Export entfernen (`Select-Object`), z. B. `Params`, `DatabasePath`, `ApplicationPath`.
- **Nicht weitergeben:** Trace-Rohdateien, `config.json`, Ausgaben von `-AnalyzeOnly` (enthalten Klartext).
- **Grenzen der Pseudonymisierung kennen:** Feldabdeckung in `features/PSEUDONYMIZATION.md`, Bedrohungen 1–2 in
  `security/THREAT_MODEL.md`.

---

## 3. Output-Dateien und Speicherorte

| Datei | Inhalt | Sensitivität |
|-------|--------|-------------|
| `E:\trace_output_<Zeitstempel>.log` | Trace-Rohdaten: SQL-Texte, Parameter, Benutzer, IPs, Pfade | Vertraulich (ggf. Streng vertraulich) |
| CSV-/Excel-Export aus `Show-TraceStructure.ps1` | wie oben, strukturiert | Vertraulich (ggf. Streng vertraulich) |
| Export nach `Pseudonymize-FirebirdTrace.ps1` | pseudonymisiert, Klartext-Reste laut Feldabdeckung | Vertraulich |
| `config.json` | Firebird-Zugangsdaten im Klartext (bis I4) | Streng vertraulich (Secret) |

- Rohdaten nur auf dem Datenbankserver bzw. einem zugriffsgeschützten Analyseplatz, nicht auf Netzlaufwerken mit
  breitem Zugriff, nie im Repository.
- `.gitignore` schützt `**/*.log`, `trace_output*`, `/*.csv`, `config*.json` (außer der Vorlage).

---

## 4. Zugriffsschutz

- Trace-Start/-Stopp nur durch Datenbank-Administration; künftig mit dediziertem Trace-Benutzer statt SYSDBA
  (`architecture/CREDENTIAL_STRATEGY.md`).
- Ausgabeverzeichnis mit NTFS-Rechten nur für Administratoren/Analysten.
- Least Privilege: Analysten erhalten pseudonymisierte Exporte, nicht die Rohdatei.
- Secret-Speicherung und Rotation: siehe `docs/operations/SECRETS_MANAGEMENT.md`

---

## 5. Datenhaltung / Retention

- Rohdatei: nach Abschluss der Analyse löschen, spätestens nach dem in der Organisation festgelegten Zeitraum
  (Vorschlag: 30 Tage); jede Session erzeugt eine neue Datei (Zeitstempel im Namen), es wird nichts überschrieben —
  Dateien akkumulieren ohne manuelles Aufräumen.
- Exporte und weitergegebene Dateien: Löschfrist mit dem Empfänger vereinbaren.
- Verantwortlich für das Aufräumen: wer die Session gestartet hat (Runbook-Schritt in `operations/RUNBOOK.md`).

---

## 6. Weitergabe an Dritte (externe Analyse)

- Nur pseudonymisierte, auf nötige Spalten reduzierte Exporte.
- Freigabe durch die für die Datenbank verantwortliche Stelle; bei externen Dienstleistern AVV (Klasse Vertraulich).
- Bis I2/I3: Export manuell auf Klartext-Reste prüfen (Bedrohungen 1–2).

---

## 7. Compliance-Checkliste für neue Features

- [ ] Keine neuen persistenten Speicher ohne Retention-Konzept
- [ ] Kein Logging von sensiblen Inhalten (Passwörter, Nutzdaten, PII)
- [ ] Externe Services nur nach Compliance-Prüfung einführen
- [ ] Neue Parser-Property → Entscheidung in `features/PSEUDONYMIZATION.md` (pseudonymisiert oder begründet Klartext)
- [ ] Test-Fixtures nur mit fiktiven Daten, nie Auszüge echter Traces
