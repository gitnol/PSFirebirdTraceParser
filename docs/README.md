# Dokumentation – PSFirebirdTraceParser

Übersicht über das Doku-Set. Einstieg für Menschen ist die [README](../README.md) (Englisch) bzw.
[README.de](../README.de.md); Einstieg für Agenten ist [KICKOFF.md](KICKOFF.md).

## Ich möchte …

| Ziel | Dokument |
|---|---|
| ein Trace-Log auswerten, Felder lesen, pseudonymisieren, weitergeben | [Benutzerhandbuch](handbuch/BENUTZERHANDBUCH.md) |
| installieren, einen Trace aufzeichnen, den C#-Parser bauen, Schlüssel und Zugänge verwalten, aktualisieren | [Adminhandbuch](handbuch/ADMINHANDBUCH.md) |
| wissen, welches Ereignis welche Felder füllt | [features/TRACE_PARSING.md](features/TRACE_PARSING.md) → „Felder je Ereignistyp“ |
| wissen, was pseudonymisiert wird und was nicht | [features/PSEUDONYMIZATION.md](features/PSEUDONYMIZATION.md) |
| Konfiguration und Exit-Codes der Trace-Skripte | [features/TRACE_CAPTURE.md](features/TRACE_CAPTURE.md), [architecture/CONFIGURATION.md](architecture/CONFIGURATION.md), [architecture/ERROR_HANDLING.md](architecture/ERROR_HANDLING.md) |
| bei einem Problem nachsehen | [operations/RUNBOOK.md](operations/RUNBOOK.md), [KNOWN_ISSUES.md](KNOWN_ISSUES.md) |

## Aufbau

| Ordner / Datei | Inhalt |
|---|---|
| `handbuch/` | Benutzer- und Adminhandbuch (Deutsch) |
| `features/` | je Funktion der Vertrag: Parameter, Ablauf, Einschränkungen, Fallstricke, Teststrategie |
| `architecture/` | Übersicht, Projekt-Layout, Konfiguration, Fehlerbehandlung, Abhängigkeiten, Zugangsdaten; `ADR/` = Entscheidungen (ADR-001 Pseudonymisierung, ADR-002 Trace-Anmeldung, ADR-003 C#-Parser) |
| `operations/` | Einrichtung, Runbook, Deployment, Monitoring, Secrets, Vorfälle |
| `security/` | Bedrohungsmodell, Datenschutz, Abhängigkeitsprüfung, Authentifizierung |
| `testing/` | Teststrategie |
| `principles/` | Grundsätze der Entwicklung ([INDEX](principles/INDEX.md)) |
| `STATE.md`, `TODO.md`, `BACKLOG.md`, `CHANGELOG.md`, `KNOWN_ISSUES.md` | Projektstand, Plan, Ideen, Verlauf, bekannte Probleme |
| `LESSONS_LEARNED.md`, `REFLECTION.md` | gesammelte Lehren und die Reflexion nach Inkrementen |
| `CONVENTIONS.md`, `CONVENTIONS_COMMON.md`, `GLOSSARY.md` | Regeln und Begriffe |
| `KICKOFF.md`, `BOOTSTRAP.md` | Arbeitsablauf für Agenten, Projektstart |
| `local/` | **nicht versioniert** (gitignoriert): umgebungsspezifische Angaben, die nicht in ein öffentliches Repository gehören |

Das Schwesterprojekt [firebird-trace-report-generator](https://github.com/gitnol/firebird-trace-report-generator) erzeugt aus
den Objekten des Parsers einen HTML-Bericht; die Feldnamen aus `features/TRACE_PARSING.md` sind der Vertrag zwischen beiden.
