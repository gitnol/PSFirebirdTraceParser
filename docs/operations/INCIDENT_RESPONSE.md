# Incident Response – PSFirebirdTraceParser

Was zu tun ist, wenn ein Sicherheitsvorfall, ein kritischer Bug oder ein
Datenverlust eintritt. Vor Eskalation lesen, nicht erst während der Krise.

Verbindet sich mit `security/THREAT_MODEL.md`, `operations/SECRETS_MANAGEMENT.md`
und `operations/RUNBOOK.md` (Stack-spezifisch).

---

## Klassifizierung

| Stufe | Definition | Beispiele | Reaktionsfenster |
|---|---|---|---|
| **P0 – Kritisch** | Datenverlust, Datenleck, Produktion komplett offline | `config.json` oder echte Trace-Daten ins öffentliche Repo gepusht; pseudonymisierter Export mit Klartext-Resten an Dritte gegangen; Firebird-Admin-Passwort in zentralen Logs | sofort |
| **P1 – Hoch** | Kernfunktion ausgefallen, sensible Daten gefährdet aber nicht abgeflossen | Pseudonymisierer-Regression (Feld fällt in Klartext zurück) vor Weitergabe entdeckt; vergessene Trace-Session füllt das Serverlaufwerk | < 2 Stunden |
| **P2 – Mittel** | Funktion eingeschränkt, kein Daten-/Sicherheitsrisiko | Parser liefert für eine Firebird-Version leere Felder | < 24 Stunden |
| **P3 – Niedrig** | Kosmetischer / nicht-blockierender Defekt | falscher Skriptname im Hinweistext, Umlaut-Darstellung | Backlog |

Projektspezifische Erstmaßnahmen: Bei einem Passwort-Leak zuerst das Firebird-Passwort ändern (Rotation,
`operations/SECRETS_MANAGEMENT.md`), dann Logs bereinigen lassen. Bei Interna oder Trace-Daten im öffentlichen Repo:
nicht weiter pushen, Repo-Owner informieren, History-Bereinigung entscheiden — bereits geklonte Kopien sind
nicht rückholbar. Bei weitergegebenen Exporten: Empfänger um Löschung bitten, Datenschutz einbinden.

---

## Vorgehen (5 Phasen)

### 1. Eindämmen (Contain)

Ziel: weiteren Schaden verhindern, Beweise sichern. Erst danach analysieren.

- Bei Credential-Leak: betroffenes Secret **sofort** invalidieren (siehe
  `SECRETS_MANAGEMENT.md` → Rotation).
- Bei aktivem Angriff: betroffene Komponente isolieren (Service stoppen,
  Netzwerk-Zugriff sperren).
- Logs und betroffene Artefakte sichern, **bevor** etwas verändert wird
  (Forensik-Pfad).
- Bei P0: weitere Personen benachrichtigen (siehe Eskalationspfad unten).

### 2. Bewerten (Assess)

- **Was ist betroffen?** Welche Daten, welche Nutzer, welche Systeme?
- **Wann hat es begonnen?** Logs prüfen → Zeitfenster eingrenzen.
- **Welcher Vektor?** Welche Schwachstelle / welches Versagen hat es ermöglicht?
- **Wer muss informiert werden?** Intern (Stakeholder), extern (Kunden,
  Auditor, Datenschutzbehörde bei DSGVO-Relevanz).

Output: kurzer Status (1 Absatz), an Eskalationsstelle übergeben.

### 3. Kommunizieren (Communicate)

- **Intern zuerst.** Stakeholder informieren, bevor sie es von außerhalb hören.
- **Faktentreu.** Was wir wissen, was wir nicht wissen, was wir gerade tun.
  Keine Spekulation.
- **Extern nur abgestimmt.** Bei DSGVO-Verstoss: Meldepflicht 72h
  (Datenschutzbehörde); Compliance-Rahmen siehe `security/DATA_HANDLING.md`.

### 4. Beheben (Eradicate & Recover)

- Wurzelursache fixen, nicht nur Symptom (Code-Fix, Konfigurations-Härtung,
  Patch-Update).
- Verifikation: Reproduziert sich der Vorfall im fix-validierten Stand? Nein.
- Wiederherstellung: Service wieder hochfahren, Datenintegrität prüfen.
- Monitoring intensivieren für 24–72h.

### 5. Post-Mortem

Innerhalb von 5 Werktagen nach P0/P1-Vorfall:

- **Zeitleiste:** wer hat wann was bemerkt / getan.
- **Wurzelursache:** technisch + prozessual (5-Why-Analyse).
- **Lessons Learned:** was schief lief, was gut lief. Einträge in
  `LESSONS_LEARNED.md` und `CHANGELOG.md`.
- **Maßnahmen:** konkrete TODO-Punkte oder ADRs, um Wiederholung zu verhindern.
- **Update Threat Model:** falls die Bedrohung neu ist → Eintrag in
  `security/THREAT_MODEL.md`.

---

## Eskalationspfad

| Vorfall-Stufe | Wer wird wann benachrichtigt |
|---|---|
| P0 | Repo-Owner/Maintainer sofort; bei Datenabfluss zusätzlich die Datenschutzstelle der Organisation, deren Datenbank betroffen ist (Kontakt lokal in `docs/local/`) |
| P1 | Repo-Owner/Maintainer innerhalb 1 Stunde; bei Server-Auswirkung die DB-Administration |
| P2 | Im nächsten regulären Sync |
| P3 | Backlog-Eintrag, keine Sonder-Eskalation |

---

## Checkliste für die ersten 15 Minuten bei P0/P1

- [ ] Schaden eingedämmt (Service / Secret / Netzwerk-Pfad)?
- [ ] Logs gesichert?
- [ ] Eskalation losgeschickt?
- [ ] Zeitstempel des Beginns notiert?
- [ ] Aktuell aktive Personen kennen jeweils ihren Teil-Auftrag?

---

## Pflege

Trigger: nach jedem P0/P1-Vorfall: Post-Mortem-Hinweis hier integrieren falls
generalisierbar (z.B. Eskalationsweg ändert sich). Sonst nur projektspezifische
Anpassung der Eskalations-Tabelle.
