# Reflexion 2026-11-11 – PSFirebirdTraceParser

Zentrale Reflexion über die Arbeit seit der Reflexion I18 (2026-11-08), im Schwerpunkt die Doku-Überarbeitung I24
(Commits `afe4204..85cb054`: Felder je Ereignistyp, `docs/README.md`, Benutzer- und Adminhandbuch, README en/de,
Betriebsdokumente) und der G-DATA-Fund vom 2026-11-10. Stand: lokal 8 Commits vor `origin/main`, **nicht gepusht**
und noch nicht in der CI gelaufen. Template-Stand des Projekts: v37@b5021d9. Konkrete Vorschläge für das Template:
`BACKPORT-VORSCHLAG-2026-11-11.md` im Schwester-Repo (Generator); die Lehren-Auswertung steht dort, hier nur die
Befunde dieses Repos.

Geprüft am 2026-11-11: Feldzahl aus dem Quelltext gezählt (Enum `TraceField` in `src/FirebirdTraceParser/
TraceField.cs`: **46** Einträge), Repo-Sichtbarkeit per anonymem Abruf (dieses Repo: HTTP 200, öffentlich), Abgleich der
Doku-Aussagen mit `CHANGELOG.md`. Nicht neu gemessen: Ausgaben der Handbuch-Rezepte (nur aus dem CHANGELOG übernommen).

## 1. Was lief gut

- **Die Feldtabelle stammt aus einem Probelauf, nicht aus der Erinnerung.** `features/TRACE_PARSING.md` → „Felder je
  Ereignistyp“ wurde aus einem Lauf beider Engines über die Fixtures und einen kleinen synthetischen Trace erzeugt
  (gleiches Ergebnis in beiden Engines). Dabei fielen vorhandene Fehler der Doku auf: Zähler sind `long` (stand `int`),
  `AttachID`/`TransactionID`/`RootTxID` tragen nur die Nummer ohne `ATT_`/`TRA_`/`INIT_`.
- **Die Zahl 46 ist belegt:** Doku nennt „46 Properties“, der Enum zählt 46, beide Engines liefern 46 (heute neu
  gezählt). `TRACE_PARSING.md` nennt die Quelle (`TraceField.cs`) und den Probelauf.
- **Ehrlicher Abschnitt „Confidence / Ungeprüft“** im CHANGELOG zu I24: nennt, was nicht geprüft ist
  (`EXECUTE_STATEMENT_START` ohne Fixture, `-TRUSTED`/Rolle `TRACER` gegen echten Server, Herkunft der Einschätzung zu
  `ErrorSource`).
- **Neue `docs/README.md`** als Landkarte („Ich möchte … → Dokument“, Aufbau je Ordner). Verweise beider Richtungen
  zum Schwester-Projekt; die Feldnamen sind als Vertrag zwischen beiden Projekten benannt.
- **Öffentliches Repo geschützt:** `docs/local/` ist nicht versioniert (`git ls-files docs/local` leer), das
  README nennt das ausdrücklich; L1 (History-Scan beim Init) ist bereits im Template (v32).
- **G-DATA-Fund sauber zerlegt:** erster Fix (`ffeca05`) war unvollständig, `9e61a9c` ersetzte alle vier Fälle durch
  `u{…}`-Escapes, L12 verweist auf die Lehre des Schwester-Projekts statt sie zu wiederholen.
- **Commits geteilt nach Zweck** (Felder, Handbücher, README, Betrieb, STATE/CHANGELOG): jede Änderung einzeln
  prüfbar.

## 2. Was lief nicht gut

1. **Die Doku war ungenau und niemand bemerkte es.** Vor I24 nannte der Ausgabe-Vertrag keine Feldzahl (im
   Schwester-Repo stand 44), Typen und ID-Präfixe waren falsch (`int` statt `long`, Präfix `ATT_`). Aufgefallen
   erst beim *Neuschreiben* der Doku, nicht durch einen Test. Es gibt weiterhin **keinen Test, der die Feldtabelle gegen
   die Fixtures prüft**; `grep` in `tests/` findet keinen Bezug auf `TRACE_PARSING`. Die Tabelle altert wieder, sobald
   der Parser ein Feld bekommt.
2. **Mehr Doku, als eine Prüfung trägt:** I24 umfasst 20 Dateien, 893 Zeilen neu (Diffstat `afe4204~1..85cb054`),
   darunter zwei Handbücher mit 568 Zeilen. Die Rezepte des Benutzerhandbuchs liefen nur gegen Fixtures und einen
   synthetischen Trace; echte Traces sind in diesem öffentlichen Repo nicht verfügbar (L3).
3. **Fehlerereignisse sind ungenau beschrieben:** K9 (Fehlerereignisse ohne Statement/Transaktion, `FAILED …` ohne
   Fehlertext) ist neu aufgenommen; die Einschätzung zu `ErrorSource` (`prepare`/`openCursor` ohne Statement,
   `fetchNext` mit dem Statement davor) stützt sich auf Beobachtungen aus Praxis-Traces, nicht auf den Firebird-
   Quelltext (steht so im CHANGELOG). Das Schwester-Projekt hat dazu inzwischen eine Statement-Zuordnung gebaut (dort L65),
   die diese Annahme voraussetzt.
4. **Reflexion überfällig:** `STATE.md` führt „Nächste Reflexion: fällig“ seit I18; I19–I24 sind ohne Reflexion
   abgeschlossen. Heutige Reflexion ersetzt das noch nicht (Marker bleibt, bis der Nutzer entscheidet).
5. **Unveröffentlichter Stand:** 8 lokale Commits (Parity-Test-Fix gegen G DATA, I24). Die CI ist für sie nicht
   gelaufen; das Risiko „Virenscanner entfernt Testdatei“ (L12) trifft dort **zuerst** auf der lokalen Maschine.
6. **Alte Aussage im STATE (berichtigt in I24):** „CI läuft erst auf GitHub“ — die CI läuft seit 2026-11-08. Ein
   Risikoeintrag blieb Tage nach seinem Wegfall stehen.
7. **Lehren-Stau:** 10 von 12 Lehren stehen auf `offen` (L3–L12), L2 steht auf `projekt-intern`, obwohl ihr Inhalt
   („Versprechen per Probeaufruf belegen“) für das Template generisch ist. In dieser Runde ist **keine** neue Lehre
   zur Doku-Überarbeitung hinzugekommen, obwohl dort Fehlaussagen auffielen (siehe 3).

## 3. Fehlaussagen (im Lauf entstanden, inzwischen berichtigt oder offen)

| Aussage | Richtig | Stand |
|---|---|---|
| Feldzahl 44 (stand im Schwester-Repo; hier nannte die Doku keine Zahl) | 46 (Enum gezählt) | hier ergänzt (`afe4204`), im Schwester-Repo berichtigt (`805abf9`) |
| Zähler sind `int` | `long` | berichtigt (`afe4204`) |
| `AttachID`/`TransactionID`/`RootTxID` enthalten `ATT_`/`TRA_`/`INIT_` | nur die Nummer | berichtigt (`afe4204`) |
| MONITORING: Laufzeitmeldung „Konsolenausgabe“, „records“ | `Parsed <n> events in <s> seconds.`, nur mit `-Verbose` | berichtigt (`b39f13b`) |
| STATE: CI läuft erst auf GitHub | läuft seit 2026-11-08 | berichtigt (`85cb054`) |
| `ErrorMessages` werden pseudonymisiert | ohne `-RedactLiterals` im Klartext | berichtigt (`PSEUDONYMIZATION.md`) |
| „`fetchNext` gehört zum folgenden Statement“ (Annahme im Schwester-Projekt) | zum Statement davor (Stichprobe: 125 ms) | im Schwester-Repo berichtigt; hier als Beobachtung dokumentiert, nicht aus dem Quelltext belegt |
| Repo-Sichtbarkeit | dieses Repo ist öffentlich (HTTP 200 am 2026-11-11), das Schwester-Repo privat (404) | belegt per Abruf |

## 4. Prüfung der zusätzlichen Lehren aus der Sitzung (Auszug für dieses Repo)

- **Zugänglichkeit per Abruf prüfen:** belegt (heute). Bedeutung hier groß, weil dieses Repo öffentlich ist und
  `docs/` Verweise auf das nicht öffentliche Schwester-Repo trägt; ein anonymer Leser folgt dem Verweis ins Leere
  (404). Das ist plausibel gewollt, steht aber nirgends: die Suche nach „privat“/„nicht öffentlich“ in README,
  `docs/README.md` und den Handbüchern findet nichts.
- **Zahlen zählen:** belegt (46).
- **Headless-Chrome:** Das Parser-Repo erzeugt kein HTML; kein Beleg hier.
- **Hintergrundaufgaben beenden / Vergleichsaussagen:** kein Beleg in diesem Repo (die Messung in I19, 15 MB:
  1,6 s statt 13–14 s, nennt in `STATE.md` keine Zahl der Läufe; nicht weiter geprüft).

## 5. Lehren-Filter (Advocatus Diaboli)

- **Neu aufzunehmen** (Entwurf, nicht eingetragen, weil Auftrag nur die Reflexion war): „Eine Zahl in der Doku ist eine
  Probe, kein Gedächtnis“ (Zählen, Befehl nennen, Test dagegen). Zusammen mit L2 ein Cluster; ein Projekt (zwei Repos
  derselben Familie).
- **L12** ist zweiter Beleg für Generator L47, **als eine Lehre** zu führen; Template-Ziel `powershell-automation`
  (Testregeln).
- **L11/L9** (stille Semantik messen) bilden zusammen mit Generator L50–L57 die Familie „Orakel einfrieren“.
- **Zu jung:** die Doku-Struktur (`handbuch/`) hat ein Projekt als Beleg und einen Nachbau im Schwester-Repo, der
  an anderer Stelle (`features/`) liegt: gerade das ist der Befund (Vereinheitlichung vorgeschlagen).

## 6. Drift und Pflege

- `STATE.md`: „Nächste Reflexion: fällig“ bleibt, bis der Nutzer die heutige Reflexion als Abschluss wertet.
- Aufräumpunkte, nicht in dieser Sitzung geändert: Hinweis „nicht öffentlich“ beim Verweis auf das Schwester-Repo (Entscheidung des Nutzers, ob gewollt)
  (`docs/README.md`, README); L2-Scope prüfen; Test „Feldtabelle ↔ Fixtures“ als eigenes Inkrement (Vorschlag B7 im
  Backport-Vorschlag).
- Keine Zugangsdaten, Hostnamen, Kunden- oder Personenangaben in dieser Datei (öffentliches Repo).
