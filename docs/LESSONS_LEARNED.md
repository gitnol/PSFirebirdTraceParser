# Lessons Learned – PSFirebirdTraceParser

Strukturierter Index für gelernte Patterns. Jeder Eintrag benennt Scope und
Backport-Ziel; die zentrale Reflexion im Template-Repo erntet diese Datei lesend und entscheidet
projektübergreifend, ob eine Lehre ins Template wandert (REFLECTION.md Schritt 3). Das Projekt selbst schlägt
keine Backports vor und schreibt nie ins Template. Global heißt ein Eintrag `<projekt>/L<N>` — Nummern deshalb nie
neu vergeben.

Neue Einträge entstehen aus dem „Lessons Learned"-Abschnitt der `CHANGELOG.md` —
dort kurze Beschreibung, hier der strukturierte Steckbrief. Ausnahme: Lessons aus einem Template-Update stehen nur
hier (das Update hat keinen CHANGELOG-Eintrag); `Inkrement:` nennt dann das Update, z. B. `Template-Update v27`.

---

## L1: History-Scan beim Init eines bereits öffentlichen Repos
- Inkrement: I1
- Scope: generisch-base
- Backport-Ziel: `NEUES_PROJECT_INITIALISIEREN.md` Schritt 1 („Öffentliches Repository?") bzw. `base/CONVENTIONS_COMMON.md` 3.1
- Status: backported v32@e8eaf0f

Die Regel „vor dem ersten Push die Branch-History prüfen" greift nicht, wenn das Repository schon öffentlich ist; beim
Init fanden sich Interna nur in **gelöschten** Kommentar-Beispielen älterer Commits, nicht im aktuellen Stand. Ein
History-Scan (`git log -p --all` gegen die Denylist) gehört deshalb in den Init, der Befund nach `docs/local/` und die
Bereinigung als Owner-Entscheidung in `TODO.md`.

---

## L2: Datenschutz-Versprechen per Probeaufruf belegen
- Inkrement: I1
- Scope: projekt-spezifisch
- Backport-Ziel: keiner
- Status: projekt-intern

Aussagen über die Feldabdeckung des Pseudonymisierers wurden nicht nur aus dem Code gelesen, sondern mit einem
fiktiven Objekt nachgeprüft; dabei zeigte sich eine im Code leicht zu übersehende Bedingung (Bulk-Redaktion nur,
wenn das Schlüsselwort nach der Literal-Ersetzung noch vorkommt). Künftige Änderungen belegen die Abdeckung per Pester-Test.

---

## L3: Testdaten aus der Formatquelle bauen, echte Daten nur lokal und nur gezählt auswerten
- Inkrement: I9, I10, K3
- Scope: generisch-base
- Backport-Ziel: `base/testing/UNIT_TESTS.md` (Fixtures) bzw. `base/CONVENTIONS_COMMON.md` 3.1 (öffentliche Repos)
- Gesehen mit: v37
- Status: offen

In einem öffentlichen Repo mit sensiblen Echtdaten wurden die Test-Fixtures aus dem Quellcode des Herstellers abgeleitet
(Format nach Firebird 5.0.4, Werte ausgedacht, IPs aus 192.0.2.0/24). Ein echtes Log diente nur lokal als Beleg, und zwar
nur über Zählwerte (298 Kopfzeilen, 12 leere Verbindungszeilen) — so wurden zwei Parser-Fehler belegt, ohne Inhalte ins
Repo zu bringen. Grenze: Formen, die nur im Quellcode stehen (Linux-Kopfzeile, Fehlerereignisse), bleiben unbelegt
und müssen als „Ungeprüft" im CHANGELOG stehen. Bisher nur in diesem Projekt gesehen.

---

## L4: Vorbehalte an das Thema binden, nicht an eine vorhergesagte Inkrement-ID
- Inkrement: Reflexion I3
- Scope: generisch-base
- Backport-Ziel: `base/REFLECTION.md` Schritt 1 (Health-Check) bzw. Init-Anleitung zu Vorbehalten
- Gesehen mit: v37
- Status: offen

Beim Init entstanden 19 Vorbehalte „ab I2" in neun Dateien (Tests, gepinnte Module). Die Arbeit landete dann in I9, nicht
in I2 — die Verweise waren nicht nur veraltet, sondern falsch, und der Health-Check fand sie erst, als I2 abgeschlossen
war. Zusätzlich übersieht der Health-Check eine erledigte ID in der Status-Spalte von Tabellen („Bekannte Einschränkungen"
mit `| I6 |`); dort standen nach I2/I3/I6 sieben erledigte Zeilen. Besser: Vorbehalt mit Stichwort schreiben („noch nicht
vorhanden: CI") und die ID nur als Hinweis; bei Roadmap-Umbau nach den alten IDs suchen. Ein Projekt, ein Fall.

---

## L5: Unterstützte Laufzeit nur zusagen, wenn die Tests darunter laufen
- Inkrement: I14
- Scope: generisch-stack
- Backport-Ziel: `stacks/powershell-automation/testing/UNIT_TESTS.md` (Abschnitt 7) bzw. Stack-CI-Vorlage
- Gesehen mit: v37
- Status: offen

Das Projekt sagt Windows PowerShell 5.1 und PowerShell 7 zu, die Tests liefen aber nur unter 7: `Join-Path` mit drei
Teilen und .NET-5-APIs (`Convert::ToHexString`, `SHA256::HashData`) ließen unter 5.1 alle 66 Tests scheitern, bevor
sie den Code prüften. Nach dem Umbau auf `[System.IO.Path]::Combine` und .NET-Framework-Aufrufe liefen alle Tests auch
unter 5.1 grün — erst dann trägt ein zweiter CI-Job. Ein Fall, ein Projekt.

---

## L6: Ein Gate-Skript mit `$ErrorActionPreference = 'Stop'` verändert die Tests
- Inkrement: I14
- Scope: generisch-stack
- Backport-Ziel: `stacks/powershell-automation/CONVENTIONS.md` (Quality Gates) bzw. Vorlage eines Gate-Skripts
- Gesehen mit: v37
- Status: offen

`Invoke-Pester` läuft im Bereich des aufrufenden Skripts. Setzte das Gate-Skript `Stop`, wurde aus einem erwarteten,
nicht abbrechenden Fehler (`Write-Error` bei fehlender Datei) ein Abbruch — ein Test war nur im Gate rot, beim direkten
Aufruf grün. Lösung: Pester in einem Kindbereich mit den Standard-Einstellungen starten. Ein Fall, ein Projekt.

---

## Pflege

- Neuer „Lessons Learned"-Block im `CHANGELOG.md` → Eintrag `## L<N>:` hier anlegen.
- Mehrere Patterns aus einem Inkrement → mehrere `## L<N>:`-Einträge.
- Scope-Werte:
  - `projekt-spezifisch` — nur für dieses Projekt relevant, kein Backport nötig.
  - `generisch-stack` — gehört in `docs_template/stacks/<stack>/CONVENTIONS.md` o.ä.
  - `generisch-base` — gehört in `docs_template/base/` (Prinzip, Basis-Convention, MANIFEST).
- `Gesehen mit` → Template-Stand beim Festhalten der Lehre, nur die Version aus dem `STATE.md`-Kopf
  „Initialisiert mit" (letzter Stand der Kette, z. B. `v35`). Daran erkennt die zentrale Reflexion Lehren, die eine
  neuere Template-Version schon behebt.
- Status `offen` → wartet auf die zentrale Reflexion im Template-Repo; bleibt `offen`, bis das Template die Lehre
  übernommen oder verworfen hat.
- Status `backported vN@<commit>` → setzt das Projekt beim Template-Update (`ALTES_PROJECT_AKTUALISIEREN.md` im
  Template-Repo), sobald `TEMPLATE_CHANGELOG.md` die Lehre als Herkunft (`<projekt>/L<N>`) nennt; Version + Commit
  des Template-Stands, z. B. `v36@0a4c8f1`.
- Status `projekt-intern` → Endzustand für `Scope: projekt-spezifisch` (kein Backport vorgesehen; die Lesson gilt
  im Projekt weiter). Die zentrale Reflexion überspringt sie.
- Niemals Patterns löschen, auch wenn überholt — `Status: verworfen (<grund>)` setzen.
- Diese Datei steht in der Trigger-Matrix in `KICKOFF.md` Phase 3a.
