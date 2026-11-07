# Verify Before Cite (LLM-Agent)

## Regel

Bevor ein Dateipfad, eine Funktion, eine Zeilennummer, ein Symbol oder eine
Konfigurations-Option im Chat, Commit-Text oder Doku-Eintrag zitiert wird,
muss sie in einer **aktuellen** Lese- oder Such-Operation nachweisbar sein.

Halluzination ist der häufigste LLM-Projektfehler. Diese Regel ist die
strukturelle Gegenmaßnahme.

## Konkrete Vorgaben

- Dateipfad zitieren → vorher Read/Glob bestätigen, dass die Datei existiert.
- Funktion / Methode / Klasse zitieren → vorher Grep bestätigen, dass der
  Name genau so vorkommt.
- Zeilennummer zitieren → aus aktuell gelesener Datei mit Zeilen-Präfix,
  nicht aus dem Gedächtnis.
- Konfig-Schlüssel oder Env-Variable zitieren → aus aktueller Konfig- oder
  Code-Lese-Operation.
- Externe API-Endpunkte zitieren → aus aktueller Doku-/Code-Lese-Operation,
  nicht aus Vortrainings-Wissen.

## Anti-Pattern

- "Wahrscheinlich existiert die Funktion `do_x()` in `module_y.py`" — verboten
  ohne vorherige Prüfung.
- "Wie üblich liegt die Konfig in `config.yaml`" — verboten ohne Glob.
- Pfade aus dem Gedächtnis aus früheren Sessions wiederverwenden — verboten;
  der Status kann veraltet sein.
- Aus Code-Patterns auf Funktionsnamen schliessen ("müsste hier `validate_input`
  geben") — Vermutung, nicht Beleg.

## Belege altern — Existenz ist nicht Gültigkeit

Die Vorgaben oben prüfen, ob etwas **da ist**. Die teurere Fehlerklasse zitiert Vorhandenes, das **nicht mehr gilt**:
die Datei, die es noch gibt, aber nicht mehr benutzt wird; die Zeilennummer, an der heute etwas anderes steht; die
Zahl, die einmal stimmte. Solche Aussagen bestehen jede Existenzprüfung. Ein Beleg gilt für einen Zeitpunkt, eine
Quelle und einen Zustand — nicht für immer:

- **Ist-Aussagen datieren.** Wer in `docs/` beschreibt, wie etwas *ist* (Zustand, Stand, Messung), schreibt das Datum
  dazu („Stand JJJJ-MM-TT: …"). Undatiert behauptet der Satz Gegenwart — auch noch, wenn er längst falsch ist.
- **Berechenbare Werte nicht abschreiben.** Test-, Zeilen-, Datei- oder Trefferzahlen, die ein Werkzeug jederzeit
  ausgibt, gehören nicht in Prosa: Befehl nennen oder Wert weglassen. Jede Kopie ist eine zweite Wahrheitsquelle,
  die niemand nachzieht. Datierte Messungen mit Befehl (`STATE.md` „Kennzahlen (gemessen)") sind die Ausnahme.
- **Wer etwas behebt, sucht seine Beschreibung.** Wird ein Fehler, ein Risiko oder eine Einschränkung beseitigt,
  gehört ein Grep nach der alten Beschreibung (Stichwort, Funktionsname, Formulierung) zum Fix; jede Fundstelle
  wird umgestellt. Sonst lädt die Doku dazu ein, Behobenes ein zweites Mal zu „reparieren".
- **„Funktioniert derzeit" ist eine Messung mit Ablaufdatum.** Wer eine bekannte Abweichung als wirkungslos
  einstuft, nennt den Umstand, der sie unterdrückt, und ob er festgeschrieben ist. Ein Zufall der Umgebung ist keine
  Behebung — und eine plausible Erklärung, die zur Beobachtung passt, ist eine Hypothese, bis eine Gegenprobe sie trägt.
- **Ein Echo ist kein Beleg.** Stammt eine Angabe aus derselben Stelle, an der sie eingetragen wurde (Konfiguration,
  eigene Annahme, früherer Doku-Text), bestätigt sie nichts. Das gilt auch für das Programm: Eine Log- oder
  Statuszeile, die einen Konfigurationswert ausgibt, als wäre er beobachtet, kann nicht fehlschlagen — messen oder
  als Angabe kennzeichnen.
- **Den Zustand der Verwendung prüfen.** Liegt zwischen Prüfung und Verwendung ein Schritt, der den Gegenstand
  verändert (eigener Code, Formatierer, Neustart, eine Konfiguration außerhalb der eigenen Kontrolle), belegt die
  Prüfung den Zustand davor. Dann an der Verwendungsstelle prüfen — oder dort wenigstens die Diagnose ermöglichen.

## Bestand zählen, bevor man darauf baut

Eine Feldliste, ein Schema oder ein Suchdialog belegt Struktur, nicht Befüllung. Bevor Code sich auf einen
Datenbestand verlässt:

- **Join, Export, Abgleich:** zählen, wie viele der Zielmenge den Schlüssel tatsächlich tragen (gesamt und in der
  Stichprobe). Wird gegen eine Referenz gemessen, je Kriterium zählend belegen, dass die Referenzspalte denselben
  Begriff trägt (Wertart, Einheit, Zeitpunkt, Währung) — fehlt das Gegenüber, ist das eine Frage vor dem Bau.
- **Feld streichen, Daten verschieben oder umformen:** vorher per Grep alle Lesestellen und Läufe aufzählen und je
  Fundstelle die Erwartung danach nennen; was nicht aufgezählt ist, gilt als nicht geprüft, nicht als grün.
- **Verschieben, Löschen, Überschreiben:** zuerst als Trockenlauf gegen eine bekannte Referenz, dann echt.

## Prüffrage

"Wenn der Nutzer diesen Pfad / diese Funktion / diese Zeile JETZT prüfen
würde — finde ich die Beweisspur in meinem Tool-Verlauf der letzten paar
Schritte?"
→ Wenn NEIN: nicht zitieren. Erst prüfen.

Und für Aussagen über einen Zustand: "Belegt meine Spur, dass es **jetzt noch gilt** — oder nur, dass es existiert?
Stammt sie aus einer Beobachtung oder aus derselben Quelle wie die Behauptung?"

## Eskalation bei Unsicherheit

Wenn die Prüfung nicht möglich ist (Datei nicht zugreifbar, externe Quelle
nicht abrufbar): den Zweifel explizit benennen ("ich vermute, habe aber nicht
verifiziert") statt eine sichere Aussage zu formulieren.

## Verwandt

- [[CONTEXT_DISCIPLINE]] — gezieltes Laden statt blindes Vermuten
- [[EXPLICIT_OVER_IMPLICIT]] — explizite Belege statt implizites Wissen
- [[FAIL_FAST]] — lieber frühzeitig anhalten und nachprüfen, als später falsch sein

## Projektspezifisch

<!-- Projekt-adaptierte Beispiele, Stage-Tabellen, Modul-Referenzen hier einfügen.
     Maßgeblich für die Update-Klassifizierung ist der Vergleich gegen die alte
     Template-Version (ALTES_PROJECT_AKTUALISIEREN.md, Schritt 2c/3): Solange diese
     Datei byte-identisch zum Template ist, gilt sie als Kategorie A (sicher
     überschreibbar). Jede lokale Anpassung — hier oder im Fließtext oben — macht
     sie zu Kategorie C: nur Drei-Wege-Merge, kein Blanket-Overwrite. -->
