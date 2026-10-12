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

## Prüffrage

"Wenn der Nutzer diesen Pfad / diese Funktion / diese Zeile JETZT prüfen
würde — finde ich die Beweisspur in meinem Tool-Verlauf der letzten paar
Schritte?"
→ Wenn NEIN: nicht zitieren. Erst prüfen.

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
