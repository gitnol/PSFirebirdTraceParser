# Logging Strategy

## Regel

Logs sind das einzige Fenster in den Systemzustand eines laufenden Prozesses.
Jeder Log-Eintrag muss ohne Kontextwissen verständlich und filterbar sein.

## Konkrete Vorgaben

- **Level DEBUG:** Detaillierter Datenfluss (z.B. "Datei X gelesen, Hash: Y")
- **Level INFO:** Fachliche Meilensteine (z.B. "Dokument X erfolgreich verarbeitet")
- **Level WARNING:** Erwartete, aber behandelte Probleme (z.B. "Service Timeout, Versuch 1/3")
- **Level ERROR:** Unerwartete Fehler – muss zwingend den Stacktrace enthalten (z. B. Python `exc_info=True`,
  .NET `LogError(ex, …)`)
- **Kontext:** Jeder Eintrag muss IDs, Dateinamen oder Bezeichner enthalten.
  "Verarbeitung fehlgeschlagen" ist verboten.
  "Verarbeitung für Datei 'X.pdf' fehlgeschlagen" ist korrekt.
- Konsolenausgaben über `print()` sind für interaktive CLI-Tools akzeptabel.
  Bei automatisiertem Betrieb (Scheduler, Service) muss das Logging-Framework verwendet werden.

## Verwandt

- [[FAIL_FAST]]
- [[UNTRUSTED_DOCUMENT_CONTENT]]

## Projektspezifisch

<!-- Hier beim Befüllen ersetzen. Maßgeblich für die Update-Klassifizierung ist
     der Vergleich gegen die alte Template-Version (ALTES_PROJECT_AKTUALISIEREN.md,
     Schritt 2c/3): LOGGING.md ist konstruktionsbedingt immer Kategorie C. -->


- **Genutzt:** kein Logging-Framework, kein Event Log. Meldungen nur an die Konsole: `Write-Host` (Status, Hinweise),
  `Write-Error` (Fehler), `Write-Progress` (Fortschritt im Parser alle 5000 Blöcke, im Pseudonymisierer alle 1000 Objekte).
  Ziel (I5/I6): Status über `Write-Verbose`/`Write-Information`, damit die Pipeline-Ausgabe sauber bleibt.
- **Debug-Modus:** keiner. Nach Einführung von `[CmdletBinding()]` in allen Skripten über `-Verbose`.
- **Nie ausgeben oder protokollieren:** Firebird-Passwort, Kommandozeile mit `-PASS`, Inhalte von Trace-Blöcken
  (SQL-Texte, Parameter, Benutzer, IPs) in Status- oder Fehlermeldungen. Ausnahme bewusst: `-AnalyzeOnly` zeigt
  Literale und Klauseln im Klartext an — das ist seine Funktion, die Ausgabe ist vertraulich (`security/DATA_HANDLING.md`).
- **Wohin:** nur Konsole; die einzige Datei, die entsteht, ist die Trace-Ausgabe von `fbtracemgr` (kein Anwendungs-Log).
