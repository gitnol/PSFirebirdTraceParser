# Egress by Declaration (Ausgehende Verbindungen nur deklariert)

## Regel

Ein Programm, Dienst oder Container baut nur dort Verbindungen nach außen auf, wo das
**dokumentiert und gewollt** ist — **DNS eingeschlossen**. Alles andere wird **technisch
verweigert**, nicht nur „nicht konfiguriert". Grundlage ist eine Egress-Liste des Projekts:
Ziel (Rolle oder Dienst), Zweck, Protokoll/Port, Zeitpunkt (Laufzeit, Build, Wartung) und wer
es braucht. Steht eine Verbindung nicht darin, ist sie nicht erlaubt. Zur Liste gehört der
**Update-Weg**: wie das System trotz Sperre aktualisiert wird.

## Warum

Bibliotheken, Modelle und Container-Images telefonieren nach Hause: Telemetrie und
Usage-Statistiken, Update-Checks, Modell-Downloads beim ersten Aufruf, Analytics einer
mitgelieferten Oberfläche. Die Voreinstellungen ändern sich mit jedem Update, ohne dass der
eigene Code sich ändert. Auf einem System mit vertraulichen Daten ist jede unbekannte
Verbindung ein möglicher Abfluss — und jede unbekannte Namensauflösung verrät mindestens,
was dort läuft.

Belegter Fall: Ein Dokumenten-Parser im Container war per Firewall gegen ausgehende Pakete
gesperrt; die Namensauflösung lief trotzdem weiter, weil der eingebettete DNS der
Container-Laufzeit Anfragen an den Resolver des Hosts weiterreichte. Die Sperre galt als
vollständig, bis ein Negativtest mit `getent hosts <externer Name>` aus dem Container sie
widerlegte.

## Umsetzung

- **Egress-Liste** zuerst: jede gewollte Verbindung mit Ziel, Zweck, Port, Zeitpunkt. Sie
  gehört zur Sicherheitsdoku (z. B. Threat Model oder Datenfluss-Doku) und wird bei jeder
  neuen Abhängigkeit, jedem neuen Dienst und jedem Feature mit Netzbezug im selben Inkrement
  angepasst.
- **Durchsetzen auf der Ebene, die das Programm nicht selbst umgehen kann:** Firewall- oder
  Netzregeln (Container-Netz ohne Ausgang, DROP für alles nicht Gelistete), nicht nur
  Konfiguration der Anwendung. Offline-Schalter und abgeschaltete Telemetrie zusätzlich,
  nie statt der Sperre.
- **DNS zählt:** Laufzeit ohne externe Namensauflösung, wenn sie nicht gelistet ist (z. B.
  eigener Resolver ohne Weiterleitung, `dns: 127.0.0.1` im Container). Eine Sperre nur für
  TCP/HTTP lässt Namen und DNS-Tunnel durch.
- **Build und Laufzeit trennen:** Downloads (Pakete, Modelle, Images) nur im Build- oder
  Wartungsfenster und dort gelistet; der laufende Dienst arbeitet offline.
- **Update-Weg mitliefern:** Eine Sperre ohne beschriebenen Aktualisierungsweg führt zu
  veralteten Komponenten oder zu Ausnahmen, die offen bleiben. Zur Egress-Liste gehört deshalb
  ausdrücklich, *wie* aktualisiert wird: welche Update-Quellen (Paket-Index, Betriebssystem-
  Archiv, Image-Registry, Modell-Hub) zu welchem Zeitpunkt erreichbar sind, über welchen Weg
  (Neubau des Images mit Netz nur im Build, Spiegel/Proxy, befristet geöffnetes
  Wartungsfenster mit festem Ende) und welche Prüfung danach folgt (Scanner, Negativtest,
  Funktionsprobe, Rückweg). Wer das Update ausführt, braucht dafür keine Sperre dauerhaft zu
  lockern.
- **Kein Host-Netz aus Bequemlichkeit:** `--network host` oder gleichwertige Freigaben heben
  jede Sperre auf und brauchen eine ausdrückliche, begründete Ausnahme in der Egress-Liste.
- **Nachweis per Negativtest:** Aus dem Prozess bzw. Container müssen Namensauflösung und
  Verbindung zu einem bekannten externen Ziel scheitern — bei der Einrichtung, nach jedem
  Update von Image, Laufzeit oder Netz und in jedem Security-Sweep
  ([[SECURITY_CURRENCY]]). Geblockte Versuche protokollieren (z. B. LOG-Regel vor dem DROP)
  und auswerten: Sie zeigen, wer nach Hause telefonieren wollte.

## Anti-Patterns

- **„Läuft lokal, braucht kein Netz"** — ohne Sperre ist das eine Annahme, keine Eigenschaft.
- **Sperre ohne DNS** — Pakete verworfen, Namen aufgelöst.
- **Offline-Variablen als einzige Maßnahme** — der nächste Release kennt eine neue Variable.
- **Sperre ohne Negativtest** — bricht beim nächsten Netz- oder Laufzeitwechsel unbemerkt.
- **Ausnahme ohne Eintrag** — „nur kurz zum Testen geöffnet" und vergessen.
- **Sperre ohne Update-Weg** — Updates unterbleiben oder die Sperre wird dafür dauerhaft gelockert.

## Verwandt

- [[SECURITY_CURRENCY]] — der Sweep prüft auch die Egress-Liste und den Negativtest.
- [[UNTRUSTED_DOCUMENT_CONTENT]] — fremde Inhalte dürfen keinen Weg nach außen finden.
- [[EXPLICIT_OVER_IMPLICIT]] — gewollte Verbindungen stehen ausdrücklich in der Liste.
- [[FAIL_FAST]] — eine nicht gelistete Verbindung scheitert sofort und sichtbar.

## Projektspezifisch

<!-- Egress-Liste des Projekts (Ziel, Zweck, Port, Zeitpunkt, Durchsetzung, Negativtest) oder Verweis
     auf ihren Ort hier einfügen.
     Maßgeblich für die Update-Klassifizierung ist der Vergleich gegen die alte
     Template-Version (ALTES_PROJECT_AKTUALISIEREN.md, Schritt 2c/3): Solange diese
     Datei byte-identisch zum Template ist, gilt sie als Kategorie A (sicher
     überschreibbar). Jede lokale Anpassung — hier oder im Fließtext oben — macht
     sie zu Kategorie C: nur Drei-Wege-Merge, kein Blanket-Overwrite. -->
