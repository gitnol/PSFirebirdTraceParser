# Separation of Concerns

## Regel

Jede Schicht hat genau eine Verantwortung und kennt nur die Schicht direkt
unter ihr. Präsentation kennt keine Datenbank; Persistenz kennt keine HTTP-Codes.

## Sprach-agnostische Vorgaben

- Schichten als gerichteter Graph — keine zyklischen Abhängigkeiten zwischen Schichten
- Geschäftsregeln leben in der Domänen-/Service-Schicht, nicht in Controllern,
  Views oder Repositories
- Persistenz-Details (SQL-Eigenheiten, ORM-Spezifika) bleiben in Repositories —
  die Service-Schicht arbeitet auf Domänenobjekten, nicht auf ORM-Entities
- UI/View-Code (Jinja-Templates, Razor-Views, Streamlit-Layout) enthält KEINE
  Business-Logik — nur Präsentation
- Externe Services (HTTP-Clients, LLM-APIs) werden über eine Adapterschicht
  gekapselt — Domäne arbeitet gegen ein Interface, nicht gegen ein konkretes SDK

## Typische Schichten

| Schicht | Verantwortung | Darf kennen |
|---|---|---|
| Präsentation | Eingabe entgegennehmen, Ausgabe formatieren | Anwendung |
| Anwendung (Services) | Use Cases orchestrieren, Transaktionsgrenzen | Domäne, Adapter |
| Domäne | Geschäftsregeln, Invarianten | (nichts außerhalb der Domäne) |
| Infrastruktur (Adapter, Repositories) | Externe Welt anbinden, persistieren | Domäne |

## Prüffragen

- "Wenn ich die Datenbank austausche, welche Module muss ich anfassen?"
  → Nur Persistenzschicht. Domäne + Anwendungsschicht bleiben unverändert.

- "Wenn ich von CLI auf Web-UI wechsle, welche Module muss ich anfassen?"
  → Nur die Präsentation. Anwendungs- und Domänenschicht bleiben unverändert.

- "Wenn ich diese Geschäftsregel ändere, muss ich sie an mehreren Stellen anpassen?"
  → Wenn JA: die Regel lebt nicht in der Domäne, sondern dupliziert in UI + API.
    Refaktorieren.

## Verwandt

- [[ORTHOGONALITY]] — gleiche Stossrichtung auf Modulebene, eine Ebene granularer
- [[DRY]] — Schichtung verhindert duplizierte Geschäftslogik in UI und API
- [[YAGNI]] — nicht zu viele Schichten einführen, wenn 2 reichen

## Projektspezifisch

<!-- Projekt-adaptierte Beispiele, Stage-Tabellen, Modul-Referenzen hier einfügen.
     Maßgeblich für die Update-Klassifizierung ist der Vergleich gegen die alte
     Template-Version (ALTES_PROJECT_AKTUALISIEREN.md, Schritt 2c/3): Solange diese
     Datei byte-identisch zum Template ist, gilt sie als Kategorie A (sicher
     überschreibbar). Jede lokale Anpassung — hier oder im Fließtext oben — macht
     sie zu Kategorie C: nur Drei-Wege-Merge, kein Blanket-Overwrite. -->
