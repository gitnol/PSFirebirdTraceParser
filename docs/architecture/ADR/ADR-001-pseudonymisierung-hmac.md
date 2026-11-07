# ADR-001: Pseudonyme per HMAC-SHA256 mit Schlüssel, der beim Datenverantwortlichen bleibt

**Status:** Accepted
**Datum:** 2026-11-07

## 1. Kontext & Problem

`Pseudonymize-FirebirdTrace.ps1` bildete Pseudonyme als ungesalzenes, gekürztes SHA-256 des Klartexts. Wer den Wert
vermutet, kann ihn bestätigen; kleine Wertebereiche (alle IPv4-Adressen, bekannte Benutzerlisten) lassen sich komplett
vorausberechnen (`security/THREAT_MODEL.md` Bedrohung 2). Damit ist jeder Empfänger der Daten in der Lage, Personen zu
re-identifizieren. Die EDPB-Leitlinien 01/2025 nennen schlüsselbasierte Verfahren (MAC/HMAC) als stärkere Technik. Nach
EuGH C-413/23 P (4. 9. 2025) hängt der Personenbezug pseudonymisierter Daten für einen Empfänger davon ab, ob dieser
realistischerweise re-identifizieren kann — dafür muss die Zuordnung beim Verantwortlichen bleiben.

## 2. Betrachtete Alternativen

* **Salz pro Lauf, öffentlich:** verhindert nur vorberechnete Tabellen, nicht das gezielte Prüfen einzelner Werte.
* **HMAC-SHA256 mit geheimem Schlüssel aus Datei** (`-KeyFile`), Schlüssel bleibt beim Verantwortlichen.
* **HMAC mit Schlüssel als `SecureString`-Parameter:** in Skripten unpraktisch (muss trotzdem irgendwo gespeichert werden).
* **Verschlüsselung (umkehrbar) statt Hash:** mit Schlüssel umkehrbar — der Verantwortliche bräuchte das, die
  Zuordnungsdatei (unten) deckt den Bedarf aber ohne neues Krypto-Verfahren.

## 3. Entscheidung

1. Pseudonym = erste `-HashLength` Hex-Zeichen von **HMAC-SHA256(Schlüssel, UTF-8(Wert))**.
2. Schlüssel aus `-KeyFile`: Base64, mindestens 32 Byte. Existiert die Datei nicht, wird ein Zufallsschlüssel (32 Byte,
   kryptografischer Zufall) erzeugt und gespeichert; die Datei erhält Rechte nur für den aktuellen Benutzer.
3. Ohne `-KeyFile`: Zufallsschlüssel **nur für diesen Lauf** (mit Warnung) — Pseudonyme sind dann innerhalb eines Laufs
   konsistent, aber nicht über Läufe hinweg vergleichbar und für niemanden umkehrbar.
4. Optional `-MappingFile`: Zuordnungstabelle Pseudonym → Original (CSV) für den Verantwortlichen, damit er Ergebnisse
   (z. B. „Benutzer `3f9a…` verursacht Sperrkonflikte") auf echte Werte zurückführen kann. Rechte nur für den aktuellen
   Benutzer, Warnung bei der Erzeugung.
5. Schlüssel und Zuordnung werden nie ausgegeben, geloggt oder in die pseudonymisierten Objekte geschrieben.

## 4. Begründung

* Ohne Schlüssel kann ein Empfänger Pseudonyme weder vorausberechnen noch gezielt prüfen; der Verantwortliche kann
  über Schlüssel und Zuordnungsdatei jederzeit zurückführen — genau die Rollenteilung des geplanten Dienstes
  (Kunde behält Schlüssel und Zuordnung, Dienstleister sieht nur Pseudonyme).
* Gleicher Schlüssel über mehrere Läufe → gleiche Pseudonyme → Trends und Vorher-nachher-Vergleiche möglich.
* HMAC-SHA256 ist in .NET eingebaut (`System.Security.Cryptography.HMACSHA256`), keine Abhängigkeit.

## 5. Konsequenzen

* **Positiv:** Wörterbuch- und Vorausberechnungsangriffe ohne Schlüssel nicht mehr möglich; Rückführung nur beim Verantwortlichen.
* **Negativ/Risiken:** Pseudonyme ändern sich gegenüber früheren Läufen (SHA-256) — alte und neue Exporte sind nicht
  vergleichbar. Verlust des Schlüssels = keine Vergleichbarkeit mehr; Abfluss des Schlüssels = Re-Identifikation durch
  jeden, der ihn hat (Schlüssel wie ein Passwort behandeln). Gekürzte Pseudonyme (Standard 12 Hex = 48 Bit) können bei
  sehr vielen Werten kollidieren; die Zuordnungsdatei meldet Kollisionen. Daten bleiben für den Verantwortlichen
  personenbezogen (DSGVO); Informationspflichten bei Weitergabe bleiben bestehen.
