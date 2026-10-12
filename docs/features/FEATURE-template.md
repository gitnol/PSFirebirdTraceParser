# Feature: [Feature-Name]

---

## Zweck

[Was macht dieses Feature? Welche Automatisierungsaufgabe löst es? Ein Satz reicht.]

---

## Technologie / Abhängigkeiten

- [Modul — z.B. `ImportExcel`, `PSFramework`, `Az`]
- [Externe Ressource — z.B. "SharePoint-Liste via REST", "lokales Dateisystem"]

---

## Parameter

| Parameter | Typ | Pflicht | Default | Validierung | Beschreibung |
|-----------|-----|---------|---------|-------------|-------------|
| `-[Param1]` | `[string]` | Ja | — | `[ValidateNotNullOrEmpty]` | [Beschreibung] |
| `-[Param2]` | `[int]` | Nein | `[Default]` | `[ValidateRange(1,100)]` | [Beschreibung] |
| `-WhatIf` | Switch | Nein | `$false` | — | Dry-Run: keine Änderungen vornehmen |

---

## Kritische Patterns

- [Pattern 1 — z.B. "`$ErrorActionPreference = 'Stop'` am Funktionsanfang"]
- [Pattern 2 — z.B. "Join-Path statt String-Konkatenation für Pfade"]

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Status |
|---------------|---------|--------|
| [Einschränkung] | [Ursache] | [Geplant in I# / Akzeptiert] |

---

## Bekannte Fallstricke

- [Fallstrick 1 — z.B. "Invoke-Expression mit Benutzerpfaden vermeiden — Command-Injection-Risiko"]

---

## Teststrategie

- Zugehörige Testdatei: `tests/[Feature].Tests.ps1`
- Pester-Beschreibung: `Describe '[Feature]' { ... }`
- Kritische Testfälle: [z.B. "WhatIf macht keine Änderungen; ungültiger Pfad → Fehler"]
