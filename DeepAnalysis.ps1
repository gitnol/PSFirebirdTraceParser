# Anwendungsbeispiel:
# Wenn bei Get-SqlAnalysis in den LikeConditions das PercentCount = 1 und StartsWithPercent = true wäre, 
# dann könnte man einen Suchindex mit REVERSE(<FIELD>) in Firebird empfehlen, jedoch nur dann, wenn die Applikation ebenfalls dies erkennt.
# Denn die Abfrage müsste dann auch REVERSE(<FIELD>) LIKE REVERSE('...%') lauten, damit der Index genutzt werden kann.

# Außerdem könnte man die am häufigsten durchsuchten Tabellen/Objekte ermitteln, um gezielt Optimierungen vorzuschlagen.


function Get-SqlLikeConditions {
    <#
    Deprecated: Use Get-SqlAnalysis instead.
.SYNOPSIS Extrahiert LIKE-Felder + Suchwerte aus einem WHERE-Statement.

Get-SqlLikeConditions "SELECT * FROM X WHERE A LIKE '%2506%33%4%'"

Field                : A
Value                : %2506%33%4%
PercentCount         : 4
StartsWithPercent    : True
ContainsInnerPercent : True
EndsWithPercent      : True

#>
    param(
        [Parameter(Mandatory)]
        [string]$Sql
    )

    $where = [regex]::Match($Sql, '(?is)where\s+(.*)').Groups[1].Value
    if (-not $where) { return }

    $pattern = '(?is)([A-Za-z0-9_\.]+)\s+like\s+''([^'']*)'''
    $regmatches = [regex]::Matches($where, $pattern)

    foreach ($m in $regmatches) {
        $value = $m.Groups[2].Value

        $percentCount = ($value.ToCharArray() | Where-Object { $_ -eq '%' }).Count

        $starts = $value.StartsWith('%')
        $ends = $value.EndsWith('%')

        # Inneres % = ein % irgendwo außer Start/Ende
        $inner = $false
        if ($percentCount -gt 0) {
            $inner = ($value.Substring(1, $value.Length - 2) -match '%')
        }

        [PSCustomObject]@{
            Field                = $m.Groups[1].Value
            Value                = $value
            PercentCount         = $percentCount
            StartsWithPercent    = $starts
            ContainsInnerPercent = $inner
            EndsWithPercent      = $ends
        }
    }
}

function Get-SqlObjectName {
    <#
    .SYNOPSIS
        Deprecated: Use Get-SqlAnalysis instead.
        Liefert Objektname + Typ (SELECT, EXECUTE PROCEDURE, INSERT, UPDATE, DELETE, MERGE inklusive JOINS).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Sql
    )

    # Regex erweitert um JOINs (mit optionalen Präfixen wie INNER, LEFT, etc.)
    # (?is) = Case-insensitive, Single-line mode
    # Wir suchen nach Schlüsselwörtern, gefolgt von optionalen Anführungszeichen und dem Namen
    $pattern = '(?is)(from|execute\s+procedure|insert\s+into|update|delete\s+from|merge\s+into|(?:(?:inner|left|right|full|cross|outer)\s+)*join)\s+"?([A-Za-z0-9_\.]+)"?'

    # [regex]::Matches verwenden, um ALLE Vorkommen zu finden
    $allMatches = [regex]::Matches($Sql, $pattern)

    foreach ($m in $allMatches) {
        if ($m.Success) {
            # Bereinigen des Typs (z.B. "  inner join " -> "INNER JOIN") und in Großbuchstaben
            # Wir ersetzen auch mehrfache Leerzeichen durch einfache für sauberen Output
            $rawCommand = $m.Groups[1].Value -replace '\s+', ' '
            $type = $rawCommand.Trim().ToUpper()
            
            # Das gefundene Objekt (Tabelle/Prozedur)
            $objectName = $m.Groups[2].Value

            [PSCustomObject]@{
                Type   = $type
                Object = $objectName
            }
        }
    }
}

function Get-SqlAnalysis {
    <#
    .SYNOPSIS
        Analysiert ein SQL-Statement und extrahiert sowohl verwendete Objekte (Tabellen/Joins) 
        als auch Analysen zu LIKE-Bedingungen.

        $sql = "SELECT * FROM Kunde k 
                INNER JOIN Adresse a ON k.Id = a.KundeId 
                WHERE k.Name LIKE 'Müller%' 
                AND a.Strasse LIKE '%weg%'
                ORDER BY k.Name"

        # Funktion aufrufen
        $result = Get-SqlAnalysis -Sql $sql

        # 1. Zugriff auf die gefundenen Tabellen
        Write-Host "--- Gefundene Objekte ---" -ForegroundColor Cyan
        $result.DbObjects | Format-Table -AutoSize

        # 2. Zugriff auf die LIKE Analysen
        Write-Host "--- Gefundene LIKEs ---" -ForegroundColor Cyan
        $result.LikeConditions | Format-Table -AutoSize

    #>
    param(
        [Parameter(Mandatory)]
        [string]$Sql
    )

    # ---------------------------------------------------------
    # TEIL 1: Objekte ermitteln (Tables, Joins, Procedures)
    # ---------------------------------------------------------
    $foundObjects = @()
    
    # Regex: Sucht nach Keywords (FROM, JOIN, INSERT etc.) gefolgt vom Objektnamen
    $patternObj = '(?is)(from|execute\s+procedure|insert\s+into|update|delete\s+from|merge\s+into|(?:(?:inner|left|right|full|cross|outer)\s+)*join)\s+"?([A-Za-z0-9_\.]+)"?'
    $matchesObj = [regex]::Matches($Sql, $patternObj)

    foreach ($m in $matchesObj) {
        if ($m.Success) {
            $rawCommand = $m.Groups[1].Value -replace '\s+', ' '
            $type = $rawCommand.Trim().ToUpper()
            $objectName = $m.Groups[2].Value

            # Zuweisung an Variable im Block (Best Practice)
            $objItem = [PSCustomObject]@{
                Type   = $type
                Object = $objectName
            }
            $foundObjects += $objItem
        }
    }

    # ---------------------------------------------------------
    # TEIL 2: LIKE-Conditions analysieren
    # ---------------------------------------------------------
    $foundConditions = @()

    # Schritt A: Den WHERE-Teil isolieren
    # Optimierung: Stoppt vor ORDER BY, GROUP BY oder HAVING, damit diese nicht analysiert werden.
    $whereMatch = [regex]::Match($Sql, '(?is)where\s+(.*?)(?:\s+order\s+by|\s+group\s+by|\s+having|$)')
    
    if ($whereMatch.Success) {
        $whereClause = $whereMatch.Groups[1].Value

        # Schritt B: LIKEs innerhalb des WHERE finden
        $patternLike = '(?is)([A-Za-z0-9_\.]+)\s+like\s+''([^'']*)'''
        $matchesLike = [regex]::Matches($whereClause, $patternLike)

        foreach ($m in $matchesLike) {
            $fieldName = $m.Groups[1].Value
            $value = $m.Groups[2].Value
            
            # Analyse der Wildcards
            $percentCount = ($value.ToCharArray() | Where-Object { $_ -eq '%' }).Count
            $starts = $value.StartsWith('%')
            $ends = $value.EndsWith('%')
            
            # Inneres % prüfen (nur wenn lang genug und nicht nur Start/Ende)
            $inner = $false
            if ($percentCount -gt 0 -and $value.Length -gt 2) {
                # Schneidet erstes und letztes Zeichen ab und prüft den Rest
                $subCheck = $value.Substring(1, $value.Length - 2)
                if ($subCheck -match '%') { $inner = $true }
            }

            $condItem = [PSCustomObject]@{
                Field                = $fieldName
                Value                = $value
                PercentCount         = $percentCount
                StartsWithPercent    = $starts
                ContainsInnerPercent = $inner
                EndsWithPercent      = $ends
            }
            $foundConditions += $condItem
        }
    }

    # ---------------------------------------------------------
    # TEIL 3: Ergebnis zusammenfügen
    # ---------------------------------------------------------
    
    # Rückgabe eines Objekts, das beide Listen enthält
    [PSCustomObject]@{
        OriginalSql    = $Sql
        DbObjects      = $foundObjects
        LikeConditions = $foundConditions
    }
}


# Erste 10000 SQL Statements aus der Analyse-Tabelle holen
$analysebasis = $erg | Where-Object SqlStatement -ne $null | Select-Object -First 10000 | Select-Object User, SqlStatement, @{N = 'SQLObject'; E = { (Get-SqlObjectName($_.SqlStatement)).Object } }, @{N = 'SQLType'; E = { (Get-SqlObjectName($_.SqlStatement)).Type } }

# Alle Ergebnisse holen
# $analysebasis = $erg | Where-Object SqlStatement -ne $null | Select-Object User, SqlStatement, @{N = 'SQLObject'; E = { (Get-SqlObjectName($_.SqlStatement)).Object } }, @{N = 'SQLType'; E = { (Get-SqlObjectName($_.SqlStatement)).Type } }

# # Beispiel: Alle LIKE-Bedingungen anzeigen
# $analysewhere = $erg | Where-Object SqlStatement -like "*'%*" | Select User,SqlStatement, @{N='LikeConditions';E={Get-SqlLikeConditions($_.SqlStatement)}}
# $analysewhere | ogv

# # Erste 10000 SQL Statements aus der Analyse-Tabelle holen
# $analyse_part = $erg | Where-Object { $null -ne $_.SqlStatement } | Select-Object -First 10000 | ForEach-Object {
    
#     # 1. Analyse nur EINMAL ausführen (Performance-Vorteil)
#     $analysis = Get-SqlAnalysis -Sql $_.SqlStatement

#     # 2. Das Objekt zusammenbauen
#     # PowerShells "Member Enumeration" erlaubt es uns, $analysis.DbObjects.Object 
#     # zu schreiben, um direkt das Array aller Tabellennamen zu erhalten.
#     [PSCustomObject]@{
#         User           = $_.User
#         SqlStatement   = $_.SqlStatement
#         SQLObject      = $analysis.DbObjects.Object
#         SQLType        = $analysis.DbObjects.Type
#         LikeConditions = $analysis.LikeConditions
#     }
# }

# Gesamte Analyse (ohne Limitierung)
$analyse_all = $erg | Where-Object { $null -ne $_.SqlStatement } | ForEach-Object {
    # 1. Analyse nur EINMAL ausführen (Performance-Vorteil)
    $analysis = Get-SqlAnalysis -Sql $_.SqlStatement

    # 2. Das Objekt zusammenbauen
    # PowerShells "Member Enumeration" erlaubt es uns, $analysis.DbObjects.Object 
    # zu schreiben, um direkt das Array aller Tabellennamen zu erhalten.
    [PSCustomObject]@{
        User           = $_.User
        SqlStatement   = $_.SqlStatement
        SQLObject      = $analysis.DbObjects.Object # -join ', '
        SQLType        = $analysis.DbObjects.Type # -join ', '
        LikeConditions = $analysis.LikeConditions # -join ', '
    }
}

$TopObjects = $analyse_all | Group-Object -Property SQLObject | Sort-Object Count -Descending
$TopObjects | Out-GridView

$FlatPerUser = $analyse_all |
Group-Object User |
ForEach-Object {
    $u = $_.Name
    $_.Group |
    Group-Object SQLObject |
    Sort-Object Count -Descending |
    ForEach-Object {
        [PSCustomObject]@{
            User      = $u
            SQLObject = $_.Name
            Count     = $_.Count
        }
    }
}
$FlatPerUser | Sort-Object Count -Descending | Out-GridView
