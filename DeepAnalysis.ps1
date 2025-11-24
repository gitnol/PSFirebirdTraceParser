function Get-SqlLikeConditions {
    <#
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



# function Get-SqlObjectName {
#     <#
# .SYNOPSIS Liefert Objektname + Typ (SELECT, EXECUTE PROCEDURE, INSERT, UPDATE, DELETE, MERGE).
# #>
#     param(
#         [Parameter(Mandatory)]
#         [string]$Sql
#     )

#     # Erlaubt:
#     #   FROM / EXECUTE PROCEDURE / INSERT INTO / UPDATE / DELETE FROM / MERGE INTO
#     #   optional Quotes
#     #   optional Schema (z.B. SCHEMA.TABELLE)
#     $pattern = '(?is)(from|execute\s+procedure|insert\s+into|update|delete\s+from|merge\s+into)\s+"?([A-Za-z0-9_\.]+)"?'
#     $m = [regex]::Match($Sql, $pattern)

#     if ($m.Success) {
#         $command = $m.Groups[1].Value.Trim().ToUpper()

#         switch -Regex ($command) {
#             '^FROM$' { $type = 'FROM' }
#             '^EXECUTE\s+PROCEDURE$' { $type = 'EXECUTE PROCEDURE' }
#             '^INSERT\s+INTO$' { $type = 'INSERT INTO' }
#             '^UPDATE$' { $type = 'UPDATE' }
#             '^DELETE\s+FROM$' { $type = 'DELETE FROM' }
#             '^MERGE\s+INTO$' { $type = 'MERGE INTO' }
#         }

#         [PSCustomObject]@{
#             Type   = $type
#             Object = $m.Groups[2].Value
#         }
#     }
# }


function Get-SqlObjectName {
    <#
    .SYNOPSIS
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

# Erste 10000 SQL Statements aus der Analyse-Tabelle holen
$analysebasis = $erg | Where-Object SqlStatement -ne $null | Select-Object -First 10000 | Select-Object User, SqlStatement, @{N = 'SQLObject'; E = { (Get-SqlObjectName($_.SqlStatement)).Object } }, @{N = 'SQLType'; E = { (Get-SqlObjectName($_.SqlStatement)).Type } }

# Alle Ergebnisse holen
# $analysebasis = $erg | Where-Object SqlStatement -ne $null | Select-Object User, SqlStatement, @{N = 'SQLObject'; E = { (Get-SqlObjectName($_.SqlStatement)).Object } }, @{N = 'SQLType'; E = { (Get-SqlObjectName($_.SqlStatement)).Type } }

# # Beispiel: Alle LIKE-Bedingungen anzeigen
# $analysewhere = $erg | Where-Object SqlStatement -like "*'%*" | Select User,SqlStatement, @{N='LikeConditions';E={Get-SqlLikeConditions($_.SqlStatement)}}
# $analysewhere | ogv

$TopObjects = $analysebasis |
Group-Object -Property SQLObject |
Sort-Object Count -Descending

$TopObjects | Out-GridView


$FlatPerUser = $analysebasis |
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
