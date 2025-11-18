<#
.SYNOPSIS
    Analysiert eine Sammlung von geparsten Firebird-Trace-Objekten,
    um Statistiken zu Häufigkeit, Dauer und Performance zu erstellen.

.DESCRIPTION
    Dieses Skript nimmt die Ausgabe von 'Show-TraceStructure.ps1' über die
    Pipeline entgegen. Es berechnet Hashes für SQL-Statements und Pläne
    und gruppiert die Einträge, um aggregierte Statistiken zu erstellen.

.PARAMETER InputObject
    Die [PSCustomObject]-Einträge, die von 'Show-TraceStructure.ps1'
    generiert wurden. Dieser Parameter wird über die Pipeline befüllt.

.PARAMETER GroupBy
    Definiert, wonach gruppiert werden soll.
    - 'SqlHash': Gruppiert identische SQL-Statements (Standard).
    - 'PlanHash': Gruppiert identische Ausführungspläne.
    - 'User': Gruppiert nach dem Benutzer.
    - 'ApplicationPath': Gruppiert nach dem Pfad der Anwendung.

.EXAMPLE
    # Analysiert ein Log und gruppiert nach identischen SQL-Abfragen
    .\Show-TraceStructure.ps1 -Path "trace.log" | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash

.EXAMPLE
    # Findet die häufigsten Ausführungspläne
    $erg = .\Show-TraceStructure.ps1 -Path "trace.log"
    $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy PlanHash | Sort-Object Count -Descending

.OUTPUTS
    [System.Management.Automation.PSCustomObject[]]
    Ein Array von aggregierten Statistik-Objekten.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [psobject]$InputObject,

    [Parameter(Mandatory = $false)]
    [ValidateSet("SqlHash", "PlanHash", "User", "ApplicationPath")]
    [string]$GroupBy = "SqlHash"
)

# Pipeline-Verarbeitung
begin {
    # Interne Helper-Funktion, um einen SHA256-Hash von einem String zu erstellen
    function Get-StringHash($InputString) {
        if ([string]::IsNullOrEmpty($InputString)) { return $null }
        
        # Using ist wichtig, damit die Ressourcen freigegeben werden
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
        $hashBytes = $sha.ComputeHash($bytes)
        
        # Konvertiert das Byte-Array in einen hexadezimalen String
        return [System.BitConverter]::ToString($hashBytes).Replace('-', '').ToLowerInvariant()
    }

    # Wir verwenden eine .NET List für bessere Performance beim Hinzufügen
    $allObjects = [System.Collections.Generic.List[psobject]]::new()
    Write-Host "Starte Analyse. Sammle Einträge aus der Pipeline..."
}

process {
    # Fügt jedes Objekt aus der Pipeline der Liste hinzu
    $allObjects.Add($InputObject)
}

end {
    Write-Host "Alle $($allObjects.Count) Einträge empfangen. Berechne Hashes und aggregate..."
    
    # 1. Alle Objekte anreichern
    # Wir fügen SqlHash und PlanHash zu *jedem* Objekt hinzu
    $enrichedObjects = $allObjects | Select-Object *,
    @{Name = "SqlHash"; Expression = { Get-StringHash $_.SqlStatement } },
    @{Name = "PlanHash"; Expression = { Get-StringHash $_.SqlPlan } }

    # 2. Filtern und Gruppieren
    # Wir filtern alle Einträge heraus, bei denen der GroupBy-Wert $null ist
    # (z.B. Einträge ohne SQL-Statement, wenn nach SqlHash gruppiert wird)
    $groupedData = $enrichedObjects | Where-Object { $_.$GroupBy } | Group-Object -Property $GroupBy

    # 3. Statistik-Objekte erstellen
    $report = $groupedData | ForEach-Object {
        
        # Aggregierte Werte für die Gruppe berechnen
        $totalDuration = ($_.Group | Measure-Object DurationMs -Sum).Sum
        $totalFetches = ($_.Group | Measure-Object Fetches -Sum).Sum
        $totalWrites = ($_.Group | Measure-Object Writes -Sum).Sum
        
        [PSCustomObject]@{
            GroupValue        = $_.Name
            GroupBy           = $GroupBy
            Count             = $_.Count
            TotalDurationMs   = $totalDuration
            TotalFetches      = $totalFetches
            TotalWrites       = $totalWrites
            AvgDurationMs     = if ($_.Count -gt 0) { [Math]::Round($totalDuration / $_.Count, 2) } else { 0 }
            AvgFetches        = if ($_.Count -gt 0) { [Math]::Round($totalFetches / $_.Count, 0) } else { 0 }
            
            # Wir nehmen das erste Objekt der Gruppe als Referenz für die Textfelder
            # (Nützlich, um das SQL-Statement oder den Plan-Text zu sehen)
            FirstSqlStatement = ($_.Group | Select-Object -First 1).SqlStatement
            FirstSqlPlan      = ($_.Group | Select-Object -First 1).SqlPlan
            FirstUser         = ($_.Group | Select-Object -First 1).User
        }
    }

    Write-Host "Analyse abgeschlossen. Gebe $($report.Count) Gruppen zurück."
    
    # 4. Bericht ausgeben, sortiert nach Häufigkeit (Count)
    $report | Sort-Object Count -Descending
}

# Um die 10 langsamsten *individuellen* Abfragen zu finden (wie in deinem RANK-Beispiel),
# brauchst du das Skript nicht. Das machst du direkt mit der Ausgabe des Parsers:
# $erg = .\Show-TraceStructure.ps1 -Path "C:\temp\20251113\trace_output_ib_aid_20251112\trace_output_ib_aid_20251112.log" 
# $erg | Sort-Object DurationMs -Descending | Select-Object -First 10


# Führt die Analyse durch und speichert die nach SqlHash gruppierten Ergebnisse:
# $sqlStats = $erg | .\Get-FbTraceAnalysis.ps1 -GroupBy SqlHash

# Zeigt die 10 häufigsten SQL-Abfragen an
# $sqlStats | Select-Object -First 10 | Format-Table Count, AvgDurationMs, TotalFetches, FirstSqlStatement -Wrap
