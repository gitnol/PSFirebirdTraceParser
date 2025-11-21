<#
.SYNOPSIS
    Gruppiert Trace-Einträge basierend auf ihrer Transaktions-Zugehörigkeit (Chain).

.DESCRIPTION
    Dieses Skript analysiert die Beziehung zwischen TransactionID (TRA_...) und 
    InitiatorID (INIT_...). Es fasst alle Aktionen (SQLs, Commits, Rollbacks), 
    die logisch zu einer Sitzung/Kette gehören, zusammen.
    
    Dies hilft zu verstehen, welche SQL-Befehle zu den "teuren" Commits gehören.

.PARAMETER InputObject
    Die [PSCustomObject]-Einträge aus 'Show-TraceStructure.ps1'.

.EXAMPLE
    $erg | .\Get-FbTransactionGrouping.ps1 | Sort-Object TotalDurationMs -Descending | Select-Object -First 5

.OUTPUTS
    [PSCustomObject] mit aggregierten Werten pro Transaktionskette.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [psobject]$InputObject
)

begin {
    $allObjects = [System.Collections.Generic.List[psobject]]::new()
    Write-Host "Sammle Transaktionsdaten..."
}

process {
    $allObjects.Add($InputObject)
}

end {
    Write-Host "Analysiere $($allObjects.Count) Einträge auf Transaktions-Ketten..."

    # Wir müssen eine "RootTxID" (die Ursprungs-Transaktion) für jeden Eintrag bestimmen
    $enriched = $allObjects | Select-Object *, @{Name = "RootTxID"; Expression = {
            if (-not [string]::IsNullOrWhiteSpace($_.InitID)) {
                # Wenn es eine InitID gibt (z.B. bei Commit Transaction oder späteren SQLs), ist das der Vater
                return $_.InitID
            }
            elseif (-not [string]::IsNullOrWhiteSpace($_.TransactionID)) {
                # Wenn keine InitID da ist, aber eine TransactionID (z.B. Start Transaction), ist es selbst der Vater
                return $_.TransactionID
            }
            else {
                # Einträge ohne jegliche Transaktionsinfo (z.B. Connect/Disconnect)
                return "NoTx"
            }
        }
    }

    # Gruppieren nach dieser RootID (und User, damit wir wissen wer es war)
    # Wir filtern "NoTx" raus, da diese für Transaktionsanalyse irrelevant sind
    $grouped = $enriched | Where-Object { $_.RootTxID -ne "NoTx" } | Group-Object RootTxID

    $results = foreach ($chain in $grouped) {
        # Statistiken berechnen
        $totalDuration = ($chain.Group | Measure-Object DurationMs -Sum).Sum
        $totalFetches = ($chain.Group | Measure-Object Fetches -Sum).Sum
        $totalWrites = ($chain.Group | Measure-Object Writes -Sum).Sum
        $totalMarks = ($chain.Group | Measure-Object Marks -Sum).Sum
        
        # Alle eindeutigen SQL-Statements in dieser Kette sammeln (ohne Leere)
        $sqls = $chain.Group.SqlStatement | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        
        # Den User ermitteln (vom ersten Eintrag, der einen User hat)
        $user = ($chain.Group | Where-Object { $_.User } | Select-Object -First 1).User

        # Start- und Endzeit der gesamten Kette ermitteln
        $sortedGroup = $chain.Group | Sort-Object Timestamp
        $startTime = ($sortedGroup | Select-Object -First 1).Timestamp
        $endTime = ($sortedGroup | Select-Object -Last 1).Timestamp

        # Versuchen, den Prozess/Applikation zu finden
        $app = ($chain.Group | Where-Object { $_.ApplicationPath } | Select-Object -First 1).ApplicationPath

        [PSCustomObject]@{
            RootTxID        = $chain.Name
            User            = $user
            App             = $app
            CountEntries    = $chain.Count
            TotalDurationMs = $totalDuration
            TotalFetches    = $totalFetches
            TotalWrites     = $totalWrites
            TotalMarks      = $totalMarks
            StartTime       = $startTime
            EndTime         = $endTime
            UniqueSqlCount  = $sqls.Count
            # Wir fügen die SQLs als Array bei, falls man sie inspizieren will
            SqlStatements   = $sqls 
        }
    }

    Write-Host "Gefundene Transaktions-Ketten: $($results.Count)"
    
    # Ausgabe sortiert nach Writes (da dich diese Ressourcennutzung interessiert hat)
    $results | Sort-Object TotalWrites -Descending
}