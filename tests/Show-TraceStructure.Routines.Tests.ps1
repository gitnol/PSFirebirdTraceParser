#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer Prozeduren, Funktionen und Trigger als Ereignisse und die Verbindungsdauer (I12).
    Fixtures: tests/fixtures/trace_fb5_routines.log und trace_fb4_routines.log - synthetisch, Format nach Firebird
    src/utilities/ntrace/TracePluginImpl.cpp (v5.0-release: logRecordProc/logRecordFunc/logRecordTrig,
    v4.0-release: logRecordProcFunc und log_event_trigger_execute), alle Werte ausgedacht, IPs aus 192.0.2.0/24.
    Firebird 5 schreibt "Trigger <Name> FOR <Tabelle> (<Zeitpunkt> <Aktion>):" auf eine eigene Zeile,
    Firebird 4 "<TAB><Name> FOR <Tabelle> (<Zeitpunkt> <Aktion>) " direkt unter die Transaktionszeile.
#>

BeforeAll {
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Pseudo = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Pseudonymize-FirebirdTrace.ps1')
    $script:R5 = @(& $script:Parser -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures', 'trace_fb5_routines.log')) 6>$null)
    $script:R4 = @(& $script:Parser -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures', 'trace_fb4_routines.log')) 6>$null)
    $script:NewFields = @('RoutineType', 'RoutineName', 'TriggerTable', 'TriggerTime', 'TriggerEvent', 'ConnectionDurationMs')

    function Get-Routine([object[]]$Events, [string]$Field, [string]$Value) { @($Events | Where-Object { $_.$Field -eq $Value })[0] }
}

Describe 'Show-TraceStructure: Prozeduren und Funktionen (I12)' {
    It 'liefert einen Eintrag je Ereignisblock' {
        $script:R5.Count | Should -Be 10
        $script:R4.Count | Should -Be 6
    }

    It 'liest Name, Laufzeit, I/O und Parameter einer Prozedur (Firebird 5)' {
        $e = $script:R5[1]
        $e.Action | Should -BeExactly 'EXECUTE_PROCEDURE_FINISH'
        $e.RoutineType | Should -BeExactly 'Procedure'
        $e.RoutineName | Should -BeExactly 'CALC_ORDER_TOTAL'
        $e.DurationMs | Should -Be 150
        $e.Reads | Should -Be 12
        $e.Writes | Should -Be 1
        $e.Fetches | Should -Be 340
        $e.RecordsFetched | Should -Be 25
        $e.Params | Should -BeExactly 'param0 = integer, "4711"'
        $e.SqlPlan | Should -BeExactly 'PLAN (ORDER_LINE INDEX (FK_ORDER_LINE_ORDER))'
        $e.TableCounts[0].Index | Should -Be 25
        $e.TriggerTable | Should -BeNullOrEmpty
        $e.TriggerTime | Should -BeNullOrEmpty
        $e.TriggerEvent | Should -BeNullOrEmpty
    }

    It 'liest eine Prozedur im Format von Firebird 4 (Parameter direkt unter dem Namen)' {
        $e = $script:R4[1]
        $e.RoutineType | Should -BeExactly 'Procedure'
        $e.RoutineName | Should -BeExactly 'CALC_ORDER_TOTAL'
        $e.Params | Should -BeExactly 'param0 = integer, "4712"'
        $e.RecordsFetched | Should -Be 30
        $e.DurationMs | Should -Be 160
        $e.Reads | Should -Be 14
    }

    It 'liest Funktionen mit demselben Feld (Firebird 4 und 5)' {
        foreach ($e in @($script:R5[2], $script:R4[2])) {
            $e.Action | Should -BeExactly 'EXECUTE_FUNCTION_FINISH'
            $e.RoutineType | Should -BeExactly 'Function'
            $e.RoutineName | Should -BeExactly 'CALC_TAX'
        }
        $script:R5[2].DurationMs | Should -Be 2
        $script:R4[2].Fetches | Should -Be 5
    }
}

Describe 'Show-TraceStructure: Trigger (I12)' {
    It 'liest Name, Tabelle, Zeitpunkt, Aktion, Laufzeit und I/O (Firebird 5)' {
        $e = Get-Routine $script:R5 'RoutineName' 'TRG_ORDER_LINE_BI'
        $e.RoutineType | Should -BeExactly 'Trigger'
        $e.TriggerTable | Should -BeExactly 'ORDER_LINE'
        $e.TriggerTime | Should -BeExactly 'BEFORE'
        $e.TriggerEvent | Should -BeExactly 'INSERT'
        $e.DurationMs | Should -Be 120
        $e.Reads | Should -Be 3
        $e.Marks | Should -Be 1
        @($e.TableCounts | ForEach-Object Table) | Should -Be @('ITEM', 'ORDER_LINE')
        $e.SqlPlan | Should -BeExactly 'PLAN (ITEM INDEX (PK_ITEM))'
    }

    It 'liest Datenbank-Trigger ohne Tabelle (ON CONNECT)' {
        $e = Get-Routine $script:R5 'RoutineName' 'TRG_LOG_CONNECT'
        $e.TriggerTable | Should -BeNullOrEmpty
        $e.TriggerTime | Should -BeExactly 'ON'
        $e.TriggerEvent | Should -BeExactly 'CONNECT'
        $e.DurationMs | Should -Be 105
    }

    It 'liest fehlgeschlagene Trigger (FAILED ...) mit AFTER UPDATE' {
        $e = Get-Routine $script:R5 'Action' 'FAILED EXECUTE_TRIGGER_FINISH'
        $e.RoutineName | Should -BeExactly 'TRG_STOCK_AU'
        $e.TriggerTable | Should -BeExactly 'STOCK'
        $e.TriggerTime | Should -BeExactly 'AFTER'
        $e.TriggerEvent | Should -BeExactly 'UPDATE'
    }

    It 'laesst den Namen leer, wenn Firebird keinen kennt (Firebird 5 ohne Namen, Firebird 4 mit Platzhalter unknown)' {
        $e5 = Get-Routine $script:R5 'TriggerEvent' 'TRANSACTION_COMMIT'
        $e5.RoutineType | Should -BeExactly 'Trigger'
        $e5.RoutineName | Should -BeNullOrEmpty
        $e5.TriggerTime | Should -BeExactly 'ON'
        $e4 = $script:R4[4]
        $e4.RoutineType | Should -BeExactly 'Trigger'
        $e4.RoutineName | Should -BeNullOrEmpty
        $e4.TriggerEvent | Should -BeExactly 'CONNECT'
    }

    It 'liest die Trigger-Zeile von Firebird 4 (Tabulator, Leerzeichen am Ende)' {
        $e = $script:R4[3]
        $e.RoutineType | Should -BeExactly 'Trigger'
        $e.RoutineName | Should -BeExactly 'TRG_STOCK_AU'
        $e.TriggerTable | Should -BeExactly 'STOCK'
        $e.TriggerTime | Should -BeExactly 'AFTER'
        $e.TriggerEvent | Should -BeExactly 'UPDATE'
        $e.DurationMs | Should -Be 110
        $e.TableCounts[0].Update | Should -Be 1
        $e.TransactionID | Should -Be '702'
    }

    It 'laesst die neuen Felder bei Statements, Transaktionen und Verbindungen leer' {
        $stmt = Get-Routine $script:R5 'Action' 'EXECUTE_STATEMENT_FINISH'
        $stmt.SqlStatement | Should -BeExactly 'SELECT ID FROM ITEM'
        foreach ($e in @($stmt, $script:R5[0])) {
            foreach ($f in $script:NewFields) { $e.$f | Should -BeNullOrEmpty -Because $f }
        }
    }
}

Describe 'Show-TraceStructure: Verbindungsdauer (I12)' {
    It 'berechnet die Dauer ATTACH_DATABASE bis DETACH_DATABASE in ms' {
        $d = @($script:R5 | Where-Object Action -eq 'DETACH_DATABASE')
        $d[0].AttachID | Should -Be '31'
        $d[0].ConnectionDurationMs | Should -Be 301500
        $d[0].ConnectionDurationMs | Should -BeOfType [long]
        (@($script:R4 | Where-Object Action -eq 'DETACH_DATABASE')[0]).ConnectionDurationMs | Should -Be 5000
    }

    It 'laesst die Dauer leer, wenn die Verbindung vor dem Trace begann' {
        $d = @($script:R5 | Where-Object Action -eq 'DETACH_DATABASE')
        $d[1].AttachID | Should -Be '32'
        $d[1].ConnectionDurationMs | Should -BeNullOrEmpty
    }

    It 'trennt gleiche Verbindungsnummern verschiedener Datenbanken (auch ab CREATE_DATABASE)' {
        $f = Join-Path $TestDrive 'two_db.log'
        $conn = { param($db) "`tC:\DATA\$db (ATT_5, APPUSER:NONE, UTF8, TCPv4:192.0.2.70/50800)" }
        @(
            '2026-11-08T14:00:00.0000 (4321:000001A2B3C4D5E0) CREATE_DATABASE', (& $conn 'A.FDB'), ''
            '2026-11-08T14:00:10.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE', (& $conn 'B.FDB'), ''
            '2026-11-08T14:00:12.5000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', (& $conn 'B.FDB'), ''
            '2026-11-08T14:01:00.0000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', (& $conn 'A.FDB'), ''
        ) | Set-Content -LiteralPath $f -Encoding UTF8
        $r = @(& $script:Parser -Path $f 6>$null)
        $r[2].ConnectionDurationMs | Should -Be 2500
        $r[3].ConnectionDurationMs | Should -Be 60000
    }

    It 'zaehlt eine Verbindung nur einmal (zweites DETACH ohne neues ATTACH bleibt leer)' {
        $f = Join-Path $TestDrive 'twice.log'
        $c = "`tC:\DATA\A.FDB (ATT_6, APPUSER:NONE, UTF8, TCPv4:192.0.2.71/50801)"
        @(
            '2026-11-08T15:00:00.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE', $c, ''
            '2026-11-08T15:00:01.0000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', $c, ''
            '2026-11-08T15:00:02.0000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', $c, ''
        ) | Set-Content -LiteralPath $f -Encoding UTF8
        $r = @(& $script:Parser -Path $f 6>$null)
        $r[1].ConnectionDurationMs | Should -Be 1000
        $r[2].ConnectionDurationMs | Should -BeNullOrEmpty
    }

    It 'haengt die neuen Felder hinten an den Ausgabe-Vertrag an (nach TableCounts)' {
        $names = @($script:R5[0].PSObject.Properties.Name)
        $names[-6..-1] | Should -Be $script:NewFields
        $names.IndexOf('TableCounts') | Should -Be ($names.Count - 7)
    }
}

Describe 'Pseudonymize-FirebirdTrace: Felder aus I12' {
    It 'laesst Prozedur-, Trigger- und Tabellennamen im Klartext, Benutzer wird pseudonymisiert' {
        $in = Get-Routine $script:R5 'RoutineName' 'TRG_ORDER_LINE_BI'
        $out = $in | & $script:Pseudo 3>$null 6>$null
        $out.User | Should -Not -Be $in.User
        foreach ($f in $script:NewFields) { $out.$f | Should -Be $in.$f -Because $f }
        $d = @($script:R5 | Where-Object Action -eq 'DETACH_DATABASE')[0] | & $script:Pseudo 3>$null 6>$null
        $d.ConnectionDurationMs | Should -Be 301500
    }
}
