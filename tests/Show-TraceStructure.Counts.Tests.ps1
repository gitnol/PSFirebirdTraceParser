#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer RecordsFetched, Transaktionsoptionen als Felder und die Tabellenstatistik je Tabelle (I11).
    Fixture: tests/fixtures/trace_fb5_counts.log - synthetisch, Format nach Firebird 5
    (src/utilities/ntrace/TracePluginImpl.cpp: "%d records fetched", Transaktionszeile, appendTableCounts),
    alle Werte ausgedacht. Die Namensspalte der Tabellenstatistik ist max(32, laengster Name in Bytes) breit
    (Firebird 4/5), bei Firebird 3 fest 31; jede Zahl steht rechtsbuendig in 10 Zeichen, 0 als Leerzeichen.
#>

BeforeAll {
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Pseudo = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Pseudonymize-FirebirdTrace.ps1')
    $script:Fixture = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures', 'trace_fb5_counts.log')
    $script:R = @(& $script:Parser -Path $script:Fixture 6>$null)
    $script:Umlaut = 'LAGER_' + [char]0x00DC + 'BERSICHT_GR' + [char]0x00D6 + 'SSE'   # 2 Umlaute: 2 Bytes mehr als Zeichen
    $script:Cols = @('Natural', 'Index', 'Update', 'Insert', 'Delete', 'Backout', 'Purge', 'Expunge')

    function Get-Row([object]$TraceEvent, [string]$Table) { @($TraceEvent.TableCounts | Where-Object Table -eq $Table)[0] }
    function Get-Value([object]$Row) { @($script:Cols | ForEach-Object { $Row.$_ }) }
}

Describe 'Show-TraceStructure: RecordsFetched (I11)' {
    It 'liefert einen Eintrag je Ereignisblock' {
        $script:R.Count | Should -Be 5
    }

    It 'liest "N records fetched" getrennt von den Seiten-Fetches' {
        $script:R[0].RecordsFetched | Should -Be 1234
        $script:R[0].Fetches | Should -Be 25000
        $script:R[0].RecordsFetched | Should -BeOfType [long]
    }

    It 'liest Werte ueber 2^31' {
        $script:R[4].RecordsFetched | Should -Be 3000000000
    }

    It 'ueberspringt den Text im SQL und liest die Zeile mit der Zahl' {
        $f = Join-Path $TestDrive 'rf_in_sql.log'
        @(
            '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH'
            "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)"
            ''
            'Statement 1:'
            ('-' * 79)
            "SELECT 'max 5 records fetched' FROM T"
            ('^' * 79)
            '17 records fetched'
            '      2 ms, 4 fetch(es)'
            ''
        ) -join "`n" | Set-Content -Path $f -NoNewline -Encoding utf8
        @(& $script:Parser -Path $f 6>$null)[0].RecordsFetched | Should -Be 17
    }

    It 'liefert 0 bei "0 records fetched" und ohne die Zeile (wie die anderen Zaehler)' {
        $script:R[1].RecordsFetched | Should -Be 0
        $script:R[2].RecordsFetched | Should -Be 0
        $script:R[3].RecordsFetched | Should -Be 0
        $script:R[2].RecordsFetched | Should -BeOfType [long]
    }
}

Describe 'Show-TraceStructure: Transaktionsoptionen als Felder (I11)' {
    It 'zerlegt READ_COMMITTED | REC_VERSION | WAIT 10 | READ_WRITE' {
        $e = $script:R[0]
        $e.TxIsolation | Should -BeExactly 'READ_COMMITTED'
        $e.TxReadMode | Should -BeExactly 'REC_VERSION'
        $e.TxWaitMode | Should -BeExactly 'WAIT'
        $e.TxLockTimeout | Should -Be 10
        $e.TxAccessMode | Should -BeExactly 'READ_WRITE'
    }

    It 'zerlegt CONSISTENCY | NOWAIT | READ_ONLY (ohne Lesemodus und Wartezeit)' {
        $e = $script:R[1]
        $e.TxIsolation | Should -BeExactly 'CONSISTENCY'
        $e.TxReadMode | Should -BeNullOrEmpty
        $e.TxWaitMode | Should -BeExactly 'NOWAIT'
        $e.TxLockTimeout | Should -BeNullOrEmpty
        $e.TxAccessMode | Should -BeExactly 'READ_ONLY'
    }

    It 'zerlegt READ_CONSISTENCY mit unbegrenztem WAIT und NO_REC_VERSION mit WAIT 5' {
        $script:R[2].TxReadMode | Should -BeExactly 'READ_CONSISTENCY'
        $script:R[2].TxWaitMode | Should -BeExactly 'WAIT'
        $script:R[2].TxLockTimeout | Should -BeNullOrEmpty
        $script:R[3].Action | Should -Be 'START_TRANSACTION'
        $script:R[3].TxReadMode | Should -BeExactly 'NO_REC_VERSION'
        $script:R[3].TxLockTimeout | Should -Be 5
        $script:R[3].TxLockTimeout | Should -BeOfType [int]
        $script:R[4].TxIsolation | Should -BeExactly 'CONCURRENCY'
    }

    It 'laesst TransactionOptions als Text unveraendert' {
        $script:R[0].TransactionOptions | Should -BeExactly 'READ_COMMITTED | REC_VERSION | WAIT 10 | READ_WRITE'
    }

    It 'laesst die Felder ohne Transaktionszeile leer' {
        $f = Join-Path $TestDrive 'attach.log'
        @(
            '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE'
            "`tC:\DATA\SAMPLE.FDB (ATT_5, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
            ''
        ) -join "`n" | Set-Content -Path $f -NoNewline -Encoding utf8
        $e = @(& $script:Parser -Path $f 6>$null)[0]
        $e.TxIsolation | Should -BeNullOrEmpty
        $e.TxWaitMode | Should -BeNullOrEmpty
        $e.TxAccessMode | Should -BeNullOrEmpty
        $e.TableCounts | Should -BeNullOrEmpty
    }
}

Describe 'Show-TraceStructure: Tabellenstatistik je Tabelle (I11)' {
    It 'liefert ein Objekt je Tabellenzeile in der Reihenfolge des Logs' {
        @($script:R[0].TableCounts).Count | Should -Be 3
        @($script:R[0].TableCounts | ForEach-Object Table) |
            Should -Be @('WAREHOUSE_STOCK_MOVEMENT_HISTORY_ARCHIVE', 'ITEM', $script:Umlaut)
    }

    It 'liest alle acht Spalten bei breiter Namensspalte (Firebird 4/5, langer Name)' {
        Get-Value (Get-Row $script:R[0] 'WAREHOUSE_STOCK_MOVEMENT_HISTORY_ARCHIVE') | Should -Be @(0, 5000, 0, 0, 0, 2, 3, 4)
        Get-Value (Get-Row $script:R[0] 'ITEM') | Should -Be @(120, 0, 7, 8, 9, 0, 0, 0)
        (Get-Row $script:R[0] 'ITEM').Natural | Should -BeOfType [long]
    }

    It 'liest Namen mit Umlaut richtig (Firebird fuellt die Spalte nach Bytes, nicht nach Zeichen)' {
        Get-Value (Get-Row $script:R[0] $script:Umlaut) | Should -Be @(123456789, 22, 0, 0, 0, 0, 0, 0)
    }

    It 'liest den Firebird-3-Kopf und einen Namen, der die Spalte genau fuellt, mit zehnstelliger Zahl' {
        $row = Get-Row $script:R[4] 'ORDER_POSITION_HISTORY_ARCHIVES'
        $row.Natural | Should -Be 3000000000
        $row.Index | Should -Be 0
    }

    It 'verschiebt alle Zahlen, wenn ein Name laenger ist als die Namensspalte' {
        $f = Join-Path $TestDrive 'overlong.log'
        $name = 'A_VERY_LONG_TABLE_NAME_BEYOND_THE_HEADER_COLUMN'
        @(
            '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH'
            "`tC:\DATA\SAMPLE.FDB (ATT_5, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
            "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)"
            ''
            'Statement 1:'
            ('-' * 79)
            'SELECT 1 FROM T'
            ('^' * 79)
            '1 records fetched'
            '      2 ms, 4 fetch(es)'
            ''
            'Table                             Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge'
            ('*' * 111)
            ($name + (' ' * 10) + '{0,10}{1,10}' -f 7, 8)
            ('SHORT'.PadRight(31) + '{0,10}' -f 9)
            ''
        ) -join "`n" | Set-Content -Path $f -NoNewline -Encoding utf8
        $e = @(& $script:Parser -Path $f 6>$null)[0]
        Get-Value (Get-Row $e $name) | Should -Be @(0, 7, 8, 0, 0, 0, 0, 0)
        Get-Value (Get-Row $e 'SHORT') | Should -Be @(9, 0, 0, 0, 0, 0, 0, 0)
    }

    It 'ueberspringt eine unlesbare Zeile und liest die uebrigen' {
        $f = Join-Path $TestDrive 'broken_row.log'
        @(
            '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH'
            "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)"
            ''
            '      2 ms, 4 fetch(es)'
            ''
            'Table                             Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge'
            ('*' * 111)
            ('BROKEN'.PadRight(31) + '      n/a')
            ('GOOD'.PadRight(31) + '{0,10}' -f 3)
            ''
        ) -join "`n" | Set-Content -Path $f -NoNewline -Encoding utf8
        $e = @(& $script:Parser -Path $f 6>$null)[0]
        @($e.TableCounts | ForEach-Object Table) | Should -Be @('GOOD')
        $e.TableCounts[0].Natural | Should -Be 3
    }

    It 'laesst TableStats als ungetrimmten Text unveraendert' {
        $script:R[0].TableStats | Should -Match '(?m)^ITEM {43}120'
    }

    It 'liefert keine Tabellenobjekte ohne Tabellenstatistik' {
        $script:R[1].TableCounts | Should -BeNullOrEmpty
    }

    It 'haengt die neuen Felder hinten an den Ausgabe-Vertrag an (nach SweepNext)' {
        $names = @($script:R[0].PSObject.Properties.Name)
        $names[-7..-1] | Should -Be @('RecordsFetched', 'TxIsolation', 'TxReadMode', 'TxWaitMode', 'TxLockTimeout', 'TxAccessMode', 'TableCounts')
        $names.IndexOf('SweepNext') | Should -Be ($names.Count - 8)
    }
}

Describe 'Pseudonymize-FirebirdTrace: Felder aus I11' {
    BeforeAll {
        # Eingabe im Test gebaut (fiktive Werte), Form wie die Ausgabe des Parsers
        $script:In = [pscustomobject]@{
            User = 'APPUSER:NONE'; ClientIP = '192.0.2.40'; ProtocolInfo = 'TCPv4:192.0.2.40/50500'
            ApplicationPath = $null; Params = $null; SqlStatement = 'SELECT ID FROM ITEM WHERE NAME = ''X'''
            TableStats = "Table                             Natural`n***`nITEM                                 120"
            RecordsFetched = [long]1234; TxIsolation = 'READ_COMMITTED'; TxReadMode = 'REC_VERSION'; TxWaitMode = 'WAIT'
            TxLockTimeout = 10; TxAccessMode = 'READ_WRITE'
            TableCounts = @(
                [pscustomobject]@{ Table = 'ITEM'; Natural = [long]120; Index = [long]0; Update = [long]7; Insert = [long]8; Delete = [long]9; Backout = [long]0; Purge = [long]0; Expunge = [long]0 }
                [pscustomobject]@{ Table = 'STOCK'; Natural = [long]0; Index = [long]5; Update = [long]0; Insert = [long]0; Delete = [long]0; Backout = [long]0; Purge = [long]0; Expunge = [long]0 }
            )
        }
        $script:Before = ($script:In.TableCounts | ConvertTo-Json -Compress)
        $script:Out = $script:In | & $script:Pseudo -SensitiveKeywords 'ITEM' -RedactLiterals 3>$null 6>$null
    }

    It 'laesst Tabellennamen und Zaehler im Klartext (wie TableStats)' {
        @($script:Out.TableCounts | ForEach-Object Table) | Should -Be @($script:In.TableCounts | ForEach-Object Table)
        (Get-Row $script:Out 'ITEM').Natural | Should -Be 120
        $script:Out.TableStats | Should -BeExactly $script:In.TableStats
        $script:Out.SqlStatement | Should -Match '<REDACTED_CLAUSE:'
        $script:Out.RecordsFetched | Should -Be 1234
        $script:Out.TxIsolation | Should -BeExactly 'READ_COMMITTED'
        $script:Out.TxLockTimeout | Should -Be 10
    }

    It 'gibt eigene Tabellenobjekte aus, das Eingabeobjekt bleibt unveraendert' {
        [object]::ReferenceEquals($script:Out.TableCounts[0], $script:In.TableCounts[0]) | Should -BeFalse
        @($script:Out.TableCounts).Count | Should -Be 2
        $script:Out.TableCounts[0].Natural = 999
        ($script:In.TableCounts | ConvertTo-Json -Compress) | Should -BeExactly $script:Before
    }
}
