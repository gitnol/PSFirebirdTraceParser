#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Paritaetstest (I17, ADR-003): Show-TraceStructure.ps1 (PowerShell-Parser, Orakel) und ConvertFrom-FirebirdTrace
    (C#-Parser) laufen ueber jedes Fixture und ueber erzeugte Grenzfaelle; jedes Feld jedes Objekts muss gleich sein
    (Name, Reihenfolge, Typ, Wert, $null gegen leer, TableCounts je Zeile), seit I18 auch Warnungen und
    Verbose-Meldungen. Jeder Unterschied ist rot - das ist die
    Ratsche bis zur Umstellung auf C#. Nur PowerShell 7 (Owner: Prioritaet PowerShell 7); fehlt die gebaute DLL,
    ist der Test rot, nicht uebersprungen. Werte ausgedacht, IPs aus 192.0.2.0/24 und 2001:db8::/32.
#>

BeforeDiscovery {
    $script:FixtureNames = @(Get-ChildItem -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures')) -Filter '*.log' | ForEach-Object Name)
    $conn = "`tC:\DATA\SAMPLE.FDB (ATT_5, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
    $app = "`tC:\Program Files\SampleApp\app.exe:5678"
    $head = 'Table                             Natural     Index    Update    Insert    Delete   Backout     Purge   Expunge'
    # Generated inputs for fields that the fixtures do not vary enough (name -> lines)
    $script:Cases = @(
        @{ Name = 'records_fetched_in_sql'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)", ''
                'Statement 1:', ('-' * 79), "SELECT 'max 5 records fetched' FROM T", ('^' * 79), '17 records fetched'
                '      2 ms, 4 fetch(es)', '')
        }
        @{ Name = 'table_overlong_broken_and_odd_cells'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)", ''
                'Statement 1:', ('-' * 79), 'SELECT 1 FROM T', ('^' * 79), '1 records fetched', '      2 ms, 4 fetch(es)', ''
                $head, ('*' * 111)
                ('A_VERY_LONG_TABLE_NAME_BEYOND_THE_HEADER_COLUMN' + (' ' * 10) + '{0,10}{1,10}' -f 7, 8)
                ('SHORT'.PadRight(31) + '{0,10}' -f 9)
                ('BROKEN'.PadRight(31) + '      n/a')
                ('EXPONENT'.PadRight(31) + '       1e3')
                ('HEX'.PadRight(31) + '       x1F')
                ('BIG'.PadRight(31) + '3000000000')
                ('ÄÖÜ_TABELLE'.PadRight(31) + '{0,10}' -f 4)
                ('TABLE_WITH_TEN_DIGITS_NAME_FILL1234567890'), '')
        }
        @{ Name = 'table_header_without_natural_column'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, ''
                'Table Natural', ('*' * 20), 'X 1', '')
        }
        @{ Name = 'table_only_unreadable_rows'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, '      2 ms', ''
                $head, ('*' * 111), ('BROKEN'.PadRight(31) + '      n/a'), ('BROKEN2'.PadRight(31) + '       ???'), '')
        }
        @{ Name = 'sql_followed_by_table_stats_and_error_blanks'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, ''
                'Statement 8:', ('-' * 79), 'SELECT 2 FROM T', $head, ('*' * 111), ('T'.PadRight(31) + '{0,10}' -f 1), ''
                '2026-11-08T11:00:01.0000 (4321:000001A2B3C4D5E0) ERROR AT JStatement::fetch', $conn
                '335544321 : arithmetic exception   ', '')
        }
        @{ Name = 'errors_and_warnings'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) ERROR AT JStatement::execute', $conn, $app
                '335544347 : validation error for column "T"."A", value "*** null ***"', '335544665 : violation of PRIMARY or UNIQUE KEY constraint', ''
                '2026-11-08T11:00:01.0000 (4321:000001A2B3C4D5E0) WARNING AT JAttachment::detach', $conn
                '        335544321 : arithmetic exception', ''
                '2026-11-08T11:00:02.0000 (4321:000001A2B3C4D5E0) ERROR AT JProvider::attachDatabase', ''
                '2026-11-08T11:00:03.0000 (4321:000001A2B3C4D5E0) FAILED EXECUTE_STATEMENT_FINISH', $conn, "`t`t(TRA_9, CONCURRENCY | NOWAIT | READ_ONLY)", ''
                'Statement 3:', ('-' * 79), 'UPDATE T SET A = 1', ('^' * 79), '0 records fetched', '      5 ms', '')
        }
        @{ Name = 'addresses_protocols_and_tx_options'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:0x7f3a1c2b4d10) ATTACH_DATABASE'
                "`t/data/sample.fdb (ATT_6, APPUSER:RDB`$ADMIN, NONE, TCPv6:2001:db8::10/50124)", "`t/usr/bin/isql:42", ''
                '2026-11-08T11:00:01.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE'
                "`tC:\DATA\SAMPLE.GDB (ATT_7, SYSDBA:NONE, NONE, XNET:HOST)", ''
                '2026-11-08T11:00:02.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE'
                "`tC:\DATA\SAMPLE.FDB (ATT_8, SYSDBA:NONE, NONE, <internal>)", ''
                '2026-11-08T11:00:03.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $conn, $app
                "`t`t(TRA_10, INIT_7, read_committed | rec_version | WAIT 30 | READ_WRITE)", ''
                '2026-11-08T11:00:04.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $conn
                "`t`t(TRA_11, <unknown> | WAIT x | READ_ONLY)", ''
                '2026-11-08T11:00:05.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, $app, "`t`t(TRA_12, CONCURRENCY | WAIT | READ_WRITE)", ''
                'Statement 5:', ('-' * 79), 'SELECT A', 'FROM T', 'WHERE B = ?', ('^' * 79)
                'PLAN (T NATURAL)', 'PLAN (U INDEX (I1))', 'param0 = varchar(10), "x"', 'param1 = integer, <NULL>', ''
                '4000000000 records fetched', '  99999 ms, 3000000000 read(s), 2 write(s), 4000000000 fetch(es), 5 mark(s)', '')
        }
        @{ Name = 'connection_duration_create_and_double_detach'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) CREATE_DATABASE', $conn, ''
                '2026-11-08T11:00:01.5000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', $conn, ''
                '2026-11-08T11:00:02.0000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', $conn, ''
                '2026-11-08T11:00:03.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE', "`tC:\DATA\OTHER.FDB (ATT_5, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)", ''
                '2026-11-08T11:00:04.0000 (4321:000001A2B3C4D5E0) DETACH_DATABASE', $conn, '')
        }
        @{ Name = 'sql_with_blanks_around'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, ''
                'Statement 7:', ('-' * 79), '   SELECT 1   ', '   FROM T   ', '      3 ms', '')
        }
        @{ Name = 'services_variants'; Lines = @(
                '2026-11-08T11:00:00.0000 (4321:0000000006B1C2D0) ATTACH_SERVICE'
                "`tservice_mgr, (Service 0000000007C3D4E0, BACKUPUSER, internal)", ''
                '2026-11-08T11:00:01.0000 (4321:0000000006B1C2D0) QUERY_SERVICE'
                "`tservice_mgr, (Service 0x7f0000001000, BACKUPUSER, TCPv4:192.0.2.30/50400, C:\Program Files\Firebird\gbak.exe:9012)"
                "`t""Restore Database""", ''
                '2026-11-08T11:00:02.0000 (4321:0000000006B1C2D0) DETACH_SERVICE'
                "`tservice_mgr, (Service 0000000007C3D4E0, BACKUPUSER, XNET:HOST)", '')
        }
    )
}

BeforeAll {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'TraceParity.ps1'))
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Fixtures = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
    $script:Dll = Get-TraceParserAssembly
    if ($PSVersionTable.PSEdition -eq 'Core' -and (Test-Path -LiteralPath $script:Dll)) { Import-Module -Name $script:Dll -Verbose:$false }

    function Compare-Engine([string]$Path) {
        # Differences between both parsers for one file: objects, warnings and verbose messages (since I18)
        Compare-TraceRun -Expected (Invoke-TraceEngine PowerShell $Path) -Actual (Invoke-TraceEngine CSharp $Path)
    }
}

Describe 'Paritaet PowerShell- und C#-Parser: alle Felder (I17)' -Skip:($PSVersionTable.PSEdition -ne 'Core') {
    It 'hat die gebaute DLL (sonst kein Vergleich)' {
        Test-Path -LiteralPath $script:Dll | Should -BeTrue -Because 'tools/Invoke-QualityGate.ps1 -Gate Build baut sie'
    }

    It 'liefert fuer das Fixture <_> dieselben Objekte' -ForEach $script:FixtureNames {
        Compare-Engine (Join-Path $script:Fixtures $_) | Should -BeNullOrEmpty
    }

    It 'liefert fuer den Grenzfall <Name> dieselben Objekte' -ForEach $script:Cases {
        $f = Join-Path $TestDrive "$Name.log"
        [System.IO.File]::WriteAllText($f, (($Lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
        Compare-Engine $f | Should -BeNullOrEmpty
    }
}
