#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer Show-TraceStructure.ps1.
    Fixture: tests/fixtures/trace_fb5_windows.log - synthetisch, Format nach Firebird 5.0.4
    (src/utilities/ntrace/TracePluginImpl.cpp), alle Werte ausgedacht.
#>

BeforeAll {
    $script:Parser  = Join-Path $PSScriptRoot '..' 'Show-TraceStructure.ps1'
    $script:Fixture = Join-Path $PSScriptRoot 'fixtures' 'trace_fb5_windows.log'

    function Invoke-Parser([string]$Path) {
        # Statusausgaben (Write-Host) unterdruecken, nur die Objekte zurueckgeben
        & $script:Parser -Path $Path 6>$null
    }
}

Describe 'Show-TraceStructure: Firebird-5-Log (Windows-Format)' {
    BeforeAll { $script:R = @(Invoke-Parser $script:Fixture) }

    It 'liefert einen Eintrag je Ereignisblock' {
        $script:R.Count | Should -Be 7
    }

    It 'liest Zeitstempel, Prozess-ID und Adresse aus der Kopfzeile' {
        $script:R[0].Timestamp | Should -Be '2026-11-07T10:00:00.0010'
        $script:R[0].ProcessID | Should -Be '4321'
        $script:R[0].SessionID | Should -Be '000001A2B3C4D5E0'
    }

    It 'liest die Verbindung (ATT, Benutzer, IP, Port, Anwendung)' {
        $e = $script:R[1]
        $e.AttachID        | Should -Be '12'
        $e.User            | Should -Be 'APPUSER:NONE'
        $e.ClientIP        | Should -Be '192.0.2.10'
        $e.ClientPort      | Should -Be '50123'
        $e.ApplicationPath | Should -Be 'C:\Program Files\SampleApp\app.exe'
        $e.ApplicationPID  | Should -Be '5678'
    }

    It 'liest Transaktion und Wurzel-Transaktion (INIT)' {
        $script:R[1].TransactionID      | Should -Be '345'
        $script:R[1].RootTxID           | Should -Be '340'
        $script:R[1].TransactionOptions | Should -Be 'CONCURRENCY | WAIT | READ_WRITE'
        $script:R[2].RootTxID           | Should -Be '350'
    }

    It 'liest SQL, Plan und Parameter' {
        $script:R[1].SqlStatement | Should -Be 'SELECT ID, NAME FROM CUSTOMER WHERE ID = ?'
        $script:R[1].SqlPlan      | Should -Be 'PLAN (CUSTOMER INDEX (PK_CUSTOMER))'
        $script:R[1].Params       | Should -Be 'param0 = integer, "42"'
    }

    It 'liest Laufzeit und I/O-Zaehler' {
        $e = $script:R[2]
        $e.DurationMs | Should -Be 850
        $e.Reads      | Should -Be 1200
        $e.Writes     | Should -Be 2
        $e.Fetches    | Should -Be 98000
        $e.Marks      | Should -Be 4
    }

    It 'liest die Tabellenstatistik als Textblock' {
        $script:R[2].TableStats | Should -Match 'ORDERS\s+52000'
    }
}

Describe 'Show-TraceStructure: Kopfzeile plattformneutral (I9)' {
    # Firebird schreibt die Adresse mit printf("%p"): Windows (MSVC) "000001A2B3C4D5E0",
    # Linux (glibc) "0x7f3a1c2b4d10". Beide muessen erkannt werden.
    BeforeAll {
        $linux = Join-Path $TestDrive 'trace_linux.log'
        (Get-Content $script:Fixture -Raw).Replace('(4321:000001A2B3C4D5E0)', '(4321:0x7f3a1c2b4d10)') |
            Set-Content -Path $linux -NoNewline -Encoding utf8
        $script:L = @(Invoke-Parser $linux)
    }

    It 'erkennt jede Linux-Kopfzeile mit Ereignis und Zeitstempel' {
        $script:L.Count | Should -Be 7
        @($script:L | Where-Object { [string]::IsNullOrEmpty($_.Action) }).Count | Should -Be 0
        $script:L[1].Action    | Should -Be 'EXECUTE_STATEMENT_FINISH'
        $script:L[1].Timestamp | Should -Be '2026-11-07T10:00:01.1230'
    }

    It 'uebernimmt die Linux-Adresse unveraendert' {
        $script:L[0].SessionID | Should -Be '0x7f3a1c2b4d10'
    }
}

Describe 'Show-TraceStructure: Windows-Zeilenenden (CRLF)' {
    BeforeAll {
        $crlf = Join-Path $TestDrive 'trace_crlf.log'
        ((Get-Content $script:Fixture -Raw) -replace "`r?`n", "`r`n") | Set-Content -Path $crlf -NoNewline -Encoding utf8
        $script:C = @(Invoke-Parser $crlf)
    }

    It 'liefert dieselben Werte ohne Wagenruecklauf in den Feldern' {
        $script:C.Count | Should -Be 7
        $script:C[1].SqlStatement | Should -Be 'SELECT ID, NAME FROM CUSTOMER WHERE ID = ?'
        $script:C[1].SqlPlan      | Should -Be 'PLAN (CUSTOMER INDEX (PK_CUSTOMER))'
        $script:C[2].DurationMs   | Should -Be 850
        $script:C[1].ApplicationPID | Should -Be '5678'
        $script:C[2].TableStats   | Should -Not -Match "`r"   # seit I6: keine Wagenruecklaeufe in ungetrimmten Bloecken
    }
}

Describe 'Show-TraceStructure: Verbindungszeile in allen Formen (K3)' {
    BeforeAll {
        function Get-Conn([string]$ConnLine) {
            $p = Join-Path $TestDrive ("conn_{0}.log" -f [guid]::NewGuid().ToString('N'))
            @(
                '2026-11-07T11:00:00.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE'
                "`t$ConnLine"
                ''
            ) -join "`n" | Set-Content -Path $p -NoNewline -Encoding utf8
            @(Invoke-Parser $p)[0]
        }
    }

    It 'liest interne Verbindungen (Protokoll internal, z. B. Sicherheitsdatenbank)' {
        # Form aus einem echten Firebird-5.0.4-Log (Werte ersetzt)
        $e = Get-Conn 'C:\Program Files\Firebird\Firebird_5_0\SECURITY5.FDB (ATT_100, SYSDBA:NONE, NONE, <internal>)'
        $e.DatabasePath | Should -Be 'C:\Program Files\Firebird\Firebird_5_0\SECURITY5.FDB'
        $e.AttachID     | Should -Be '100'
        $e.User         | Should -Be 'SYSDBA:NONE'
        $e.ProtocolInfo | Should -Be '<internal>'
        $e.ClientIP     | Should -BeNullOrEmpty
    }

    It 'liest Benutzer mit Rolle ungleich NONE' {
        $e = Get-Conn 'C:\DATA\SAMPLE.FDB (ATT_5, TRACEUSER:TRACER, UTF8, TCPv4:192.0.2.10/50123)'
        $e.User     | Should -Be 'TRACEUSER:TRACER'
        $e.ClientIP | Should -Be '192.0.2.10'
    }

    It 'liest Datenbankpfade mit kleiner Endung und Linux-Pfad' {
        $e = Get-Conn '/var/lib/firebird/data/sample.fdb (ATT_6, APPUSER:NONE, UTF8, TCPv6:2001:db8::10/50123)'
        $e.DatabasePath | Should -Be '/var/lib/firebird/data/sample.fdb'
        $e.ClientIP     | Should -Be '2001:db8::10'
        $e.ClientPort   | Should -Be '50123'
    }

    It 'liest lokale Protokolle ohne Port' {
        $e = Get-Conn 'C:\DATA\SAMPLE.FDB (ATT_7, APPUSER:NONE, UTF8, XNET:WORKSTATION01)'
        $e.AttachID     | Should -Be '7'
        $e.ProtocolInfo | Should -Be 'XNET:WORKSTATION01'
        $e.ClientIP     | Should -Be 'WORKSTATION01'
        $e.ClientPort   | Should -BeNullOrEmpty
    }
}

Describe 'Show-TraceStructure: grosse Werte und Ausgabe (I6)' {
    It 'liest Zaehler ueber 2^31 ohne Fehler' {
        $big = Join-Path $TestDrive 'big_counters.log'
        @(
            '2026-11-07T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH'
            "`tC:\DATA\SAMPLE.FDB (ATT_12, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
            "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)"
            ''
            'Statement 1:'
            ('-' * 79)
            'SELECT COUNT(*) FROM HUGE'
            ('^' * 79)
            ' 3600000 ms, 2500000000 read(s), 2200000000 write(s), 9000000000 fetch(es), 3000000000 mark(s)'
            ''
        ) -join "`n" | Set-Content -Path $big -NoNewline -Encoding utf8
        $e = @(Invoke-Parser $big)[0]
        $e.DurationMs | Should -Be 3600000
        $e.Reads      | Should -Be 2500000000
        $e.Writes     | Should -Be 2200000000
        $e.Fetches    | Should -Be 9000000000
        $e.Marks      | Should -Be 3000000000
    }

    It 'gibt Eintraege einzeln in die Pipeline (nicht als eine Liste)' {
        $r = & $script:Parser -Path $script:Fixture 6>$null | Select-Object -First 2
        @($r).Count | Should -Be 2
        $r[0].Action | Should -Be 'ATTACH_DATABASE'
    }

    It 'schreibt keine Statusmeldungen auf den Host-Kanal' {
        $info = & $script:Parser -Path $script:Fixture 6>&1 | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }
        @($info).Count | Should -Be 0
    }
}

Describe 'Show-TraceStructure: Datei fehlt' {
    It 'meldet einen Fehler und liefert nichts' {
        $r = & $script:Parser -Path (Join-Path $TestDrive 'gibt-es-nicht.log') 6>$null 2>$null
        $r | Should -BeNullOrEmpty
    }
}

Describe 'Show-TraceStructure: Fehler-Ereignisse (I10)' {
    # Format nach Firebird 5.0.4: Kopfzeile "ERROR AT <Komponente>", danach Verbindung, danach
    # Fehlerzeilen "%9lu : <Text>" (TraceObjects.cpp, TraceStatusVectorImpl::getText).
    BeforeAll { $script:R = @(Invoke-Parser $script:Fixture) }

    It 'liest ERROR AT mit Komponente, Fehlercodes und Texten' {
        $e = $script:R[3]
        $e.Action        | Should -Be 'ERROR'
        $e.ErrorSource   | Should -Be 'JStatement::execute'
        $e.ErrorCodes    | Should -Be '335544336, 335544451, 335544878'
        $e.ErrorMessages | Should -Be 'deadlock | update conflicts with concurrent update | concurrent transaction number is 349'
        $e.User          | Should -Be 'REPORTUSER:NONE'
    }

    It 'liest Schluesselverletzungen mit allen Zeilen' {
        $e = $script:R[5]
        $e.ErrorCodes    | Should -Be '335544665, 335545072'
        $e.ErrorMessages | Should -Match 'Problematic key value is \("ID" = 42\)'
    }

    It 'behaelt bei FAILED den vollen Ereignisnamen und liest das Statement' {
        $e = $script:R[4]
        $e.Action       | Should -Be 'FAILED EXECUTE_STATEMENT_FINISH'
        $e.SqlStatement | Should -Be 'UPDATE ORDERS SET STATUS = ? WHERE ID = ?'
        $e.Params       | Should -Match 'param1 = integer, "77"'
        $e.DurationMs   | Should -Be 5
        $e.ErrorCodes   | Should -BeNullOrEmpty
    }

    It 'laesst Fehlerfelder bei normalen Ereignissen leer' {
        $script:R[1].ErrorSource   | Should -BeNullOrEmpty
        $script:R[1].ErrorCodes    | Should -BeNullOrEmpty
        $script:R[1].ErrorMessages | Should -BeNullOrEmpty
    }

    It 'liest SQL-Zeilen, die wie Fehlerzeilen aussehen, nicht als Fehler' {
        $sql = Join-Path $TestDrive 'statement_like_error.log'
        @(
            '2026-11-07T11:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH'
            "`tC:\DATA\SAMPLE.FDB (ATT_12, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
            "`t`t(TRA_1, CONCURRENCY | WAIT | READ_WRITE)"
            ''
            'Statement 1:'
            ('-' * 79)
            'SELECT CASE WHEN A = 1 THEN'
            '  335544336 : 1 END FROM T'
            ('^' * 79)
            '      3 ms, 1 fetch(es)'
            ''
        ) -join "`n" | Set-Content -Path $sql -NoNewline -Encoding utf8
        $s = @(Invoke-Parser $sql)
        $s[0].ErrorCodes    | Should -BeNullOrEmpty
        $s[0].ErrorMessages | Should -BeNullOrEmpty
    }

    It 'liest WARNING AT wie ERROR AT' {
        $warn = Join-Path $TestDrive 'warning.log'
        @(
            '2026-11-07T11:00:00.0000 (4321:000001A2B3C4D5E0) WARNING AT JAttachment::execute'
            "`tC:\DATA\SAMPLE.FDB (ATT_12, APPUSER:NONE, UTF8, TCPv4:192.0.2.10/50123)"
            '335544808 : Arithmetic overflow or division by zero has occurred.'
            ''
        ) -join "`n" | Set-Content -Path $warn -NoNewline -Encoding utf8
        $w = @(Invoke-Parser $warn)
        $w[0].Action      | Should -Be 'WARNING'
        $w[0].ErrorSource | Should -Be 'JAttachment::execute'
        $w[0].ErrorCodes  | Should -Be '335544808'
    }
}
