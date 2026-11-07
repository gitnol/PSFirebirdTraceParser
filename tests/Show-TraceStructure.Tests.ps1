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
        $script:R.Count | Should -Be 6
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
        $script:L.Count | Should -Be 6
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
        $script:C.Count | Should -Be 6
        $script:C[1].SqlStatement | Should -Be 'SELECT ID, NAME FROM CUSTOMER WHERE ID = ?'
        $script:C[1].SqlPlan      | Should -Be 'PLAN (CUSTOMER INDEX (PK_CUSTOMER))'
        $script:C[2].DurationMs   | Should -Be 850
        $script:C[1].ApplicationPID | Should -Be '5678'
    }
}

Describe 'Show-TraceStructure: Datei fehlt' {
    It 'meldet einen Fehler und liefert nichts' {
        $r = & $script:Parser -Path (Join-Path $TestDrive 'gibt-es-nicht.log') 6>$null 2>$null
        $r | Should -BeNullOrEmpty
    }
}
