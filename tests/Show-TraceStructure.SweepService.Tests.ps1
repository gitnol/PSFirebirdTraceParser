#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer Sweep- und Service-Ereignisse in Show-TraceStructure.ps1.
    Fixture: tests/fixtures/trace_fb5_sweep_service.log - synthetisch, Format nach Firebird 5
    (src/utilities/ntrace/TracePluginImpl.cpp, log_event_sweep und log_event_service_*), alle Werte ausgedacht.
    Der Block "Transaction counters" endet dort mit LF statt CRLF (wie im Quellcode).
#>

BeforeAll {
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Fixture = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures', 'trace_fb5_sweep_service.log')
    $script:R = @(& $script:Parser -Path $script:Fixture 6>$null)
    function Get-TestEvent([string]$Action, [int]$Index = 0) { @($script:R | Where-Object Action -eq $Action)[$Index] }
}

Describe 'Show-TraceStructure: Sweep-Ereignisse' {
    It 'liefert einen Eintrag je Ereignisblock' {
        $script:R.Count | Should -Be 9
        @($script:R | ForEach-Object Action) | Should -Be @('SWEEP_START', 'SWEEP_PROGRESS', 'SWEEP_FINISH', 'SWEEP_FAILED',
            'ATTACH_SERVICE', 'START_SERVICE', 'DETACH_SERVICE', 'START_SERVICE', 'UNAUTHORIZED START_SERVICE')
    }

    It 'liest die Transaktionszaehler bei SWEEP_START' {
        $e = Get-TestEvent 'SWEEP_START'
        $e.SweepOIT | Should -Be 1000
        $e.SweepOAT | Should -Be 1500
        $e.SweepOST | Should -Be 1450
        $e.SweepNext | Should -Be 1600
        $e.SweepOIT | Should -BeOfType [long]
    }

    It 'liest Zaehler, Laufzeit und Tabellenstatistik bei SWEEP_FINISH' {
        $e = Get-TestEvent 'SWEEP_FINISH'
        $e.SweepOIT | Should -Be 1599
        $e.SweepNext | Should -Be 1601
        $e.SweepOST | Should -Be 1598
        $e.DurationMs | Should -Be 5333
        $e.Reads | Should -Be 1200
        $e.Writes | Should -Be 300
        $e.Fetches | Should -Be 45000
        $e.Marks | Should -Be 800
        $e.TableStats | Should -Match 'CUSTOMER'
    }

    It 'liest Verbindung und Programm des Sweeps' {
        $e = Get-TestEvent 'SWEEP_START'
        $e.DatabasePath | Should -Be 'C:\DATA\SAMPLE.FDB'
        $e.AttachID | Should -Be '77'
        $e.User | Should -Be 'SWEEPER:NONE'
        $e.ClientIP | Should -Be '192.0.2.20'
        $e.ApplicationPath | Should -Be 'C:\Program Files\Firebird\gfix.exe'
    }

    It 'laesst die Zaehler leer, wo Firebird keine schreibt (PROGRESS, FAILED, andere Ereignisse)' {
        (Get-TestEvent 'SWEEP_PROGRESS').SweepOIT | Should -BeNullOrEmpty
        (Get-TestEvent 'SWEEP_PROGRESS').DurationMs | Should -Be 2100
        (Get-TestEvent 'SWEEP_FAILED').SweepNext | Should -BeNullOrEmpty
        (Get-TestEvent 'START_SERVICE').SweepOIT | Should -BeNullOrEmpty
    }
}

Describe 'Show-TraceStructure: Service-Ereignisse' {
    It 'liest den Dienstnamen einer Sicherung (gbak)' {
        (Get-TestEvent 'START_SERVICE' 0).ServiceName | Should -BeExactly 'Backup Database'
    }

    It 'liest den Dienstnamen einer inkrementellen Sicherung (nbackup)' {
        (Get-TestEvent 'START_SERVICE' 1).ServiceName | Should -BeExactly 'Incremental Backup Database'
    }

    It 'liest Dienst-Kennung, Benutzer, Adresse und Programm aus der Dienstzeile' {
        $e = Get-TestEvent 'START_SERVICE' 1
        $e.ServiceID | Should -Be '0000000007C3D4F0'
        $e.User | Should -Be 'BACKUPUSER:RDB$ADMIN'
        $e.ProtocolInfo | Should -Be 'TCPv4:192.0.2.30/50400'
        $e.ClientIP | Should -Be '192.0.2.30'
        $e.ClientPort | Should -Be '50400'
        $e.ApplicationPath | Should -Be 'C:\Program Files\Firebird\nbackup.exe'
        $e.ApplicationPID | Should -Be '9100'
    }

    It 'liest ATTACH/DETACH_SERVICE ohne Dienstnamen und UNAUTHORIZED ohne Programm' {
        (Get-TestEvent 'ATTACH_SERVICE').ServiceID | Should -Be '0000000007C3D4E0'
        (Get-TestEvent 'ATTACH_SERVICE').ServiceName | Should -BeNullOrEmpty
        $u = Get-TestEvent 'UNAUTHORIZED START_SERVICE'
        $u.ServiceName | Should -BeExactly 'Restore Database'
        $u.User | Should -Be 'GUEST'
        $u.ApplicationPath | Should -BeNullOrEmpty
    }

    It 'uebernimmt die Schalter mit Dateipfaden nicht (Pseudonymisierung)' {
        $text = ((Get-TestEvent 'START_SERVICE' 0).PSObject.Properties | ForEach-Object { [string]$_.Value }) -join '|'
        $text | Should -Not -Match 'SAMPLE\.FBK'
        $text | Should -Not -Match '-VERBOSE'
    }

    It 'haengt die neuen Felder hinten an den Ausgabe-Vertrag an' {
        $names = @($script:R[0].PSObject.Properties.Name)
        $start = $names.IndexOf('ErrorMessages') + 1
        $names[$start..($start + 5)] | Should -Be @('ServiceName', 'ServiceID', 'SweepOIT', 'SweepOAT', 'SweepOST', 'SweepNext')
    }
}

Describe 'Pseudonymize-FirebirdTrace: Service-Ereignisse' {
    It 'pseudonymisiert Benutzer, IP und Programm der Dienstzeile, Dienstname und Sweep-Zaehler bleiben' {
        $p = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Pseudonymize-FirebirdTrace.ps1')
        $in = Get-TestEvent 'START_SERVICE' 1
        $out = $in | & $p 3>$null 6>$null
        $out.User | Should -Not -Be $in.User
        $out.ClientIP | Should -Not -Be $in.ClientIP
        $out.ApplicationPath | Should -Not -Be $in.ApplicationPath
        $out.ServiceName | Should -BeExactly 'Incremental Backup Database'
        $s = (Get-TestEvent 'SWEEP_START') | & $p 3>$null 6>$null
        $s.SweepOIT | Should -Be 1000
    }
}
