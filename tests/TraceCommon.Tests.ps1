#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer TraceCommon.ps1, trace_start.ps1 und trace_stop.ps1 (I4, I5).
    fbtracemgr wird nie wirklich aufgerufen: alle Aufrufe laufen ueber Invoke-FbTraceMgr, und das ist hier gemockt
    (docs/testing/UNIT_TESTS.md 8.5). Alle Namen, Pfade und Passwoerter sind ausgedacht.
#>

BeforeAll {
    Set-StrictMode -Version 3.0
    $script:RepoRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..'))
    . ([System.IO.Path]::Combine($script:RepoRoot, 'TraceCommon.ps1'))

    $script:Secret = 'Geheim-Test-4711'
    $script:Stamp = [datetime]::new(2026, 11, 8, 9, 30, 0)

    function Initialize-TestRoot {
        # Ordner wie beim Nutzer: config.json, fbtracemgr.exe (leere Datei), Trace-Konfiguration, Ausgabeordner,
        # Passwortdatei. -Firebird ueberschreibt Schluessel; Wert $null entfernt den Schluessel.
        param([hashtable]$Firebird = @{}, [switch]$NoConfig, [string]$RawJson)
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $fb = Join-Path $root 'fb'
        $out = Join-Path $root 'out'
        $null = New-Item -ItemType Directory -Path $fb, $out
        $null = New-Item -ItemType File -Path (Join-Path $fb 'fbtracemgr.exe')
        Set-Content -LiteralPath (Join-Path $root 'fbtrace50.conf') -Value 'database { enabled = true }'
        $pass = Join-Path $root 'fb.pass'
        Set-Content -LiteralPath $pass -Value $script:Secret -NoNewline
        $values = [ordered]@{
            FirebirdPath = $fb; Username = 'TRACE_USER'; PasswordFile = $pass; UseTrustedAuth = $false; Role = ''
            TraceConfigFilename = 'fbtrace50.conf'; OutputDirectory = $out; SessionName = 'PSFirebirdTrace'
        }
        foreach ($k in $Firebird.Keys) {
            if ($null -eq $Firebird[$k]) { $values.Remove($k) } else { $values[$k] = $Firebird[$k] }
        }
        $json = if ($RawJson) { $RawJson } else { @{ Firebird = $values } | ConvertTo-Json -Depth 3 }
        if (-not $NoConfig) { Set-Content -LiteralPath (Join-Path $root 'config.json') -Value $json -Encoding UTF8 }
        $root
    }

    function Get-ConfigError([string]$Root) {
        ({ $null = Read-TraceConfig -ScriptRoot $Root } | Should -Throw -PassThru).Exception
    }

    function Get-TestConfig([string]$Root, [hashtable]$Override = @{}) {
        # Gepruefte Konfiguration ohne Read-TraceConfig: Start/Stop werden fuer sich getestet
        $c = [ordered]@{
            FbTraceMgr = (Join-Path $Root 'fbbtracemgr.exe'); TraceConfigPath = (Join-Path $Root 'fbtrace50.conf')
            OutputDirectory = (Join-Path $Root 'out'); Username = 'TRACE_USER'; PasswordFile = (Join-Path $Root 'fb.pass')
            UseTrustedAuth = $false; Role = ''; SessionName = 'PSFirebirdTrace'
        }
        foreach ($k in $Override.Keys) { $c[$k] = $Override[$k] }
        [pscustomobject]$c
    }

    $script:ListOutput = [string[]]@(
        'Session ID: 3', '  name:  Andere_Sitzung', '  user:  TRACE_USER', '  date:  2026-11-08 09:00:00',
        '  flags: active, trace', '', 'Session ID: 7', '  name:  PSFirebirdTrace_20261108_093000',
        '  user:  TRACE_USER', '  date:  2026-11-08 09:30:00', '  flags: active, trace'
    )
    function Write-TestState([string]$Root, [string]$LogFirstLine) {
        $log = Join-Path $Root 'out\trace_output_20261108_093000.log'
        if ($null -ne $LogFirstLine) { Set-Content -LiteralPath $log -Value $LogFirstLine }
        @{ SessionName = 'PSFirebirdTrace_20261108_093000'; LogFile = $log; StartedAt = '2026-11-08T09:30:00' } |
            ConvertTo-Json | Set-Content -LiteralPath (Get-TraceStatePath -ScriptRoot $Root) -Encoding UTF8
        $log
    }
}

Describe 'Read-TraceConfig: Konfiguration pruefen (I5)' {
    It 'meldet eine fehlende config.json mit Exit-Code 1' {
        $e = Get-ConfigError (Initialize-TestRoot -NoConfig)
        $e.ExitCode | Should -Be 1
        $e.Message | Should -Match 'config\.json'
    }

    It 'meldet ungueltiges JSON mit Exit-Code 2' {
        $e = Get-ConfigError (Initialize-TestRoot -RawJson '{ "Firebird": ')
        $e.ExitCode | Should -Be 2
    }

    It 'meldet alle fehlenden oder falschen Werte zusammen' {
        $root = Initialize-TestRoot -Firebird @{
            FirebirdPath = 'C:\gibt-es-nicht'; TraceConfigFilename = 'fehlt.conf'; OutputDirectory = $null
            Username = $null; PasswordFile = 'C:\gibt-es-nicht\fb.pass'; SessionName = 'mit Leerzeichen'
        }
        $e = Get-ConfigError $root
        $e.ExitCode | Should -Be 2
        foreach ($word in 'fbtracemgr.exe', 'fehlt.conf', 'OutputDirectory', 'Username', 'PasswordFile', 'SessionName') {
            $e.Message | Should -Match ([regex]::Escape($word))
        }
    }

    It 'liefert die geprueften Werte als Objekt' {
        $root = Initialize-TestRoot -Firebird @{ Role = 'TRACER' }
        $c = Read-TraceConfig -ScriptRoot $root
        $c.FbTraceMgr | Should -Be (Join-Path $root 'fb\fbtracemgr.exe')
        $c.TraceConfigPath | Should -Be (Join-Path $root 'fbtrace50.conf')
        $c.OutputDirectory | Should -Be (Join-Path $root 'out')
        $c.Username | Should -Be 'TRACE_USER'
        $c.PasswordFile | Should -Be (Join-Path $root 'fb.pass')
        $c.UseTrustedAuth | Should -BeFalse
        $c.Role | Should -Be 'TRACER'
        $c.SessionName | Should -Be 'PSFirebirdTrace'
    }

    It 'lehnt ein Passwort in config.json ab, ohne es zu nennen (I4)' {
        $root = Initialize-TestRoot -Firebird @{ Password = $script:Secret }
        $e = Get-ConfigError $root
        $e.ExitCode | Should -Be 2
        $e.Message | Should -Match 'PasswordFile'
        $e.Message | Should -Not -Match ([regex]::Escape($script:Secret))
    }

    It 'braucht bei Windows-Anmeldung weder Benutzer noch Passwortdatei' {
        $root = Initialize-TestRoot -Firebird @{ UseTrustedAuth = $true; Username = $null; PasswordFile = $null }
        $c = Read-TraceConfig -ScriptRoot $root
        $c.UseTrustedAuth | Should -BeTrue
    }

    It 'setzt Umgebungsvariablen in PasswordFile und OutputDirectory ein' {
        $root = Initialize-TestRoot
        $old = $env:PSFTP_TEST_ROOT
        try {
            $env:PSFTP_TEST_ROOT = $root
            Set-Content -LiteralPath (Join-Path $root 'config.json') -Encoding UTF8 -Value (@{ Firebird = @{
                        FirebirdPath = (Join-Path $root 'fb'); Username = 'TRACE_USER'; PasswordFile = '%PSFTP_TEST_ROOT%\fb.pass'
                        TraceConfigFilename = 'fbtrace50.conf'; OutputDirectory = '%PSFTP_TEST_ROOT%\out'; SessionName = 'PSFirebirdTrace'
                    }
                } | ConvertTo-Json)
            $c = Read-TraceConfig -ScriptRoot $root
            $c.PasswordFile | Should -Be (Join-Path $root 'fb.pass')
            $c.OutputDirectory | Should -Be (Join-Path $root 'out')
        }
        finally { $env:PSFTP_TEST_ROOT = $old }
    }
}

Describe 'Get-TraceAuthArgumentList: Anmeldung ohne Passwort in der Befehlszeile (I4)' {
    It 'uebergibt Benutzer und den Pfad der Passwortdatei, nie das Passwort' {
        $c = Get-TestConfig (Initialize-TestRoot)
        $a = Get-TraceAuthArgumentList -Config $c
        $a | Should -Be @('-USER', 'TRACE_USER', '-FETCH_PASSWORD', $c.PasswordFile)
        ($a -join ' ') | Should -Not -Match ([regex]::Escape($script:Secret))
        $a | Should -Not -Contain '-PASS'
    }

    It 'nutzt -TRUSTED und haengt die Rolle an' {
        $c = Get-TestConfig (Initialize-TestRoot) @{ UseTrustedAuth = $true; Role = 'TRACER'; Username = ''; PasswordFile = '' }
        Get-TraceAuthArgumentList -Config $c | Should -Be @('-TRUSTED', '-ROLE', 'TRACER')
    }
}

Describe 'Start-TraceSession (I5)' {
    BeforeEach {
        $script:Root = Initialize-TestRoot
        $script:Config = Get-TestConfig $script:Root
        $script:Seen = @{}
        Mock Invoke-FbTraceMgr {
            $script:Seen.StateDuringCall = Test-Path -LiteralPath (Get-TraceStatePath -ScriptRoot $script:Root)
            Set-Content -LiteralPath $OutFile -Value 'Trace session ID 7 started'
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@() }
        }
    }

    It 'startet mit Name, Konfiguration und Logdatei im Ausgabeordner' {
        $r = Start-TraceSession -Config $script:Config -ScriptRoot $script:Root -Timestamp $script:Stamp 6>$null
        $log = Join-Path $script:Config.OutputDirectory 'trace_output_20261108_093000.log'
        $r.SessionName | Should -Be 'PSFirebirdTrace_20261108_093000'
        $r.LogFile | Should -Be $log
        $r.Bytes | Should -BeGreaterThan 0
        $expected = @('-SE', 'service_mgr', '-USER', 'TRACE_USER', '-FETCH_PASSWORD', $script:Config.PasswordFile,
            '-START', '-NAME', 'PSFirebirdTrace_20261108_093000', '-CONFIG', $script:Config.TraceConfigPath)
        Should -Invoke Invoke-FbTraceMgr -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq $script:Config.FbTraceMgr -and $OutFile -eq $log -and
            (($ArgumentList -join '|') -ceq ($expected -join '|'))
        }
    }

    It 'merkt sich die Sitzung vor dem Aufruf und raeumt danach auf' {
        $null = Start-TraceSession -Config $script:Config -ScriptRoot $script:Root -Timestamp $script:Stamp 6>$null
        $script:Seen.Keys | Should -Contain 'StateDuringCall'
        $script:Seen['StateDuringCall'] | Should -BeTrue
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Not -Exist
    }

    It 'nennt im Hinweis trace_stop.ps1 (K4)' {
        $info = @(Start-TraceSession -Config $script:Config -ScriptRoot $script:Root -Timestamp $script:Stamp 6>&1 |
                Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { "$_" })
        ($info -join "`n") | Should -Match 'trace_stop\.ps1'
        ($info -join "`n") | Should -Not -Match 'trace-stop'
    }

    It 'startet keine zweite Sitzung, solange eine gemerkt ist (Exit-Code 2)' {
        $null = Write-TestState $script:Root 'Trace session ID 7 started'
        $e = ({ Start-TraceSession -Config $script:Config -ScriptRoot $script:Root -Timestamp $script:Stamp 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 2
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Exist
        Should -Invoke Invoke-FbTraceMgr -Times 0 -Exactly
    }

    It 'meldet einen Fehler von fbtracemgr mit Exit-Code 5 und raeumt auf' {
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 1; Output = [string[]]@() } }
        $e = ({ Start-TraceSession -Config $script:Config -ScriptRoot $script:Root -Timestamp $script:Stamp 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 5
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Not -Exist
    }
}

Describe 'Stop-TraceSession (I5)' {
    BeforeEach {
        $script:Root = Initialize-TestRoot
        $script:Config = Get-TestConfig $script:Root
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 0; Output = $script:ListOutput } } -ParameterFilter {
            $ArgumentList -contains '-LIST'
        }
        Mock Invoke-FbTraceMgr {
            $id = $ArgumentList[[array]::IndexOf($ArgumentList, '-ID') + 1]
            [pscustomobject]@{ ExitCode = 0; Output = [string[]]@("Trace session ID $id stopped") }
        } -ParameterFilter { $ArgumentList -contains '-STOP' }
    }

    It 'nimmt die ID aus der ersten Zeile der gemerkten Logdatei' {
        $log = Write-TestState $script:Root 'Trace session ID 12 started'
        $r = Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root 6>$null
        $r.Id | Should -Be 12
        $r.LogFile | Should -Be $log
        Should -Invoke Invoke-FbTraceMgr -Times 1 -Exactly -ParameterFilter {
            ($ArgumentList -join '|') -ceq "-SE|service_mgr|-USER|TRACE_USER|-FETCH_PASSWORD|$($script:Config.PasswordFile)|-STOP|-ID|12"
        }
        Should -Invoke Invoke-FbTraceMgr -Times 0 -Exactly -ParameterFilter { $ArgumentList -contains '-LIST' }
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Not -Exist
    }

    It 'sucht ohne ID in der Logdatei ueber den Sitzungsnamen' {
        $null = Write-TestState $script:Root $null
        $r = Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root 6>$null
        $r.Id | Should -Be 7
    }

    It 'sucht ohne gemerkte Sitzung ueber das Praefix aus config.json' {
        $r = Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root 6>$null
        $r.Id | Should -Be 7
    }

    It 'stoppt eine angegebene ID ohne Suche' {
        $r = Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root -Id 3 6>$null
        $r.Id | Should -Be 3
        Should -Invoke Invoke-FbTraceMgr -Times 0 -Exactly -ParameterFilter { $ArgumentList -contains '-LIST' }
    }

    It 'meldet Exit-Code 3, wenn keine Sitzung passt' {
        $c = Get-TestConfig $script:Root @{ SessionName = 'Unbekannt' }
        $e = ({ Stop-TraceSession -Config $c -ScriptRoot $script:Root 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 3
    }

    It 'vergisst eine gemerkte Sitzung, die nicht mehr laeuft (Exit-Code 3)' {
        $null = Write-TestState $script:Root $null
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 0; Output = [string[]]@() } } -ParameterFilter {
            $ArgumentList -contains '-LIST'
        }
        $e = ({ Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 3
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Not -Exist
    }

    It 'meldet Exit-Code 4 bei mehreren passenden Sitzungen' {
        $c = Get-TestConfig $script:Root @{ SessionName = 'A' }
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 0; Output = [string[]]@(
                    'Session ID: 1', '  name:  A_1', 'Session ID: 2', '  name:  A_2') }
        } -ParameterFilter { $ArgumentList -contains '-LIST' }
        $e = ({ Stop-TraceSession -Config $c -ScriptRoot $script:Root 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 4
        Should -Invoke Invoke-FbTraceMgr -Times 0 -Exactly -ParameterFilter { $ArgumentList -contains '-STOP' }
    }

    It 'meldet Exit-Code 5 ohne Bestaetigung und behaelt die gemerkte Sitzung' {
        $null = Write-TestState $script:Root 'Trace session ID 12 started'
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 0; Output = [string[]]@('irgendwas') } } -ParameterFilter {
            $ArgumentList -contains '-STOP'
        }
        $e = ({ Stop-TraceSession -Config $script:Config -ScriptRoot $script:Root 6>$null } | Should -Throw -PassThru).Exception
        $e.ExitCode | Should -Be 5
        Get-TraceStatePath -ScriptRoot $script:Root | Should -Exist
    }
}

Describe 'Get-TraceSessionList (I5)' {
    It 'liest Kennung und Name je Sitzung aus fbtracemgr -LIST' {
        $c = Get-TestConfig (Initialize-TestRoot)
        Mock Invoke-FbTraceMgr { [pscustomobject]@{ ExitCode = 0; Output = $script:ListOutput } }
        $s = @(Get-TraceSessionList -Config $c)
        $s.Count | Should -Be 2
        $s[0].Id | Should -Be 3
        $s[0].Name | Should -BeExactly 'Andere_Sitzung'
        $s[1].Id | Should -Be 7
        $s[1].Name | Should -BeExactly 'PSFirebirdTrace_20261108_093000'
    }
}

Describe 'Resolve-TraceExitCode (I5)' {
    It 'liefert den Exit-Code einer TraceException' {
        $rec = try { throw [TraceException]::new(4, 'Test') } catch { $_ }
        Resolve-TraceExitCode -ErrorRecord $rec 2>$null | Should -Be 4
    }

    It 'liefert 6 fuer unerwartete Fehler' {
        $rec = try { throw 'kaputt' } catch { $_ }
        Resolve-TraceExitCode -ErrorRecord $rec 2>$null | Should -Be 6
    }
}

Describe 'Invoke-FbTraceMgr: Aufruf eines Programms (I5)' {
    BeforeAll { $script:Pwsh = (Get-Command pwsh -ErrorAction Stop).Source }

    It 'liefert Ausgabe und Exit-Code' {
        $r = Invoke-FbTraceMgr -FilePath $script:Pwsh -ArgumentList '-NoProfile', '-Command', "'zeile'; exit 3"
        $r.ExitCode | Should -Be 3
        $r.Output | Should -Be @('zeile')
    }

    It 'schreibt die Ausgabe byte-genau in die Datei (PowerShell 7.4+)' -Skip:($PSVersionTable.PSVersion -lt [version]'7.4') {
        $f = Join-Path $TestDrive 'bytes.log'
        $cmd = '$b = [byte[]](0xC3, 0xA4, 0x0A); $s = [Console]::OpenStandardOutput(); $s.Write($b, 0, 3); $s.Flush()'
        $r = Invoke-FbTraceMgr -FilePath $script:Pwsh -ArgumentList '-NoProfile', '-Command', $cmd -OutFile $f
        $r.ExitCode | Should -Be 0
        $f | Should -Exist
        [System.IO.File]::ReadAllBytes($f) | Should -Be @(0xC3, 0xA4, 0x0A)
    }
}

Describe 'Trace-Skripte als Prozess (Exit-Codes, I5)' {
    BeforeAll {
        $script:Pwsh = (Get-Command pwsh -ErrorAction Stop).Source
        function Invoke-TraceScript([string]$Root, [string]$Name) {
            foreach ($f in 'trace_start.ps1', 'trace_stop.ps1', 'TraceCommon.ps1') {
                Copy-Item -LiteralPath (Join-Path $script:RepoRoot $f) -Destination $Root
            }
            $out = & $script:Pwsh -NoProfile -File (Join-Path $Root $Name) 2>&1
            [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = ($out | Out-String) }
        }
    }

    It 'trace_start.ps1 endet ohne config.json mit Exit-Code 1' {
        $r = Invoke-TraceScript (Initialize-TestRoot -NoConfig) 'trace_start.ps1'
        $r.ExitCode | Should -Be 1
    }

    It 'trace_start.ps1 endet mit Exit-Code 2, wenn fbtracemgr.exe fehlt, und startet nichts' {
        $root = Initialize-TestRoot -Firebird @{ FirebirdPath = 'C:\gibt-es-nicht' }
        $r = Invoke-TraceScript $root 'trace_start.ps1'
        $r.ExitCode | Should -Be 2
        $r.Text | Should -Match 'fbtracemgr\.exe'
        @(Get-ChildItem -LiteralPath (Join-Path $root 'out')).Count | Should -Be 0
    }

    It 'trace_stop.ps1 endet mit Exit-Code 2 bei Passwort in config.json' {
        $r = Invoke-TraceScript (Initialize-TestRoot -Firebird @{ Password = $script:Secret }) 'trace_stop.ps1'
        $r.ExitCode | Should -Be 2
        $r.Text | Should -Not -Match ([regex]::Escape($script:Secret))
    }
}

Describe 'Repository: Vorlagen und Schutz der Zugangsdaten (I4)' {
    It 'config.sample.json hat kein Passwort, keinen SYSDBA und alle Schluessel' {
        $s = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'config.sample.json') -Raw | ConvertFrom-Json
        $names = @($s.Firebird.PSObject.Properties.Name)
        $names | Should -Not -Contain 'Password'
        $s.Firebird.Username | Should -Not -Be 'SYSDBA'
        foreach ($k in 'FirebirdPath', 'Username', 'PasswordFile', 'UseTrustedAuth', 'Role', 'TraceConfigFilename',
            'OutputDirectory', 'SessionName') {
            $names | Should -Contain $k
        }
    }

    It 'config.json ist nicht in git, trace_session.json wird ignoriert' {
        Push-Location -LiteralPath $script:RepoRoot
        try {
            (& git ls-files -- 'config.json') | Should -BeNullOrEmpty
            & git check-ignore -q -- 'trace_session.json'
            $LASTEXITCODE | Should -Be 0
        }
        finally { Pop-Location }
    }
}
