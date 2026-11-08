#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer das C#-Geruest (I16, ADR-003): die gebaute DLL laedt unter dieser PowerShell (CI: 7 und 5.1), das Cmdlet
    prueft die Parameter wie Show-TraceStructure.ps1 und liefert je Ereignis ein Objekt mit denselben Feldern, derselben
    Reihenfolge und denselben Standardwerten; die Kopfzeile wird gleich gelesen. Orakel ist das Skript selbst.
    Vorher bauen: tools/Invoke-QualityGate.ps1 -Gate Build. Werte ausgedacht, IPs aus 192.0.2.0/24.
#>

BeforeAll {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'TraceParity.ps1'))
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Fixtures = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
    $script:Dll = Get-TraceParserAssembly
    if (Test-Path -LiteralPath $script:Dll) { Import-Module -Name $script:Dll -Verbose:$false }
    $script:HeaderFields = 'Timestamp', 'Action', 'ProcessID', 'SessionID', 'ErrorSource'
    $script:Conn = "`tC:\DATA\SAMPLE.FDB (ATT_9, APPUSER:NONE, UTF8, TCPv4:192.0.2.90/50900)"

    function Write-TestTrace([string]$Name, [string[]]$Lines) {
        $f = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($f, (($Lines -join "`n") + "`n"))
        $f
    }
    function Select-Field([object[]]$Objects, [string[]]$Name) {
        # Same objects reduced to some fields (order kept), for a comparison of these fields only
        @($Objects | Select-Object -Property $Name)
    }
}

Describe 'C#-Parser: Build und Laden (I16)' {
    It 'die gebaute DLL liegt unter bin/' {
        Test-Path -LiteralPath $script:Dll | Should -BeTrue -Because 'tools/Invoke-QualityGate.ps1 -Gate Build baut sie'
    }

    It 'laedt unter dieser PowerShell und stellt ConvertFrom-FirebirdTrace als Cmdlet bereit' {
        $c = Get-Command -Name ConvertFrom-FirebirdTrace -ErrorAction SilentlyContinue
        $c.CommandType | Should -Be 'Cmdlet'
        $c.Source | Should -Be 'FirebirdTraceParser'
    }

    It 'prueft die Parameter wie das Skript' {
        $f = Join-Path $script:Fixtures 'trace_fb5_windows.log'
        { ConvertFrom-FirebirdTrace -Path $f -MaxBlockLines 0 } | Should -Throw
        { ConvertFrom-FirebirdTrace -Path $f -RegexTimeoutSeconds 0 } | Should -Throw
        { ConvertFrom-FirebirdTrace -Path $f -RegexTimeoutSeconds 3601 } | Should -Throw
        (Get-Command ConvertFrom-FirebirdTrace).Parameters['Path'].Attributes.Mandatory | Should -Contain $true
    }

    It 'meldet eine fehlende Datei mit demselben Text und ohne Ausgabe' {
        $missing = Join-Path $TestDrive 'missing.log'
        $out = @(ConvertFrom-FirebirdTrace -Path $missing -ErrorVariable err -ErrorAction SilentlyContinue)
        $null = & $script:Parser -Path $missing -ErrorVariable errPs -ErrorAction SilentlyContinue
        $out.Count | Should -Be 0
        $err.Count | Should -Be 1
        $err[0].Exception.Message | Should -BeExactly $errPs[0].Exception.Message
    }
}

Describe 'C#-Parser: Felder und Kopfzeile gleich wie Show-TraceStructure.ps1 (I16)' {
    It 'liefert je Ereignis ein PSCustomObject mit denselben 46 Feldern in derselben Reihenfolge (<_>)' -ForEach @(
        Get-ChildItem -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures')) -Filter '*.log' | ForEach-Object Name
    ) {
        $f = Join-Path $script:Fixtures $_
        $ps = @(& $script:Parser -Path $f 3>$null)
        $cs = @(ConvertFrom-FirebirdTrace -Path $f 3>$null)
        $cs.Count | Should -Be $ps.Count
        @($cs[0].PSObject.Properties.Name).Count | Should -Be 46
        foreach ($i in 0..($ps.Count - 1)) {
            ($cs[$i].PSObject.Properties.Name -join ',') | Should -BeExactly ($ps[$i].PSObject.Properties.Name -join ',')
            ($cs[$i].PSObject.TypeNames -join ',') | Should -BeExactly ($ps[$i].PSObject.TypeNames -join ',')
        }
    }

    It 'liest die Kopfzeile gleich (<_>)' -ForEach @(
        Get-ChildItem -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures')) -Filter '*.log' | ForEach-Object Name
    ) {
        $f = Join-Path $script:Fixtures $_
        $ps = @(Select-Field @(& $script:Parser -Path $f 3>$null) $script:HeaderFields)
        $cs = @(Select-Field @(ConvertFrom-FirebirdTrace -Path $f 3>$null) $script:HeaderFields)
        Compare-TraceOutput -Expected $ps -Actual $cs | Should -BeNullOrEmpty
    }

    It 'liefert bei Ereignissen nur mit Kopfzeile dieselben Werte in allen Feldern (Standardwerte)' {
        $f = Write-TestTrace 'header_only.log' @(
            'Trace session ID 1 started', ''
            '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION'
            '2026-11-08T10:00:01.0000 (4321:0x7f3a1c2b4d10) FAILED EXECUTE_STATEMENT_FINISH'
            '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) ERROR AT JStatement::prepare'
            '2026-11-08T10:00:03.0000 (4321:000001A2B3C4D5E0) UNAUTHORIZED ATTACH_DATABASE'
            '2026-11-08T10:00:04.12345678 (4321:000001A2B3C4D5E0) COMMIT_TRANSACTION'
        )
        $ps = @(& $script:Parser -Path $f 3>$null)
        $cs = @(ConvertFrom-FirebirdTrace -Path $f 3>$null)
        $cs.Count | Should -Be 5
        Compare-TraceOutput -Expected $ps -Actual $cs | Should -BeNullOrEmpty
    }

    It 'teilt Ereignisse ueber die 4-MB-Stuecke hinweg gleich' {
        $sql = 'SELECT ' + ('X' * 60000) + ' FROM T'
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($i in 1..90) {
            $lines.AddRange([string[]]@("2026-11-08T10:00:$('{0:D2}' -f ($i % 60)).0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH", $script:Conn, '', "Statement $($i):", ('-' * 79), $sql, '', '      1 ms', ''))
        }
        $f = Write-TestTrace 'chunks.log' $lines.ToArray()
        (Get-Item -LiteralPath $f).Length | Should -BeGreaterThan 5MB
        $ps = @(Select-Field @(& $script:Parser -Path $f 3>$null) $script:HeaderFields)
        $cs = @(Select-Field @(ConvertFrom-FirebirdTrace -Path $f 3>$null) $script:HeaderFields)
        $cs.Count | Should -Be 90
        Compare-TraceOutput -Expected $ps -Actual $cs | Should -BeNullOrEmpty
    }
}
