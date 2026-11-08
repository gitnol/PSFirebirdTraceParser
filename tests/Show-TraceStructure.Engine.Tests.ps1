#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer die Wahl des Parsers (I19, ADR-003): -Engine Auto|PowerShell|CSharp. Auto nimmt den C#-Parser, wenn
    PowerShell 7 laeuft und die gebaute DLL neben dem Skript oder unter bin/ liegt, sonst den PowerShell-Parser
    (Windows PowerShell 5.1 immer). Der Pseudonymisierer liefert mit beiden Parsern dasselbe. Werte ausgedacht.
#>

BeforeDiscovery {
    $script:IsCore = $PSVersionTable.PSEdition -eq 'Core'
}

BeforeAll {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'TraceParity.ps1'))
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Pseudo = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Pseudonymize-FirebirdTrace.ps1')
    $script:Fixtures = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
    $script:Fixture = Join-Path $script:Fixtures 'trace_fb5_windows.log'
    $script:Dll = Get-TraceParserAssembly
    $script:IsCore = $PSVersionTable.PSEdition -eq 'Core'

    function Get-EngineLine([string]$Script, [hashtable]$More = @{}) {
        # The verbose line that names the engine
        @(& $Script -Path $script:Fixture @More -Verbose 4>&1 3>$null 6>$null |
                Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message.StartsWith('Engine: ') } |
                ForEach-Object Message)
    }
    function Copy-ParserScript([string]$Folder) {
        $null = New-Item -ItemType Directory -Path $Folder -Force
        Copy-Item -LiteralPath $script:Parser -Destination $Folder
        Join-Path $Folder 'Show-TraceStructure.ps1'
    }
}

Describe 'Show-TraceStructure: -Engine (I19)' {
    It 'nimmt nur Auto, PowerShell und CSharp an' {
        { & $script:Parser -Path $script:Fixture -Engine Other } | Should -Throw
    }

    It 'nimmt mit -Engine PowerShell den PowerShell-Parser' {
        Get-EngineLine $script:Parser @{ Engine = 'PowerShell' } | Should -Be @('Engine: PowerShell')
    }

    It 'nimmt mit Auto unter PowerShell 7 den C#-Parser aus bin/' -Skip:(-not $script:IsCore) {
        Test-Path -LiteralPath $script:Dll | Should -BeTrue
        Get-EngineLine $script:Parser | Should -Be @('Engine: CSharp')
    }

    It 'nimmt unter Windows PowerShell 5.1 mit Auto den PowerShell-Parser und lehnt -Engine CSharp ab' -Skip:$script:IsCore {
        Get-EngineLine $script:Parser | Should -Be @('Engine: PowerShell')
        $out = @(& $script:Parser -Path $script:Fixture -Engine CSharp -ErrorVariable err -ErrorAction SilentlyContinue)
        $out.Count | Should -Be 0
        $err[0].Exception.Message | Should -Match 'PowerShell 7'
    }

    It 'nimmt ohne gebaute DLL mit Auto den PowerShell-Parser und lehnt -Engine CSharp ab' {
        $copy = Copy-ParserScript (Join-Path $TestDrive 'nodll')
        Get-EngineLine $copy | Should -Be @('Engine: PowerShell')
        @(& $copy -Path $script:Fixture 3>$null).Count | Should -Be 7
        $out = @(& $copy -Path $script:Fixture -Engine CSharp -ErrorVariable err -ErrorAction SilentlyContinue)
        $out.Count | Should -Be 0
        # Windows PowerShell 5.1 refuses CSharp before looking for the DLL
        $err[0].Exception.Message | Should -Match $(if ($script:IsCore) { 'FirebirdTraceParser\.dll' } else { 'PowerShell 7' })
    }

    It 'findet die DLL auch direkt neben dem Skript (eigener Prozess)' -Skip:(-not $script:IsCore) {
        $folder = Join-Path $TestDrive 'nextto'
        $copy = Copy-ParserScript $folder
        Copy-Item -LiteralPath $script:Dll -Destination $folder
        $exe = (Get-Process -Id $PID).Path
        $cmd = "`$v = @(& '$copy' -Path '$($script:Fixture)' -Verbose 4>&1 3>`$null 6>`$null); " +
        "@(`$v | Where-Object { `$_ -is [System.Management.Automation.VerboseRecord] -and `$_.Message.StartsWith('Engine: ') }).Message; " +
        "@(`$v | Where-Object { `$_ -isnot [System.Management.Automation.VerboseRecord] }).Count; " +
        "[AppDomain]::CurrentDomain.GetAssemblies().Where({ `$_.GetName().Name -eq 'FirebirdTraceParser' }).Location"
        $r = @(& $exe -NoProfile -NonInteractive -Command $cmd)
        $r[0] | Should -Be 'Engine: CSharp'
        $r[1] | Should -Be '7'
        $r[2] | Should -Be (Join-Path $folder 'FirebirdTraceParser.dll')
    }
}

Describe 'Pseudonymize-FirebirdTrace mit beiden Parsern (I19)' -Skip:(-not $script:IsCore) {
    BeforeAll {
        $script:Key = Join-Path $TestDrive 'parity.key'
        $bytes = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        Set-Content -Path $script:Key -Value ([Convert]::ToBase64String($bytes)) -NoNewline
    }

    It 'liefert fuer <_> mit beiden Parsern dieselben pseudonymisierten Objekte' -ForEach @(
        Get-ChildItem -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures')) -Filter '*.log' | ForEach-Object Name
    ) {
        $f = Join-Path $script:Fixtures $_
        Get-EngineLine $script:Parser @{ Engine = 'CSharp' } | Should -Be @('Engine: CSharp')
        $ps = @(& $script:Parser -Path $f -Engine PowerShell 3>$null | & $script:Pseudo -KeyFile $script:Key -RedactLiterals)
        $cs = @(& $script:Parser -Path $f -Engine CSharp 3>$null | & $script:Pseudo -KeyFile $script:Key -RedactLiterals)
        $cs.Count | Should -BeGreaterThan 0
        Compare-TraceOutput -Expected $ps -Actual $cs | Should -BeNullOrEmpty
    }
}
