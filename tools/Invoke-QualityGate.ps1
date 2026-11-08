<#
.SYNOPSIS
    Runs the quality gates of the project: build of the C# parser (compiler and .NET analyzers, warnings are errors),
    PSScriptAnalyzer (Gate 1) and Pester (Gate 4).

.DESCRIPTION
    Same commands locally and in CI (.github/workflows/ci.yml). Imports exactly the module versions
    pinned in tests/RequiredModules.psd1 - a missing version stops the run instead of silently using
    another one. Works with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Gate
    Build = dotnet build of src/FirebirdTraceParser into bin/ (ADR-003), Lint = PSScriptAnalyzer only,
    Test = Pester only, All = Build, Lint and Test, each in its own process (default). The tests of the C# parser
    need the build.

.EXAMPLE
    pwsh -File ./tools/Invoke-QualityGate.ps1

.NOTES
    Exit codes: 0 = green, 1 = analyzer findings, 2 = failed tests, 3 = pinned module missing, 4 = build failed
    or dotnet missing.
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Lint', 'Test', 'All')]
    [string]$Gate = 'All'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$script:EXIT_LINT = 1
$script:EXIT_TEST = 2
$script:EXIT_MODULE = 3
$script:EXIT_BUILD = 4

$root = Split-Path -Parent $PSScriptRoot
$required = Import-PowerShellDataFile -Path (Join-Path $root 'tests/RequiredModules.psd1')

function Import-PinnedModule {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Name)
    $version = $required[$Name].RequiredVersion
    try {
        Import-Module -Name $Name -RequiredVersion $version -Force
    }
    catch {
        Write-Warning "Module $Name $version is not installed (tests/RequiredModules.psd1): $($_.Exception.Message)"
        exit $script:EXIT_MODULE
    }
}

if ($Gate -eq 'All') {
    # Each gate in its own process: after Invoke-ScriptAnalyzer has read the tests, Pester can no longer be
    # imported in the same process ("assembly with same name is already loaded", PowerShell 7.6.9).
    # The build comes first: the tests load bin/FirebirdTraceParser.dll. A process that has loaded it keeps it locked.
    $exe = (Get-Process -Id $PID).Path
    & $exe -NoProfile -File $PSCommandPath -Gate Build
    $build = $LASTEXITCODE
    & $exe -NoProfile -File $PSCommandPath -Gate Lint
    $lint = $LASTEXITCODE
    & $exe -NoProfile -File $PSCommandPath -Gate Test
    $test = $LASTEXITCODE
    exit $(if ($build -ne 0) { $build } elseif ($lint -ne 0) { $lint } else { $test })
}

$failed = 0

if ($Gate -eq 'Build') {
    $dotnet = Get-Command -Name dotnet -CommandType Application -ErrorAction SilentlyContinue
    if (-not $dotnet) {
        Write-Warning 'dotnet (.NET SDK, see global.json) is not installed - the C# parser cannot be built.'
        exit $script:EXIT_BUILD
    }
    $project = [System.IO.Path]::Combine($root, 'src', 'FirebirdTraceParser', 'FirebirdTraceParser.csproj')
    # RestoreLockedMode: package versions exactly as in packages.lock.json
    & $dotnet.Source build $project -c Release --nologo -p:RestoreLockedMode=true
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "dotnet build failed (exit $LASTEXITCODE)."
        exit $script:EXIT_BUILD
    }
    Write-Information 'Build: bin/FirebirdTraceParser.dll' -InformationAction Continue
}

if ($Gate -eq 'Lint') {
    Import-PinnedModule -Name 'PSScriptAnalyzer'
    $settings = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
    $findings = @(Invoke-ScriptAnalyzer -Path $root -Recurse -Settings $settings)
    if ($findings.Count -gt 0) {
        $findings | Format-Table -Property Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap |
            Out-String -Width 220 | Write-Warning
        Write-Warning "PSScriptAnalyzer: $($findings.Count) finding(s)."
        $failed = $script:EXIT_LINT
    }
    else {
        Write-Information 'PSScriptAnalyzer: no findings.' -InformationAction Continue
    }
}

if ($Gate -eq 'Test') {
    Import-PinnedModule -Name 'Pester'
    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $root 'tests'
    $config.Run.PassThru = $true
    $config.Filter.ExcludeTag = 'Integration'
    $config.Output.Verbosity = 'Detailed'
    # Tests run with the default preferences a user has; 'Stop' from this script would change
    # how the scripts under test report errors (child scope, so nothing leaks back).
    $result = & { $ErrorActionPreference = 'Continue'; Invoke-Pester -Configuration $config }
    Write-Information ("Pester ({0}): {1} passed, {2} failed, {3} skipped." -f $PSVersionTable.PSVersion,
        $result.PassedCount, $result.FailedCount, $result.SkippedCount) -InformationAction Continue
    if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') {
        $failed = $script:EXIT_TEST
    }
}

exit $failed
