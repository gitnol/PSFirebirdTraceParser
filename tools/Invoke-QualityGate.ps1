<#
.SYNOPSIS
    Runs the quality gates of the project: PSScriptAnalyzer (Gate 1) and Pester (Gate 4).

.DESCRIPTION
    Same commands locally and in CI (.github/workflows/ci.yml). Imports exactly the module versions
    pinned in tests/RequiredModules.psd1 - a missing version stops the run instead of silently using
    another one. Works with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Gate
    Lint = PSScriptAnalyzer only, Test = Pester only, All = both, each in its own process (default).

.EXAMPLE
    pwsh -File ./tools/Invoke-QualityGate.ps1

.NOTES
    Exit codes: 0 = green, 1 = analyzer findings, 2 = failed tests, 3 = pinned module missing.
#>
[CmdletBinding()]
param(
    [ValidateSet('Lint', 'Test', 'All')]
    [string]$Gate = 'All'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$script:EXIT_LINT = 1
$script:EXIT_TEST = 2
$script:EXIT_MODULE = 3

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
    $exe = (Get-Process -Id $PID).Path
    & $exe -NoProfile -File $PSCommandPath -Gate Lint
    $lint = $LASTEXITCODE
    & $exe -NoProfile -File $PSCommandPath -Gate Test
    $test = $LASTEXITCODE
    exit $(if ($lint -ne 0) { $lint } else { $test })
}

$failed = 0

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
