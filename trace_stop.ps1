#Requires -Version 7.4
<#
.SYNOPSIS
    Stops the Firebird trace session started with trace_start.ps1 (Firebird 4.0 / 5.0).

.DESCRIPTION
    Finds the session without guessing from file names:
      1. trace_session.json (written by trace_start.ps1) names the session and its log file.
      2. The trace ID is in the first line of that log file ("Trace session ID 7 started").
      3. If it is not there (yet), "fbtracemgr -LIST" is searched for the session name.
    Without trace_session.json: -LIST is searched for sessions whose name starts with SessionName
    from config.json. Exactly one found -> stop it; several -> list them and stop (then use -Id).

.PARAMETER Id
    Optional: trace ID to stop (e.g. from "fbtracemgr -LIST"). Skips the search.

.EXAMPLE
    pwsh -File .\trace_stop.ps1

.EXAMPLE
    pwsh -File .\trace_stop.ps1 -Id 7

.NOTES
    Exit codes: 0 = stopped, 1 = config.json missing, 2 = configuration invalid, 3 = no session found,
    4 = several sessions match, 5 = fbtracemgr error or stop not confirmed, 6 = unexpected error.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, [int]::MaxValue)]
    [int]$Id
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$InformationPreference = 'Continue'
. (Join-Path $PSScriptRoot 'TraceCommon.ps1')

try {
    $config = Read-TraceConfig -ScriptRoot $PSScriptRoot
    $result = Stop-TraceSession -Config $config -ScriptRoot $PSScriptRoot -Id $Id
    Write-Information "Trace-ID $($result.Id) gestoppt."
    if ($result.LogFile) { Write-Information "Log-Datei: $($result.LogFile)" }
    exit 0
}
catch {
    exit (Resolve-TraceExitCode -ErrorRecord $_)
}
