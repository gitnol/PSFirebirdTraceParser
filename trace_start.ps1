#Requires -Version 7.4
<#
.SYNOPSIS
    Starts a Firebird trace session (Firebird 4.0 / 5.0) and writes its output to a log file.

.DESCRIPTION
    - Reads and checks config.json next to this script (template: config.sample.json).
    - Logs on WITHOUT a plaintext password: password file (-FETCH_PASSWORD) or Windows logon (-TRUSTED).
    - Gives the session a unique name (-NAME) and remembers it in trace_session.json, so that
      trace_stop.ps1 finds exactly this session.
    - The window stays busy while the trace runs. Stop it with trace_stop.ps1 from a SECOND window.

    PowerShell 7.4 or later is required: only from 7.4 on does the redirection write the output of
    fbtracemgr unchanged (byte for byte) into the file. Windows PowerShell 5.1 rewrites it as UTF-16.

.EXAMPLE
    pwsh -File .\trace_start.ps1

.NOTES
    Exit codes: 0 = trace ended, 1 = config.json missing, 2 = configuration invalid or a session is
    still remembered, 5 = fbtracemgr reported an error, 6 = unexpected error.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
$InformationPreference = 'Continue'
. (Join-Path $PSScriptRoot 'TraceCommon.ps1')

try {
    $config = Read-TraceConfig -ScriptRoot $PSScriptRoot
    $result = Start-TraceSession -Config $config -ScriptRoot $PSScriptRoot
    Write-Information ("Trace beendet. Log: {0} ({1:N1} MB)" -f $result.LogFile, ($result.Bytes / 1MB))
    exit 0
}
catch {
    exit (Resolve-TraceExitCode -ErrorRecord $_)
}
