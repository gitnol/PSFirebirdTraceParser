<#
.SYNOPSIS
    Shared functions for trace_start.ps1 and trace_stop.ps1 (Firebird 4.0 / 5.0).

.DESCRIPTION
    STUB (test commit): signatures and empty, well-formed return values only.
#>

class TraceException : System.Exception {
    [int]$ExitCode
    TraceException([int]$ExitCode, [string]$Message) : base($Message) {
        $this.ExitCode = $ExitCode
    }
}

$script:EXIT_CONFIG_MISSING = 1
$script:EXIT_CONFIG_INVALID = 2
$script:EXIT_NO_SESSION_FOUND = 3
$script:EXIT_NO_TRACE_ID = 4
$script:EXIT_FBTRACEMGR_ERROR = 5
$script:EXIT_UNEXPECTED = 6

function Read-TraceConfig {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string]$ScriptRoot)
    [pscustomobject]@{
        FbTraceMgr = ''; TraceConfigPath = ''; OutputDirectory = ''; Username = ''; PasswordFile = ''
        UseTrustedAuth = $false; Role = ''; SessionName = ''
    }
}

function Get-TraceAuthArgumentList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [pscustomobject]$Config)
    , [string[]]@()
}

function Get-TraceStatePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string]$ScriptRoot)
    Join-Path $ScriptRoot 'trace_session.json'
}

function Invoke-FbTraceMgr {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList,
        [string]$OutFile
    )
    [pscustomobject]@{ ExitCode = 0; Output = [string[]]@() }
}

function Get-TraceSessionList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)] [pscustomobject]$Config)
    , [pscustomobject[]]@()
}

function Start-TraceSession {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject]$Config,
        [Parameter(Mandatory)] [string]$ScriptRoot,
        [datetime]$Timestamp = (Get-Date)
    )
    [pscustomobject]@{ SessionName = ''; LogFile = ''; Bytes = [long]0 }
}

function Stop-TraceSession {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject]$Config,
        [Parameter(Mandatory)] [string]$ScriptRoot,
        [int]$Id
    )
    [pscustomobject]@{ Id = 0; LogFile = '' }
}

function Resolve-TraceExitCode {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)
    0
}
