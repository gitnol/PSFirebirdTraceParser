<#
.SYNOPSIS
    Shared functions for trace_start.ps1 and trace_stop.ps1 (Firebird 4.0 / 5.0).

.DESCRIPTION
    Loaded by dot-sourcing ( . (Join-Path $PSScriptRoot 'TraceCommon.ps1') ); do not run it directly.

    The password is neither in config.json nor on the command line: fbtracemgr reads it itself from a
    file (-FETCH_PASSWORD <file>) or logs on with the Windows account (-TRUSTED). See
    docs/architecture/ADR/ADR-002-trace-anmeldung.md.

    Errors are thrown as [TraceException] with the exit code of the calling script; only the scripts
    call 'exit' (Resolve-TraceExitCode). All calls of fbtracemgr go through Invoke-FbTraceMgr, the one
    function that tests replace with a mock.

    Strict mode is set by the calling script, not here (dot-sourcing would change the caller's scope).
#>

class TraceException : System.Exception {
    [int]$ExitCode
    TraceException([int]$ExitCode, [string]$Message) : base($Message) {
        $this.ExitCode = $ExitCode
    }
}

# Exit codes of trace_start.ps1 / trace_stop.ps1 (docs/architecture/ERROR_HANDLING.md)
$script:EXIT_CONFIG_MISSING = 1
$script:EXIT_CONFIG_INVALID = 2
$script:EXIT_NO_SESSION_FOUND = 3
$script:EXIT_NO_TRACE_ID = 4
$script:EXIT_FBTRACEMGR_ERROR = 5
$script:EXIT_UNEXPECTED = 6

$script:SERVICE_MANAGER = 'service_mgr'
$script:CONFIG_FILE_NAME = 'config.json'
$script:STATE_FILE_NAME = 'trace_session.json'
$script:FBTRACEMGR_EXE = 'fbtracemgr.exe'
# First line fbtracemgr writes for a started session, e.g. "Trace session ID 7 started"
$script:SESSION_STARTED_PATTERN = '^Trace session ID (\d+) started'

function Read-TraceConfig {
    <# Reads and checks config.json; returns one object with checked values. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string]$ScriptRoot)

    $configPath = Join-Path $ScriptRoot $script:CONFIG_FILE_NAME
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw [TraceException]::new($script:EXIT_CONFIG_MISSING, "config.json fehlt: $configPath (Vorlage: config.sample.json)")
    }
    try {
        $raw = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw [TraceException]::new($script:EXIT_CONFIG_INVALID, "config.json ist kein gueltiges JSON: $($_.Exception.Message)")
    }
    $fb = if ($null -ne $raw) { $raw.PSObject.Properties['Firebird'] } else { $null }
    if ($null -eq $fb -or $null -eq $fb.Value) {
        throw [TraceException]::new($script:EXIT_CONFIG_INVALID, "config.json: Abschnitt 'Firebird' fehlt.")
    }
    $fb = $fb.Value

    # A missing key gives '' instead of a strict-mode error; %VAR% is expanded where paths are expected.
    $get = {
        param([string]$Name, [switch]$Expand)
        $p = $fb.PSObject.Properties[$Name]
        if ($null -eq $p -or $null -eq $p.Value) { return '' }
        if ($Expand) { return [Environment]::ExpandEnvironmentVariables([string]$p.Value) }
        return [string]$p.Value
    }
    $useTrusted = (& $get 'UseTrustedAuth') -eq 'True'
    $errors = [System.Collections.Generic.List[string]]::new()

    if ($null -ne $fb.PSObject.Properties['Password']) {
        # I4: never accept a plaintext password; the value itself is never repeated in a message
        $errors.Add("Password steht in config.json - entfernen und PasswordFile (oder UseTrustedAuth) nutzen.")
    }

    $exe = ''
    $firebirdPath = & $get 'FirebirdPath' -Expand
    if ([string]::IsNullOrWhiteSpace($firebirdPath)) {
        $errors.Add('FirebirdPath fehlt (Ordner der Firebird-Installation mit fbtracemgr.exe).')
    }
    else {
        $exe = Join-Path $firebirdPath $script:FBTRACEMGR_EXE
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            $errors.Add("fbtracemgr.exe nicht gefunden unter '$firebirdPath' (FirebirdPath pruefen).")
        }
    }

    $traceConf = ''
    $traceName = & $get 'TraceConfigFilename'
    if ([string]::IsNullOrWhiteSpace($traceName)) {
        $errors.Add('TraceConfigFilename fehlt (z. B. fbtrace50.conf).')
    }
    else {
        $traceConf = Join-Path $ScriptRoot $traceName
        if (-not (Test-Path -LiteralPath $traceConf -PathType Leaf)) {
            $errors.Add("Trace-Konfiguration nicht gefunden: $traceName (TraceConfigFilename pruefen).")
        }
    }

    $outDir = & $get 'OutputDirectory' -Expand
    if ([string]::IsNullOrWhiteSpace($outDir) -or -not (Test-Path -LiteralPath $outDir -PathType Container)) {
        $errors.Add("Ausgabeordner fehlt oder existiert nicht: '$outDir' (OutputDirectory pruefen).")
    }

    $user = & $get 'Username'
    $passFile = & $get 'PasswordFile' -Expand
    if (-not $useTrusted) {
        if ([string]::IsNullOrWhiteSpace($user)) {
            $errors.Add('Username fehlt (oder UseTrustedAuth auf true setzen).')
        }
        if ([string]::IsNullOrWhiteSpace($passFile) -or -not (Test-Path -LiteralPath $passFile -PathType Leaf)) {
            $errors.Add("Passwortdatei fehlt: '$passFile' (PasswordFile pruefen, siehe README).")
        }
    }

    $session = & $get 'SessionName'
    if ($session -notmatch '^[A-Za-z0-9_\-]+$') {
        $errors.Add('SessionName fehlt oder enthaelt andere Zeichen als Buchstaben, Ziffern, _ und -.')
    }

    if ($errors.Count -gt 0) {
        throw [TraceException]::new($script:EXIT_CONFIG_INVALID, ($errors -join [Environment]::NewLine))
    }

    [pscustomobject]@{
        FbTraceMgr      = $exe
        TraceConfigPath = $traceConf
        OutputDirectory = $outDir
        Username        = $user
        PasswordFile    = $passFile
        UseTrustedAuth  = $useTrusted
        Role            = & $get 'Role'
        SessionName     = $session
    }
}

function Get-TraceAuthArgumentList {
    <# Logon arguments for fbtracemgr: the path of the password file, never the password. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [pscustomobject]$Config)

    $list = [System.Collections.Generic.List[string]]::new()
    if ($Config.UseTrustedAuth) {
        # Windows logon; the server needs AuthServer = Srp256, Win_Sspi in firebird.conf
        $list.Add('-TRUSTED')
    }
    else {
        $list.AddRange([string[]]@('-USER', $Config.Username, '-FETCH_PASSWORD', $Config.PasswordFile))
    }
    if (-not [string]::IsNullOrWhiteSpace($Config.Role)) {
        # Role with the system privilege TRACE_ANY_ATTACHMENT instead of SYSDBA
        $list.AddRange([string[]]@('-ROLE', $Config.Role))
    }
    $list.ToArray()
}

function Get-TraceStatePath {
    <# State file: name and log file of the session started from this folder. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string]$ScriptRoot)
    Join-Path $ScriptRoot $script:STATE_FILE_NAME
}

function Invoke-FbTraceMgr {
    <#
        The only place that runs fbtracemgr. With -OutFile, standard output goes unchanged into the file
        (byte for byte from PowerShell 7.4 on); error messages stay on the console.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$ArgumentList,
        [string]$OutFile
    )
    if ($OutFile) {
        & $FilePath @ArgumentList > $OutFile
        $output = [string[]]@()
    }
    else {
        $output = [string[]]@(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" })
    }
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Get-TraceSessionList {
    <# Reads "fbtracemgr -LIST" into objects with Id and Name. #>
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param([Parameter(Mandatory)] [pscustomobject]$Config)

    $arguments = @('-SE', $script:SERVICE_MANAGER) + (Get-TraceAuthArgumentList -Config $Config) + @('-LIST')
    $r = Invoke-FbTraceMgr -FilePath $Config.FbTraceMgr -ArgumentList $arguments
    if ($r.ExitCode -ne 0) {
        throw [TraceException]::new($script:EXIT_FBTRACEMGR_ERROR,
            "fbtracemgr -LIST fehlgeschlagen (Exit-Code $($r.ExitCode)): $($r.Output -join ' ')")
    }
    $sessions = [System.Collections.Generic.List[pscustomobject]]::new()
    $current = $null
    foreach ($line in $r.Output) {
        if ($line -match '^\s*Session ID:\s*(\d+)') {
            $current = [pscustomobject]@{ Id = [int]$Matches[1]; Name = '' }
            $sessions.Add($current)
        }
        elseif ($null -ne $current -and $line -match '^\s*name:\s*(.+?)\s*$') {
            $current.Name = $Matches[1]
        }
    }
    $sessions.ToArray()
}

function Start-TraceSession {
    <#
        Starts a named trace session; blocks until the session is stopped (trace_stop.ps1 in a second
        window). The state file is written before the call and removed when fbtracemgr returns.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject]$Config,
        [Parameter(Mandatory)] [string]$ScriptRoot,
        [datetime]$Timestamp = (Get-Date)
    )

    $stamp = $Timestamp.ToString('yyyyMMdd_HHmmss')
    $sessionName = "$($Config.SessionName)_$stamp"
    $logFile = Join-Path $Config.OutputDirectory "trace_output_$stamp.log"
    $statePath = Get-TraceStatePath -ScriptRoot $ScriptRoot

    if (Test-Path -LiteralPath $statePath) {
        $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        throw [TraceException]::new($script:EXIT_CONFIG_INVALID,
            "Es gibt noch eine gemerkte Sitzung '$($old.SessionName)' (Log: $($old.LogFile)). Erst mit trace_stop.ps1 " +
            "beenden oder $($script:STATE_FILE_NAME) loeschen, wenn sie sicher nicht mehr laeuft.")
    }
    if (-not $PSCmdlet.ShouldProcess($sessionName, 'Trace-Sitzung starten')) {
        return
    }

    [pscustomobject]@{ SessionName = $sessionName; LogFile = $logFile; StartedAt = $Timestamp.ToString('s') } |
        ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

    $logon = if ($Config.UseTrustedAuth) { 'Windows (TRUSTED)' } else { "$($Config.Username) mit Passwortdatei" }
    if ($Config.Role) { $logon += ", Rolle $($Config.Role)" }
    Write-Information "Trace-Sitzung : $sessionName"
    Write-Information "Log-Datei     : $logFile"
    Write-Information "Konfiguration : $($Config.TraceConfigPath)"
    Write-Information "Anmeldung     : $logon"
    Write-Information 'Trace laeuft. Dieses Fenster offen lassen.'
    Write-Information "Stoppen in einem zweiten Fenster mit: pwsh -File `"$(Join-Path $ScriptRoot 'trace_stop.ps1')`""

    $arguments = @('-SE', $script:SERVICE_MANAGER) + (Get-TraceAuthArgumentList -Config $Config) +
        @('-START', '-NAME', $sessionName, '-CONFIG', $Config.TraceConfigPath)
    try {
        $r = Invoke-FbTraceMgr -FilePath $Config.FbTraceMgr -ArgumentList $arguments -OutFile $logFile
    }
    finally {
        # The session is over once fbtracemgr returns (stopped, failed or interrupted)
        Remove-Item -LiteralPath $statePath -ErrorAction SilentlyContinue
    }

    $bytes = if (Test-Path -LiteralPath $logFile) { (Get-Item -LiteralPath $logFile).Length } else { [long]0 }
    if ($r.ExitCode -ne 0) {
        throw [TraceException]::new($script:EXIT_FBTRACEMGR_ERROR,
            "fbtracemgr endete mit Exit-Code $($r.ExitCode). Log ($bytes Bytes): $logFile")
    }
    [pscustomobject]@{ SessionName = $sessionName; LogFile = $logFile; Bytes = [long]$bytes }
}

function Stop-TraceSession {
    <#
        Stops the session started by trace_start.ps1. Order: -Id, else the ID in the first line of the
        remembered log file, else "fbtracemgr -LIST" by session name (remembered name or prefix from config.json).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject]$Config,
        [Parameter(Mandatory)] [string]$ScriptRoot,
        [int]$Id
    )

    $statePath = Get-TraceStatePath -ScriptRoot $ScriptRoot
    $state = $null
    $logFile = ''
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $logFile = [string]$state.LogFile
        Write-Information "Gemerkte Sitzung: $($state.SessionName) (Log: $logFile)"
    }

    if (-not $Id -and $logFile -and (Test-Path -LiteralPath $logFile)) {
        $first = Get-Content -LiteralPath $logFile -TotalCount 1
        if ("$first" -match $script:SESSION_STARTED_PATTERN) { $Id = [int]$Matches[1] }
    }

    if (-not $Id) {
        $prefix = if ($null -ne $state) { [string]$state.SessionName } else { $Config.SessionName }
        $found = @(Get-TraceSessionList -Config $Config | Where-Object { $_.Name -like "$prefix*" })
        if ($found.Count -eq 0) {
            Remove-Item -LiteralPath $statePath -ErrorAction SilentlyContinue
            throw [TraceException]::new($script:EXIT_NO_SESSION_FOUND,
                "Keine laufende Trace-Sitzung mit Namen '$prefix*' gefunden (alle Sitzungen: fbtracemgr ... -LIST).")
        }
        if ($found.Count -gt 1) {
            $list = ($found | ForEach-Object { "$($_.Id) $($_.Name)" }) -join ', '
            throw [TraceException]::new($script:EXIT_NO_TRACE_ID,
                "Mehrere passende Sitzungen: $list. Gezielt stoppen: trace_stop.ps1 -Id <Nummer>")
        }
        $Id = $found[0].Id
    }

    if (-not $PSCmdlet.ShouldProcess("Trace-ID $Id", 'Trace-Sitzung stoppen')) {
        return
    }
    Write-Information "Stoppe Trace-ID $Id ..."
    $arguments = @('-SE', $script:SERVICE_MANAGER) + (Get-TraceAuthArgumentList -Config $Config) + @('-STOP', '-ID', "$Id")
    $r = Invoke-FbTraceMgr -FilePath $Config.FbTraceMgr -ArgumentList $arguments
    if ($r.ExitCode -ne 0 -or ($r.Output -join ' ') -notmatch "Trace session ID $Id stopped") {
        throw [TraceException]::new($script:EXIT_FBTRACEMGR_ERROR,
            "Stoppen nicht bestaetigt (Exit-Code $($r.ExitCode)): $($r.Output -join ' '). Mit fbtracemgr -LIST pruefen.")
    }
    Remove-Item -LiteralPath $statePath -ErrorAction SilentlyContinue
    [pscustomobject]@{ Id = $Id; LogFile = $logFile }
}

function Resolve-TraceExitCode {
    <# Writes the error message and returns the exit code for 'exit' in the calling script. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $ex = $ErrorRecord.Exception
    $code = if ($ex -is [TraceException]) { $ex.ExitCode } else { $script:EXIT_UNEXPECTED }
    $text = if ($code -eq $script:EXIT_UNEXPECTED) { "Unerwarteter Fehler: $($ex.Message)" } else { $ex.Message }
    foreach ($line in ($text -split '\r?\n')) {
        # Error channel without stopping the script; the caller ends it with the exit code
        $Host.UI.WriteErrorLine("FEHLER: $line")
    }
    $code
}
