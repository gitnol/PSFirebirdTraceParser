# siehe: https://ib-aid.com/articles/wie-analysiert-man-firebird-traces-mit-ibsurgeon-performance-analysis

# Config laden
$ConfigPath = Join-Path $ScriptDir "config.json"
if (-not (Test-Path $ConfigPath)) { 
    Write-Error "KRITISCH: config.json fehlt!"
    Stop-Transcript
    exit 1 
}
try {
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "KRITISCH: config.json ist kein gültiges JSON."
    Stop-Transcript
    exit 1
}

$MyUser = $Config.Firebird.Username
$MyPass = $Config.Firebird.Password
$MyPfad = $Config.Firebird.FirebirdPath

$TraceConfig = Join-Path $PSScriptRoot "fbtrace30.conf"

# Zeitstempel erzeugen (YYYYMMDD_HHMMSS)
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host $Stamp

$LogOutput = "E:\trace_output_$Stamp.log"

Write-Host "Bitte ermittle die Trace ID aus dem Kopf der Log Datei unter $LogOutput"
Write-Host "Trace gestartet, Ausgabe in $LogOutput"
Write-Host "Trace stoppen mit $($PSScriptRoot)\trace-stop.ps1"

& "$MyPfad\fbtracemgr" -SE service_mgr -USER $MyUser -PASS $MyPass -START -CONFIG $TraceConfig > $LogOutput