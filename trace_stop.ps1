# siehe: https://ib-aid.com/articles/wie-analysiert-man-firebird-traces-mit-ibsurgeon-performance-analysis

# Config laden
$ScriptDir = $PSScriptRoot
$ConfigPath = Join-Path $ScriptDir "config.json"
Write-Host("Config Pfad: $ConfigPath")
if (-not (Test-Path $ConfigPath)) { 
    Write-Error "KRITISCH: config.json fehlt!"
    exit 1 
}
try {
    $Config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
}
catch {
    Write-Error "KRITISCH: config.json ist kein gültiges JSON."
    exit 2
}

$MyUser = $Config.Firebird.Username
$MyPass = $Config.Firebird.Password
$MyPfad = $Config.Firebird.FirebirdPath

# Neueste Logdatei ermitteln
$LogFile = Get-ChildItem -Path "E:\*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (-not $LogFile) {
    Write-Host "Keine Logdatei gefunden" -ForegroundColor Red
    exit 1
}

Write-Host "Datei: $($LogFile.FullName)"

# Erste Zeile lesen und Trace-ID extrahieren
$FirstLine = Get-Content -Path $LogFile.FullName -TotalCount 1

if ($FirstLine -match "Trace session ID (\d+) started") {
    $MyTraceId = $Matches[1]
    Write-Host "Trace-ID: $MyTraceId"
    
    Write-Host "Stoppe Trace..."
    & "$MyPfad\fbtracemgr" -SE service_mgr -USER $MyUser -PASS $MyPass -STOP -ID $MyTraceId
}
else {
    Write-Host "Konnte Trace-ID nicht aus erster Zeile extrahieren:" -ForegroundColor Red
    Write-Host $FirstLine
    exit 1
}