function Limit-FileSize {
    <#
    .SYNOPSIS
        Kürzt eine Datei auf eine maximale Größe.
    
    .DESCRIPTION
        Diese Funktion prüft die Größe einer Datei und kürzt sie auf die angegebene 
        Maximalgröße, falls sie größer ist. Die Datei wird vom Ende her abgeschnitten.
    
    .PARAMETER Path
        Der vollständige Pfad zur Datei. Unterstützt Pipeline-Input.
    
    .PARAMETER MaxSize
        Die maximale Größe der Datei (z.B. 99MB, 1GB).
    
    .PARAMETER PassThru
        Gibt ein Objekt mit Informationen über die Dateiänderung zurück.
    
    .EXAMPLE
        Limit-FileSize -Path "C:\temp\largefile.log" -MaxSize 99MB
        Kürzt die Datei largefile.log auf maximal 99 MB.
    
    .EXAMPLE
        Limit-FileSize -Path "C:\logs\*.log" -MaxSize 50MB -WhatIf
        Zeigt, welche Log-Dateien gekürzt würden, ohne die Aktion auszuführen.
    
    .EXAMPLE
        Get-ChildItem "C:\logs" -Filter "*.log" | Limit-FileSize -MaxSize 100MB -PassThru
        Kürzt alle Log-Dateien im Verzeichnis auf maximal 100 MB und gibt Details zurück.
    
    #>
    
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateRange(1, [long]::MaxValue)]
        [long]$MaxSize,
        
        [Parameter()]
        [switch]$PassThru
    )
    
    begin {
        Write-Verbose "Starte Dateigrößen-Limitierung auf maximal $($MaxSize) Bytes"
    }
    
    process {
        foreach ($currentItem in $Path) {
            # Sicherstellen, dass wir den Pfad korrekt auflösen (auch bei Pipeline Input)
            # PSPath ist oft sicherer, falls Provider involviert sind, aber hier vereinfacht:
            $filesToProcess = @()
            
            # Fehlerbehandlung, falls Wildcards oder ungültige Pfade übergeben werden
            try {
                # -ErrorAction Stop erzwingt den Sprung in den Catch-Block bei nicht existierenden Dateien
                $filesToProcess = Get-Item -LiteralPath $currentItem -ErrorAction Stop
            }
            catch {
                Write-Error "Die Datei '$($currentItem)' konnte nicht gefunden werden oder Zugriff verweigert: $($_.Exception.Message)"
                continue
            }

            foreach ($file in $filesToProcess) {
                # Ignorieren, falls es ein Ordner ist
                if ($file.PSIsContainer) {
                    Write-Verbose "Überspringe '$($file.FullName)', da es ein Ordner ist."
                    continue
                }

                $filePathFull = $file.FullName
                $originalSize = $file.Length

                Write-Verbose "Prüfe Datei: $($filePathFull) (Aktuelle Größe: $($originalSize) Bytes)"
                
                # Result-Objekt vorbereiten
                $result = [PSCustomObject]@{
                    Path           = $filePathFull
                    OriginalSize   = $originalSize
                    TargetSize     = $MaxSize
                    WasTruncated   = $false
                    NewSize        = $originalSize
                    SizeDifference = 0
                }
                
                if ($originalSize -gt $MaxSize) {
                    $sizeDiff = $originalSize - $MaxSize
                    
                    if ($PSCmdlet.ShouldProcess($filePathFull, "Datei auf $($MaxSize) Bytes kürzen (Differenz: $($sizeDiff))")) {
                        try {
                            # FileStream öffnen
                            $fs = [System.IO.File]::Open($filePathFull, 
                                [System.IO.FileMode]::Open, 
                                [System.IO.FileAccess]::ReadWrite)
                            
                            $fs.SetLength($MaxSize)
                            
                            # Nur Verbose nutzen, kein Write-Host
                            Write-Verbose "Datei '$($filePathFull)' erfolgreich gekürzt."
                            
                            $result.WasTruncated = $true
                            $result.NewSize = $MaxSize
                            $result.SizeDifference = $sizeDiff
                            
                        }
                        catch {
                            Write-Error "Fehler beim Kürzen der Datei '$($filePathFull)': $($_.Exception.Message)"
                        }
                        finally {
                            if ($fs) {
                                $fs.Close()
                                $fs.Dispose()
                            }
                        }
                    }
                }
                else {
                    Write-Verbose "Datei '$($filePathFull)' ist bereits klein genug."
                }
                
                if ($PassThru) {
                    Write-Output $result
                }
            }
        }
    }
    
    end {
        Write-Verbose "Vorgang abgeschlossen."
    }
}