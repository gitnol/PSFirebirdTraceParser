<#
    Shared helpers for the tests of the C# parser (ADR-003): path of the built assembly and a strict comparison of
    parser objects. Strict means: same property names in the same order, same type of every value, $null is not the
    same as an empty string, strings are compared ordinal, TableCounts row by row. Dot-source from a *.Tests.ps1 file.
#>

function Get-TraceParserAssembly {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'bin', 'FirebirdTraceParser.dll'))
}

function Compare-TraceValue {
    # Differences between two values as text lines ("<where>: ..."); nothing when they are equal
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Where,
        # Any parser value: string, number, object[] (TableCounts) or PSCustomObject (one TableCounts row)
        [AllowNull()] [object]$Expected,
        [AllowNull()] [object]$Actual
    )
    if ($null -eq $Expected -and $null -eq $Actual) { return }
    if ($null -eq $Expected -or $null -eq $Actual) { "${Where}: [$Expected] vs [$Actual] (null)"; return }
    if ($Expected.GetType() -ne $Actual.GetType()) {
        "${Where}: type $($Expected.GetType().Name) vs $($Actual.GetType().Name)"; return
    }
    if ($Expected -is [System.Management.Automation.PSObject]) {
        Compare-TraceObject -Where $Where -Expected $Expected -Actual $Actual
        return
    }
    if ($Expected -is [array]) {
        if ($Expected.Count -ne $Actual.Count) { "${Where}: $($Expected.Count) vs $($Actual.Count) element(s)"; return }
        for ($i = 0; $i -lt $Expected.Count; $i++) { Compare-TraceValue -Where "$Where[$i]" -Expected $Expected[$i] -Actual $Actual[$i] }
        return
    }
    if (-not $Expected.Equals($Actual)) { "${Where}: [$Expected] vs [$Actual]" }
}

function Compare-TraceObject {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$Where,
        [Parameter(Mandatory)] [System.Management.Automation.PSObject]$Expected,
        [Parameter(Mandatory)] [System.Management.Automation.PSObject]$Actual
    )
    $names = @($Expected.PSObject.Properties.Name)
    $actualNames = @($Actual.PSObject.Properties.Name)
    if (($names -join ',') -cne ($actualNames -join ',')) { "${Where}: properties [$($names -join ',')] vs [$($actualNames -join ',')]"; return }
    if (($Expected.PSObject.TypeNames -join ',') -cne ($Actual.PSObject.TypeNames -join ',')) { "${Where}: type names differ" }
    foreach ($n in $names) {
        Compare-TraceValue -Where "$Where.$n" -Expected $Expected.PSObject.Properties[$n].Value -Actual $Actual.PSObject.Properties[$n].Value
    }
}

function Compare-TraceOutput {
    # All differences between two parser outputs (lists of objects)
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Expected,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Actual
    )
    if ($Expected.Count -ne $Actual.Count) { "count: $($Expected.Count) vs $($Actual.Count)"; return }
    for ($i = 0; $i -lt $Expected.Count; $i++) { Compare-TraceObject -Where "#$i" -Expected $Expected[$i] -Actual $Actual[$i] }
}
