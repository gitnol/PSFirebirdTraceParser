#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer Robustheit und Diagnose des Parsers (I13): Warnungen mit Zeilennummer fuer Bloecke, die sich nicht
    zuordnen lassen, Zusammenfassung je Action mit -Verbose, Zeitlimit fuer die Regex-Auswertung und Obergrenze der
    Zeilen je Block. Die Pipeline-Ausgabe darf sich ohne Befund nicht aendern. Eingaben im TestDrive, Werte ausgedacht,
    IPs aus 192.0.2.0/24.
#>

BeforeAll {
    $script:Parser = [System.IO.Path]::Combine($PSScriptRoot, '..', 'Show-TraceStructure.ps1')
    $script:Fixtures = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
    $script:Conn = "`tC:\DATA\SAMPLE.FDB (ATT_9, APPUSER:NONE, UTF8, TCPv4:192.0.2.90/50900)"

    function New-TraceFile([string]$Name, [string[]]$Lines) {
        $f = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($f, (($Lines -join "`n") + "`n"))
        $f
    }
    # Runs the parser and splits pipeline objects, warnings and verbose messages
    function Invoke-Parser([string]$Path, [hashtable]$More = @{}) {
        $all = @(& $script:Parser -Path $Path @More -Verbose 3>&1 4>&1 6>$null)
        [PSCustomObject]@{
            Objects = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.VerboseRecord] })
            Warnings = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message)
            Verbose = @($all | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object Message)
        }
    }
}

Describe 'Show-TraceStructure: Warnungen mit Zeilennummer (I13)' {
    It 'meldet bei den mitgelieferten Fixtures keine Warnung' {
        foreach ($f in Get-ChildItem -LiteralPath $script:Fixtures -Filter '*.log') {
            (Invoke-Parser $f.FullName).Warnings | Should -BeNullOrEmpty -Because $f.Name
        }
    }

    It 'meldet eine unlesbare Kopfzeile mit Zeilennummer und gibt das Objekt trotzdem aus' {
        $f = New-TraceFile 'bad_header.log' @(
            'Trace session ID 1 started', ''
            '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $script:Conn, ''
            '2026-11-08T10:00:01.0000 garbled header without process', $script:Conn, ''
        )
        $r = Invoke-Parser $f
        $r.Objects.Count | Should -Be 2
        $r.Objects[1].Action | Should -BeNullOrEmpty
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match '\bline 6\b'
        $r.Warnings[0] | Should -Match 'header'
    }

    It 'meldet unbekannte Ereignisse ("Unknown event ...") mit Zeilennummer' {
        $f = New-TraceFile 'unknown.log' @(
            '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) Unknown event in ATTACH_DATABASE', $script:Conn, ''
        )
        $r = Invoke-Parser $f
        $r.Objects.Count | Should -Be 1
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match '\bline 1\b'
        $r.Warnings[0] | Should -Match 'Unknown event in ATTACH_DATABASE'
    }

    It 'meldet Text vor dem ersten Ereignis, aber nicht die Startzeile von fbtracemgr' {
        $f = New-TraceFile 'preamble.log' @(
            'Trace session ID 2 started', '', 'some stray text'
            '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $script:Conn, ''
        )
        $r = Invoke-Parser $f
        $r.Objects.Count | Should -Be 1
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match '\bline 1\b'
        $r.Warnings[0] | Should -Match 'skipped'
    }

    It 'meldet eine Datei ohne Ereignis' {
        $f = New-TraceFile 'no_events.log' @('this is not a trace', 'second line')
        $r = Invoke-Parser $f
        $r.Objects.Count | Should -Be 0
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match 'skipped'
    }

    It 'zaehlt die Zeilen ueber die 4-MB-Stuecke hinweg richtig' {
        $sql = 'SELECT ' + ('X' * 60000) + ' FROM T'
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($i in 1..90) {
            $lines.AddRange([string[]]@("2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH", $script:Conn, '', "Statement $($i):", ('-' * 79), $sql, '', '      1 ms', ''))
        }
        $lines.AddRange([string[]]@('2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) Unknown event in DETACH_DATABASE', $script:Conn, ''))
        $f = New-TraceFile 'chunks.log' $lines.ToArray()
        (Get-Item -LiteralPath $f).Length | Should -BeGreaterThan 5MB
        $r = Invoke-Parser $f
        $r.Objects.Count | Should -Be 91
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match "\bline $(90 * 9 + 1)\b"
    }
}

Describe 'Show-TraceStructure: Zusammenfassung mit -Verbose (I13)' {
    It 'nennt die Zahl der Bloecke je Action und die Warnungen' {
        $f = New-TraceFile 'summary.log' @(
            '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $script:Conn, ''
            '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $script:Conn, ''
            '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) COMMIT_TRANSACTION', $script:Conn, ''
            '2026-11-08T10:00:03.0000 garbled', ''
        )
        $v = (Invoke-Parser $f).Verbose
        $v | Should -Contain 'Summary: START_TRANSACTION = 2'
        $v | Should -Contain 'Summary: COMMIT_TRANSACTION = 1'
        $v | Should -Contain 'Summary: (header not readable) = 1'
        $v | Should -Contain 'Summary: 1 warning(s)'
    }

    It 'aendert die Pipeline-Ausgabe nicht (mit und ohne -Verbose gleich)' {
        $f = [System.IO.Path]::Combine($script:Fixtures, 'trace_fb5_windows.log')
        $plain = @(& $script:Parser -Path $f 3>$null 6>$null) | ConvertTo-Json -Depth 4 -Compress
        $verbose = @((Invoke-Parser $f).Objects) | ConvertTo-Json -Depth 4 -Compress
        $verbose | Should -BeExactly $plain
    }
}

Describe 'Show-TraceStructure: Schutz vor sehr langen Bloecken (I13)' {
    It 'kuerzt einen Block auf -MaxBlockLines Zeilen und meldet ihn mit Zeilennummer' {
        $f = New-TraceFile 'long.log' (@(
                '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION', $script:Conn, ''
                '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $script:Conn
            ) + @(1..20 | ForEach-Object { "param$_ = integer, ""$_""" }) + @('      7 ms', ''))
        $r = Invoke-Parser $f @{ MaxBlockLines = 5 }
        $r.Objects.Count | Should -Be 2
        $r.Objects[1].Action | Should -BeExactly 'EXECUTE_STATEMENT_FINISH'
        $r.Objects[1].AttachID | Should -Be '9'
        $r.Objects[1].DurationMs | Should -Be 0
        $r.Objects[1].Params | Should -BeExactly ("param1 = integer, ""1""`nparam2 = integer, ""2""`nparam3 = integer, ""3""")
        $r.Warnings.Count | Should -Be 1
        $r.Warnings[0] | Should -Match '\bline 4\b'
        $r.Warnings[0] | Should -Match 'more than 5 lines'
    }

    It 'laesst Bloecke bis zur Grenze unveraendert' {
        $f = New-TraceFile 'limit.log' @('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $script:Conn, '      7 ms')
        $r = Invoke-Parser $f @{ MaxBlockLines = 4 }
        $r.Objects[0].DurationMs | Should -Be 7
        $r.Warnings | Should -BeNullOrEmpty
    }

    It 'begrenzt einen Block ueber mehrere 4-MB-Stuecke und zaehlt die Zeilen danach richtig' {
        $filler = 'xx' + "`n"
        $f = Join-Path $TestDrive 'huge_block.log'
        $text = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + ($filler * 2000000) +
        '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) Unknown event in DETACH_DATABASE' + "`n" + $script:Conn + "`n"
        [System.IO.File]::WriteAllText($f, $text)
        $r = Invoke-Parser $f @{ MaxBlockLines = 1000 }
        $r.Objects.Count | Should -Be 2
        $r.Objects[1].AttachID | Should -Be '9'
        $r.Warnings.Count | Should -Be 2
        $r.Warnings[0] | Should -Match '\bline 1\b'
        $r.Warnings[0] | Should -Match 'more than 1000 lines'
        $r.Warnings[1] | Should -Match '\bline 2000002\b'
    }

    It 'bricht eine zu lange Regex-Auswertung ab, meldet sie und liest die naechsten Bloecke weiter' {
        $f = Join-Path $TestDrive 'slow.log'
        $text = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH' + "`n" + $script:Conn + "`n`n" +
        "Statement 1:`n" + ('-' * 79) + "`n" + ('Y' * 3000000) + "`n" +
        '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + $script:Conn + "`n"
        [System.IO.File]::WriteAllText($f, $text)
        $r = Invoke-Parser $f @{ RegexTimeoutSeconds = 0.001 }
        $r.Objects.Count | Should -Be 2
        $r.Objects[0].Action | Should -BeExactly 'EXECUTE_STATEMENT_FINISH'
        $r.Objects[0].SqlStatement | Should -BeNullOrEmpty
        $r.Objects[1].Action | Should -BeExactly 'START_TRANSACTION'
        @($r.Warnings | Where-Object { $_ -match 'time limit' }).Count | Should -BeGreaterOrEqual 1
        $r.Warnings[0] | Should -Match '\bline 1\b'
    }

    It 'prueft die Parameter' {
        { & $script:Parser -Path (Join-Path $script:Fixtures 'trace_fb5_windows.log') -MaxBlockLines 0 } | Should -Throw
        { & $script:Parser -Path (Join-Path $script:Fixtures 'trace_fb5_windows.log') -RegexTimeoutSeconds 0 } | Should -Throw
    }
}
