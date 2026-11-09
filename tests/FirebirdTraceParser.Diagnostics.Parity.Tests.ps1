#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Paritaet der Diagnose (I18, ADR-003): Warnungen mit Zeilennummer, Text vor dem ersten Ereignis, -MaxBlockLines,
    -RegexTimeoutSeconds, Zusammenfassung mit -Verbose und CRLF/LF-Mischungen. Beide Parser muessen dieselben Objekte,
    Warnungen und Verbose-Meldungen liefern (Zeitangabe ausgenommen). Eingaben wie in
    Show-TraceStructure.Diagnostics.Tests.ps1, im TestDrive. Nur PowerShell 7. Werte ausgedacht, IPs aus 192.0.2.0/24.
#>

BeforeDiscovery {
    $script:FixtureNames = @(Get-ChildItem -Path ([System.IO.Path]::Combine($PSScriptRoot, 'fixtures')) -Filter '*.log' | ForEach-Object Name)
    $conn = "`tC:\DATA\SAMPLE.FDB (ATT_9, APPUSER:NONE, UTF8, TCPv4:192.0.2.90/50900)"
    $start = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION'
    $script:Cases = @(
        @{ Name = 'bad_header'; Params = @{}; Lines = @('Trace session ID 1 started', '', $start, $conn, '', '2026-11-08T10:00:01.0000 garbled header without process', $conn, '') }
        @{ Name = 'two_bad'; Params = @{}; Lines = @($start, $conn, '', '2026-11-08T10:00:01.0000 garbled one', '', '2026-11-08T10:00:02.0000 garbled two', '', '2026-11-08T10:00:03.0000 (4321:000001A2B3C4D5E0) COMMIT_TRANSACTION', $conn, '') }
        @{ Name = 'unknown_event'; Params = @{}; Lines = @('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) Unknown event in ATTACH_DATABASE', $conn, '') }
        @{ Name = 'unknown_event_lowercase'; Params = @{}; Lines = @('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) UNKNOWN', '') }
        @{ Name = 'preamble'; Params = @{}; Lines = @('Trace session ID 2 started', '', 'some stray text', $start, $conn, '') }
        @{ Name = 'start_line_lowercase'; Params = @{}; Lines = @('trace session id 4 started', $start, '') }
        @{ Name = 'no_events'; Params = @{}; Lines = @('this is not a trace', 'second line') }
        @{ Name = 'only_start_line'; Params = @{}; Lines = @('Trace session ID 3 started', '   ') }
        @{ Name = 'summary_order'; Params = @{}; Lines = @($start, $conn, '', ($start -replace '10:00:00', '10:00:01'), '', '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) COMMIT_TRANSACTION', '', '2026-11-08T10:00:03.0000 (4321:000001A2B3C4D5E0) ATTACH_DATABASE', '', '2026-11-08T10:00:04.0000 garbled', '') }
        @{ Name = 'summary_order_underscore'; Params = @{}; Lines = @('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) TEST_A', '', '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) TESTB', '', '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) testc', '') }
        # Kelvin sign U+212A and Angstrom sign U+212B: equal to K / A-ring with the culture comparer, different with
        # OrdinalIgnoreCase, which @{} uses under PowerShell 7 (I23). Built from char codes to keep the file ASCII.
        @{ Name = 'summary_key_kelvin'; Params = @{}; Lines = @(
                "2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) TEST$([char]::ConvertFromUtf32(0x212A))", '',
                '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) TESTK', '',
                '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) TESTk', '',
                "2026-11-08T10:00:03.0000 (4321:000001A2B3C4D5E0) TEST$([char]::ConvertFromUtf32(0x212B))", '',
                "2026-11-08T10:00:04.0000 (4321:000001A2B3C4D5E0) TEST$([char]::ConvertFromUtf32(0x00C5))", '',
                "2026-11-08T10:00:05.0000 (4321:000001A2B3C4D5E0) TEST$([char]::ConvertFromUtf32(0x00E5))", '')
        }
        @{ Name = 'long_block_cut'; Params = @{ MaxBlockLines = 5 }; Lines = @(
                $start, $conn, '', '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn
            ) + @(1..20 | ForEach-Object { "param$_ = integer, ""$_""" }) + @('      7 ms', '', '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) COMMIT_TRANSACTION', $conn, '')
        }
        @{ Name = 'block_at_limit'; Params = @{ MaxBlockLines = 3 }; Lines = @('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $conn, '      7 ms') }
        @{ Name = 'last_block_cut_without_newline'; Params = @{ MaxBlockLines = 2 }; Lines = @($start, $conn, 'x', 'y') }
    )
}

BeforeAll {
    . ([System.IO.Path]::Combine($PSScriptRoot, 'TraceParity.ps1'))
    $script:Fixtures = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
    $script:Dll = Get-TraceParserAssembly
    if ($PSVersionTable.PSEdition -eq 'Core' -and (Test-Path -LiteralPath $script:Dll)) { Import-Module -Name $script:Dll -Verbose:$false }
    $script:Conn = "`tC:\DATA\SAMPLE.FDB (ATT_9, APPUSER:NONE, UTF8, TCPv4:192.0.2.90/50900)"

    function Compare-Engine([string]$Path, [hashtable]$Params = @{}) {
        Compare-TraceRun -Expected (Invoke-TraceEngine PowerShell $Path $Params) -Actual (Invoke-TraceEngine CSharp $Path $Params)
    }
}

Describe 'Paritaet PowerShell- und C#-Parser: Diagnose (I18)' -Skip:($PSVersionTable.PSEdition -ne 'Core') {
    It 'liefert fuer <Name> dieselben Objekte, Warnungen und Verbose-Meldungen' -ForEach $script:Cases {
        $f = Join-Path $TestDrive "$Name.log"
        [System.IO.File]::WriteAllText($f, ($Lines -join "`n") + $(if ($Name -notlike '*without_newline') { "`n" }))
        $ps = Invoke-TraceEngine PowerShell $f $Params
        Compare-TraceRun -Expected $ps -Actual (Invoke-TraceEngine CSharp $f $Params) | Should -BeNullOrEmpty
    }

    It 'liefert fuer das Fixture <_> mit CRLF und mit gemischten Zeilenenden dasselbe' -ForEach $script:FixtureNames {
        $lines = [System.IO.File]::ReadAllText((Join-Path $script:Fixtures $_)).Split("`n")
        $crlf = Join-Path $TestDrive "crlf_$_"
        [System.IO.File]::WriteAllText($crlf, ($lines -join "`r`n"))
        Compare-Engine $crlf | Should -BeNullOrEmpty
        $mixed = Join-Path $TestDrive "mixed_$_"
        $text = [System.Text.StringBuilder]::new()
        for ($i = 0; $i -lt $lines.Count; $i++) { $null = $text.Append($lines[$i]).Append($(if ($i % 2) { "`r`n" } else { "`n" })) }
        [System.IO.File]::WriteAllText($mixed, $text.ToString())
        Compare-Engine $mixed | Should -BeNullOrEmpty
    }

    It 'zaehlt die Zeilen ueber die 4-MB-Stuecke hinweg gleich' {
        $sql = 'SELECT ' + ('X' * 60000) + ' FROM T'
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($i in 1..90) {
            $lines.AddRange([string[]]@('2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH', $script:Conn, '', "Statement $($i):", ('-' * 79), $sql, '', '      1 ms', ''))
        }
        $lines.AddRange([string[]]@('2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) Unknown event in DETACH_DATABASE', $script:Conn, ''))
        $f = Join-Path $TestDrive 'chunks.log'
        [System.IO.File]::WriteAllText($f, ($lines -join "`n") + "`n")
        Compare-Engine $f | Should -BeNullOrEmpty
    }

    It 'zaehlt zwei Warnungen in verschiedenen Stuecken gleich (zweite weiter hinten im Stueck als die erste)' {
        $sql = 'SELECT ' + ('X' * 60000) + ' FROM T'
        $lines = [System.Collections.Generic.List[string]]::new()
        foreach ($i in 1..95) {
            $head = if ($i -eq 5 -or $i -eq 90) { 'Unknown event in DETACH_DATABASE' } else { 'EXECUTE_STATEMENT_FINISH' }
            $lines.AddRange([string[]]@("2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) $head", $script:Conn, '', "Statement $($i):", ('-' * 79), $sql, '', '      1 ms', ''))
        }
        $f = Join-Path $TestDrive 'two_chunks.log'
        [System.IO.File]::WriteAllText($f, ($lines -join "`n") + "`n")
        Compare-Engine $f | Should -BeNullOrEmpty
    }

    It 'kuerzt einen Block ueber mehrere 4-MB-Stuecke gleich und zaehlt danach gleich' {
        $f = Join-Path $TestDrive 'huge_block.log'
        $text = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + ("xx`n" * 2000000) +
        '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) Unknown event in DETACH_DATABASE' + "`n" + $script:Conn + "`n" +
        '2026-11-08T10:00:02.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n"
        [System.IO.File]::WriteAllText($f, $text)
        Compare-Engine $f @{ MaxBlockLines = 1000 } | Should -BeNullOrEmpty
    }

    It 'zaehlt nach einem gekuerzten Block auch Stuecke spaeter gleich' {
        $f = Join-Path $TestDrive 'cut_then_more.log'
        $sql = 'SELECT ' + ('X' * 60000) + ' FROM T'
        $more = [System.Text.StringBuilder]::new()
        foreach ($i in 1..90) {
            $null = $more.Append("2026-11-08T10:00:03.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH`n$($script:Conn)`n`nStatement $($i):`n$('-' * 79)`n$sql`n`n      1 ms`n`n")
        }
        $text = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + ("xx`n" * 2000000) + $more.ToString() +
        '2026-11-08T10:00:09.0000 (4321:000001A2B3C4D5E0) Unknown event in DETACH_DATABASE' + "`n" + $script:Conn + "`n"
        [System.IO.File]::WriteAllText($f, $text)
        Compare-Engine $f @{ MaxBlockLines = 1000 } | Should -BeNullOrEmpty
    }

    It 'liest ein Ereignis mit 300000 Zeilen in beiden Parsern schnell (K8, Standard -MaxBlockLines)' {
        # Vor I21: Zeilensuche kulturabhaengig, Laufzeit quadratisch (gemessen ~45 s je Parser); danach Sekundenbruchteile.
        # Grenze 15 s mit grossem Abstand zu beiden (L10).
        $f = Join-Path $TestDrive 'many_lines.log'
        [System.IO.File]::WriteAllText($f, '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + ("xx`n" * 300000) +
            '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n")
        foreach ($engine in 'PowerShell', 'CSharp') {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-TraceEngine $engine $f
            $sw.Stop()
            $r.Objects.Count | Should -Be 2
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 15 -Because "$engine darf bei vielen Zeilen nicht quadratisch werden"
        }
        Compare-Engine $f | Should -BeNullOrEmpty
    }

    It 'kuerzt Text ohne Zeitstempel ueber mehrere Stuecke gleich (Vorspann)' {
        $f = Join-Path $TestDrive 'huge_preamble.log'
        [System.IO.File]::WriteAllText($f, ("noise`n" * 1000000) + '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n")
        Compare-Engine $f @{ MaxBlockLines = 500 } | Should -BeNullOrEmpty
    }

    It 'bricht eine zu lange Regex-Auswertung gleich ab (deterministisch: Rueckverfolgen ueber 90000 Zeilen)' {
        # Zeitlimit 0,5 s statt 1 ms: bei 1 ms laufen auch kleine Bloecke gelegentlich ins Limit (gemessen, 1 von 3
        # Laeufen) - das waere Zufall, kein Unterschied der Parser. Die Suche im grossen Block braucht viel laenger.
        $f = Join-Path $TestDrive 'slow.log'
        $text = '2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH' + "`n" + $script:Conn + "`n`n" +
        "Statement 1:`n" + ('-' * 79) + "`n" + 'SELECT 1' + ("`n     " * 90000) + 'Y' + "`n" +
        '2026-11-08T10:00:01.0000 (4321:000001A2B3C4D5E0) START_TRANSACTION' + "`n" + $script:Conn + "`n"
        [System.IO.File]::WriteAllText($f, $text)
        $p = @{ RegexTimeoutSeconds = 0.5 }
        $ps = Invoke-TraceEngine PowerShell $f $p
        @($ps.Warnings | Where-Object { $_ -match 'time limit' }).Count | Should -Be 1 -Because 'sonst prueft der Test kein Zeitlimit'
        Compare-TraceRun -Expected $ps -Actual (Invoke-TraceEngine CSharp $f $p) | Should -BeNullOrEmpty
    }
}

Describe 'Annahme zum Vergleich der Hashtable-Schluessel (I23, ADR-003)' {
    # Ratsche: die Annahme des C#-Parsers ueber `@{}` wird hier am Verhalten gemessen, nicht nur im Code behauptet.
    # PowerShell 7: OrdinalIgnoreCase, Windows PowerShell 5.1: kulturabhaengig (Kelvin-Zeichen gleich K).
    # Kein Zugriff auf private Felder per Reflection: loeste Heuristiken von Virenscannern aus (False Positive).

    It 'unterscheidet unter PowerShell 7 Gross- und Kleinschreibung nicht' -Skip:($PSVersionTable.PSEdition -ne 'Core') {
        $h = @{ K = 1 }
        $h['k'] | Should -Be 1
    }

    It 'haelt K und das Kelvin-Zeichen unter PowerShell 7 getrennt, unter 5.1 nicht' {
        $h = @{ K = 1 }
        $h[[char]::ConvertFromUtf32(0x212A)] = 2
        $h.Count | Should -Be $(if ($PSVersionTable.PSEdition -eq 'Core') { 2 } else { 1 })
    }
}
