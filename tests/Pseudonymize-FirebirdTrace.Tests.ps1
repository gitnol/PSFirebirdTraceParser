#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
<#
    Tests fuer Pseudonymize-FirebirdTrace.ps1.
    Bisher nur der Teil fuer Fehlermeldungen (I10); die uebrigen Felder folgen mit I2.
#>

BeforeAll {
    $script:Pseudo = Join-Path $PSScriptRoot '..' 'Pseudonymize-FirebirdTrace.ps1'

    function Get-TestErrorEntry([string]$Messages) {
        [pscustomobject]@{
            Action = 'ERROR'; ErrorSource = 'JStatement::execute'
            ErrorCodes = '335544665, 335545072'; ErrorMessages = $Messages
            User = 'APPUSER:NONE'; ApplicationPath = $null; ClientIP = '192.0.2.10'; ProtocolInfo = $null
            Params = $null; SqlStatement = $null
        }
    }

    # Ein Statement-Eintrag wie Show-TraceStructure ihn liefert (ausgedachte Werte)
    function Get-TestStatement([string]$Sql = "SELECT * FROM CUSTOMER WHERE NAME = 'Mueller'") {
        [pscustomobject]@{
            Timestamp = '2026-11-07T10:00:01.1230'; Action = 'EXECUTE_STATEMENT_FINISH'; ProcessID = '4321'
            SessionID = '000001A2B3C4D5E0'; DatabasePath = 'D:\Kunden\Mustermann_GmbH\ERP.FDB'; AttachID = '12'
            User = 'MMUSTERMANN:NONE'; ProtocolInfo = 'TCPv4:192.0.2.10/50123'; ClientIP = '192.0.2.10'; ClientPort = '50123'
            ApplicationPath = 'C:\Users\mmustermann\app.exe'; ApplicationPID = '5678'; TransactionID = '345'; RootTxID = '340'
            TransactionOptions = 'CONCURRENCY | WAIT | READ_WRITE'; Params = 'param0 = varchar(20), "Mueller"'
            SqlStatement = $Sql; SqlPlan = 'PLAN (CUSTOMER NATURAL)'; TableStats = $null
            DurationMs = 12; Reads = 3; Writes = 0; Fetches = 45; Marks = 0
            ErrorSource = $null; ErrorCodes = $null; ErrorMessages = $null
        }
    }
}

Describe 'Pseudonymize-FirebirdTrace: Grundverhalten (Charakterisierung, I2)' {
    BeforeAll {
        $script:In = Get-TestStatement
        $script:Out = $script:In | & $script:Pseudo
    }

    It 'veraendert das Eingabeobjekt nicht' {
        $script:In.User     | Should -BeExactly 'MMUSTERMANN:NONE'
        $script:In.ClientIP | Should -BeExactly '192.0.2.10'
    }

    It 'pseudonymisiert Benutzer, IP und Anwendung' {
        $script:Out.User            | Should -Not -Match 'MMUSTERMANN'
        $script:Out.ClientIP        | Should -Not -Match '192\.0\.2'
        $script:Out.ApplicationPath | Should -Not -Match 'mmustermann'
        $script:Out.User            | Should -Match '^[0-9a-f]{12}$'
    }

    It 'pseudonymisiert die IP in ProtocolInfo und behaelt Protokoll und Port' {
        $script:Out.ProtocolInfo | Should -Match '^TCPv4:[0-9a-f]{12}/50123$'
    }

    It 'pseudonymisiert Parameterwerte und behaelt den Typ' {
        $script:Out.Params | Should -Match '^param0 = varchar\(20\), "[0-9a-f]{12}"$'
    }

    It 'laesst Zeichenketten im SQL ohne Schalter stehen' {
        $script:Out.SqlStatement | Should -BeExactly "SELECT * FROM CUSTOMER WHERE NAME = 'Mueller'"
    }

    It 'pseudonymisiert Zeichenketten im SQL mit -RedactLiterals und behaelt den Operator' {
        $o = Get-TestStatement | & $script:Pseudo -RedactLiterals
        $o.SqlStatement | Should -Match "^SELECT \* FROM CUSTOMER WHERE NAME = '<HASH:[0-9a-f]{12}>'$"
    }

    It 'pseudonymisiert Zeichenketten mit Stichwort aus -SensitiveKeywords' {
        $o = Get-TestStatement "SELECT * FROM T WHERE N = 'GeheimProjekt'" | & $script:Pseudo -SensitiveKeywords 'GeheimProjekt'
        $o.SqlStatement | Should -Not -Match 'GeheimProjekt'
    }

    It 'gibt gleichen Werten im selben Lauf das gleiche Pseudonym' {
        $a, $b = (Get-TestStatement), (Get-TestStatement) | & $script:Pseudo
        $a.User | Should -BeExactly $b.User
    }

    It 'beachtet -HashLength' {
        $o = Get-TestStatement | & $script:Pseudo -HashLength 20
        $o.User | Should -Match '^[0-9a-f]{20}$'
    }

    It 'gibt mit -AnalyzeOnly keine Trace-Objekte aus' {
        $o = Get-TestStatement | & $script:Pseudo -AnalyzeOnly 6>$null
        $o | Should -BeNullOrEmpty
    }

    It 'laesst Kennzahlen, Plan und Zeitstempel unveraendert' {
        $script:Out.DurationMs | Should -Be 12
        $script:Out.SqlPlan    | Should -BeExactly 'PLAN (CUSTOMER NATURAL)'
        $script:Out.Timestamp  | Should -BeExactly '2026-11-07T10:00:01.1230'
    }
}

Describe 'Pseudonymize-FirebirdTrace: Klartext-Luecken (I2)' {
    It 'pseudonymisiert den Datenbankpfad' {
        $o = Get-TestStatement | & $script:Pseudo
        $o.DatabasePath | Should -Not -Match 'Mustermann'
        $o.DatabasePath | Should -Match '^[0-9a-f]{12}$'
    }

    It 'pseudonymisiert Zahlen im SQL mit -RedactLiterals' {
        $o = Get-TestStatement 'SELECT * FROM ORDERS WHERE CUSTOMER_NO = 4711 AND AMOUNT > 99.5' | & $script:Pseudo -RedactLiterals
        $o.SqlStatement | Should -Not -Match '4711|99\.5'
        $o.SqlStatement | Should -Match '^SELECT \* FROM ORDERS WHERE CUSTOMER_NO = <HASH:[0-9a-f]{12}> AND AMOUNT > <HASH:[0-9a-f]{12}>$'
    }

    It 'laesst Ziffern in Bezeichnern und in Pseudonymen stehen' {
        $o = Get-TestStatement "SELECT COL1 FROM TAB_2024 WHERE X = 'ab'" | & $script:Pseudo -RedactLiterals
        $o.SqlStatement | Should -Match '^SELECT COL1 FROM TAB_2024 WHERE X = ''<HASH:[0-9a-f]{12}>''$'
    }

    It 'pseudonymisiert mit -RedactLiterals auch einzelne Zeichen, aber keine reinen Platzhalter' {
        # Einzelzeichen sind oft personenbezogen (z. B. Geschlecht 'W'); '%' allein ist kein Wert
        $o = Get-TestStatement "SELECT * FROM P WHERE G = 'W' AND N LIKE '%'" | & $script:Pseudo -RedactLiterals
        $o.SqlStatement | Should -Match "^SELECT \* FROM P WHERE G = '<HASH:[0-9a-f]{12}>' AND N LIKE '%'$"
    }

    It 'laesst Zahlen ohne -RedactLiterals stehen' {
        $o = Get-TestStatement 'SELECT * FROM ORDERS WHERE CUSTOMER_NO = 4711' | & $script:Pseudo
        $o.SqlStatement | Should -BeExactly 'SELECT * FROM ORDERS WHERE CUSTOMER_NO = 4711'
    }

    It 'schwaerzt bei -SensitiveKeywords (Tabellenname) alle WHERE-Klauseln ab der ersten, auch in Unterabfragen' {
        # Stichwort ausserhalb von Literalen (Tabellenname) loest die Klausel-Schwaerzung aus; vorher blieb alles bis zur
        # letzten WHERE-Klausel sichtbar (hier: die Bedingung der aeusseren Abfrage A.ID IN ...).
        $sql = 'SELECT * FROM A WHERE A.ID IN (SELECT ID FROM GEHEIM_TAB B WHERE B.NAME = ''x'') AND A.KUNDE = 17'
        $o = Get-TestStatement $sql | & $script:Pseudo -SensitiveKeywords 'GEHEIM_TAB'
        $o.SqlStatement | Should -Not -Match 'A\.ID IN|KUNDE = 17|B\.NAME'
        $o.SqlStatement | Should -Match '^SELECT \* FROM A WHERE <REDACTED_CLAUSE:[0-9a-f]{12}>$'
    }
}

Describe 'Pseudonymize-FirebirdTrace: Fehlermeldungen (I10)' {
    It 'hasht mit -RedactLiterals den Schluesselwert, nicht Constraint- und Tabellenname' {
        $msg = 'violation of PRIMARY or UNIQUE KEY constraint "PK_CUSTOMER" on table "CUSTOMER" | Problematic key value is ("ID" = 42)'
        $out = Get-TestErrorEntry $msg | & $script:Pseudo -RedactLiterals
        $out.ErrorMessages | Should -Not -Match '= 42\)'
        $out.ErrorMessages | Should -Match '"ID" = <HASH:[0-9a-f]+>\)'
        $out.ErrorMessages | Should -Match '"PK_CUSTOMER" on table "CUSTOMER"'
    }

    It 'hasht mit -RedactLiterals Zeichenketten-Literale in Fehlertexten' {
        $msg = "conversion error from string 'Mueller GmbH'"
        $out = Get-TestErrorEntry $msg | & $script:Pseudo -RedactLiterals
        $out.ErrorMessages | Should -Not -Match 'Mueller'
        $out.ErrorMessages | Should -Match "'<HASH:[0-9a-f]+>'"
    }

    It 'hasht Schluesselwerte mit mehreren Spalten einzeln' {
        $msg = 'Problematic key value is ("A" = 1, "B" = ''x y'')'
        $out = Get-TestErrorEntry $msg | & $script:Pseudo -RedactLiterals
        $out.ErrorMessages | Should -Match '^Problematic key value is \("A" = <HASH:[0-9a-f]+>, "B" = <HASH:[0-9a-f]+>\)$'
    }

    It 'laesst Fehlertexte ohne -RedactLiterals unveraendert' {
        $msg = 'Problematic key value is ("ID" = 42)'
        $out = Get-TestErrorEntry $msg | & $script:Pseudo
        $out.ErrorMessages | Should -Be $msg
    }

    It 'laesst Fehlercodes unveraendert' {
        $out = Get-TestErrorEntry 'deadlock' | & $script:Pseudo -RedactLiterals
        $out.ErrorCodes | Should -Be '335544665, 335545072'
    }
}
