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
