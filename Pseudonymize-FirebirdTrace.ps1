<#
.SYNOPSIS
    Pseudonymizes Firebird Trace Data for secure sharing.

.DESCRIPTION
    Hashes sensitive information (User, IP, String Literals) while preserving
    SQL structure and context. Supports "Analyze Only" mode for previewing
    redaction impact.

.PARAMETER SensitiveKeywords
    List of specific literal values to always hash.

.PARAMETER RedactLiterals
    Switch to forcefully hash ALL string literals.
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [PSObject]$InputObject,
    
    [Parameter(HelpMessage = "List of sensitive table names or keywords. If an SQL statement contains these, the WHERE/HAVING clause will be pseudonymized.")]
    [string[]]$SensitiveKeywords,

    [Parameter(HelpMessage = "Hash/Pseudonymize ALL string literals >= 2 chars (ignoring %). Keywords are always redacted regardless of length.")]
    [switch]$RedactLiterals,

    [Parameter(HelpMessage = "Only analyze the trace data and output grouped statistics of potential sensitive data (WHERE/HAVING/Strings). Does NOT output trace records.")]
    [switch]$AnalyzeOnly,

    [Parameter(HelpMessage = "Length of the generated hash string.")]
    [ValidateRange(8, 64)]
    [int]$HashLength = 12
)

begin {
    $Algorithm = [System.Security.Cryptography.SHA256]::Create()
    $Counter = 0
    
    # Analysis Collections
    $Stats = @{
        WhereClauses   = @{}
        HavingClauses  = @{}
        StringLiterals = @{}
    }

    # Regex Definitions
    # SQL String Literal with Context: Captures Operator (Group 1) and Literal (Group 2)
    # Operators: LIKE, NOT LIKE, STARTING WITH, CONTAINING, SIMILAR TO, IN, =, <>, !=, <=, >=, <, >
    $RxStringLiteral = [System.Text.RegularExpressions.Regex]::new('(?i)(\b(?:like|not\s+like|starting\s+with|containing|similar\s+to|in|=|<>|!=|<=|>=|<|>)\s*)?(''(?:''''|[^''])*'')', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    
    # Where/Having Extraction
    $RxWhere = [System.Text.RegularExpressions.Regex]::new('(?is)\bwhere\b\s+(.*?)(\b(?:group\s+by|order\s+by|rows|plan|union)\b|$)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $RxHaving = [System.Text.RegularExpressions.Regex]::new('(?is)\bhaving\b\s+(.*?)(\b(?:order\s+by|rows|plan|union)\b|$)', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    function Get-ShortHash {
        param([string]$Value)
        if ([string]::IsNullOrEmpty($Value)) { return $Value }
        
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hashBytes = $Algorithm.ComputeHash($bytes)
        $hashStr = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
        # Cap length at max hex string length (64 for SHA256)
        $len = [Math]::Min($HashLength, $hashStr.Length)
        return $hashStr.Substring(0, $len)
    }

    function Add-Stat {
        param($Type, $Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return }
        $Dict = $Stats[$Type]
        if (-not $Dict.ContainsKey($Value)) {
            $Dict[$Value] = 1
        }
        else {
            $Dict[$Value]++
        }
    }

    function Test-ShouldRedact {
        param([string]$Content)
        # 1. Keyword Check (Priority: Always Redact)
        if ($SensitiveKeywords) {
            foreach ($kw in $SensitiveKeywords) {
                if ($Content -match [System.Text.RegularExpressions.Regex]::Escape($kw)) {
                    return $true
                }
            }
        }

        # 2. RedactLiterals Check (Constraint: Length >= 2 ignoring %)
        if ($RedactLiterals) {
            $cleaned = $Content -replace '%', ''
            if ($cleaned.Length -ge 2) {
                return $true
            }
        }

        return $false
    }
}

process {
    $Counter++
    if ($Counter % 1000 -eq 0) {
        Write-Progress -Activity "Pseudonymizing Trace Data" -Status "Processed: $Counter records"
    }

    $item = $InputObject 

    # --- ANALYZE ONLY MODE ---
    if ($AnalyzeOnly) {
        if ($item.SqlStatement) {
            # 1. Capture Strings with Context
            $matches = $RxStringLiteral.Matches($item.SqlStatement)
            foreach ($m in $matches) {
                $operator = $m.Groups[1].Value
                $literal = $m.Groups[2].Value
                # literal includes quotes e.g. 'text'
                $content = $literal.Substring(1, $literal.Length - 2) # strip quotes

                # Determine if this WOULD be redacted
                $target = $false
                if (Test-ShouldRedact -Content $content) {
                    $target = $true
                }
                
                $display = $literal
                if (-not [string]::IsNullOrWhiteSpace($operator)) {
                    $opClean = $operator.Trim().ToUpper()
                    $display = "[$opClean] $literal"
                }

                # Append Preview
                if ($target) {
                    $hashed = Get-ShortHash $content
                    $display += " --> pseudo convert to: '<HASH:$hashed>'"
                }

                Add-Stat "StringLiterals" $display
            }

            # 2. Capture WHERE
            $mWhere = $RxWhere.Match($item.SqlStatement)
            if ($mWhere.Success) {
                Add-Stat "WhereClauses" $mWhere.Groups[1].Value.Trim()
            }

            # 3. Capture HAVING
            $mHaving = $RxHaving.Match($item.SqlStatement)
            if ($mHaving.Success) {
                Add-Stat "HavingClauses" $mHaving.Groups[1].Value.Trim()
            }
        }
        return # Skip outputting record
    }

    # --- NORMAL PROCESSING MODE ---

    # CRITICAL: Create a copy to avoid modifying the original list by reference
    $item = $InputObject | Select-Object *
    
    # 1. User
    if ($item.User) {
        $item.User = Get-ShortHash $item.User
    }
    
    # 2. ApplicationPath
    if ($item.ApplicationPath) {
        $item.ApplicationPath = Get-ShortHash $item.ApplicationPath
    }
    
    # 3. ClientIP
    if ($item.ClientIP) {
        $item.ClientIP = Get-ShortHash $item.ClientIP
    }
    
    # 4. ProtocolInfo parsing
    if ($item.ProtocolInfo) {
        $item.ProtocolInfo = [System.Text.RegularExpressions.Regex]::Replace($item.ProtocolInfo, '^([^:]+):([^/]+)(.*)$', {
                param($match)
                $type = $match.Groups[1].Value
                $ip = $match.Groups[2].Value
                $portVal = $match.Groups[3].Value
                $hashedIp = Get-ShortHash $ip
                return "$type`:$hashedIp$portVal"
            })
    }
    
    # 5. Params (Hash quoted strings)
    if ($item.Params) {
        $item.Params = [System.Text.RegularExpressions.Regex]::Replace($item.Params, '"([^"]*)"', {
                param($match)
                $val = $match.Groups[1].Value
                $hashed = Get-ShortHash $val
                return "`"$hashed`""
            })
    }
    
    # 6. Sensitive SQL Redaction
    if ($item.SqlStatement) {
        # processing always runs if SqlStatement exists, enabling RedactLiterals
        
        # A. Specific String Literal Redaction (Targeted)
        $item.SqlStatement = $RxStringLiteral.Replace($item.SqlStatement, {
                param($match)
                $operator = $match.Groups[1].Value
                $literal = $match.Groups[2].Value 
                $content = $literal.Substring(1, $literal.Length - 2)
            
                if (Test-ShouldRedact -Content $content) {
                    $hashed = Get-ShortHash $content
                    return "$operator'<HASH:$hashed>'"
                }
                
                return $match.Value
            })

        # B. Bulk Clause Redaction (Safety Net - only if Keywords present)
        if ($SensitiveKeywords) {
            $isSensitive = $false
            foreach ($kw in $SensitiveKeywords) {
                # We check again because 'A' might have removed the sensitive part
                if ($item.SqlStatement -match [System.Text.RegularExpressions.Regex]::Escape($kw)) {
                    $isSensitive = $true
                    break
                }
            }
            
            if ($isSensitive) {
                $item.SqlStatement = [System.Text.RegularExpressions.Regex]::Replace($item.SqlStatement, '(?is)(.*\b(?:where|having)\b)(.*)', {
                        param($match)
                        $prefix = $match.Groups[1].Value
                        $condition = $match.Groups[2].Value
                        $hashedCondition = Get-ShortHash $condition
                        return "$prefix <REDACTED_CLAUSE:$hashedCondition>"
                    })
            }
        }
    }
    
    # Output the copy
    $item
}

end {
    $Algorithm.Dispose()
    Write-Progress -Activity "Pseudonymizing Trace Data" -Completed

    if ($AnalyzeOnly) {
        Write-Host "`n--- Trace Analysis Report ---" -ForegroundColor Cyan
        
        # Helper to output tables
        $ShowStat = {
            param($Name, $Dict)
            if ($Dict.Count -gt 0) {
                Write-Host "`n$($Name) ($($Dict.Count) unique patterns):" -ForegroundColor Yellow
                $Dict.GetEnumerator() | 
                Sort-Object Value -Descending | 
                Select-Object -First 50 @{N = 'Count'; E = { $_.Value } }, @{N = 'Content'; E = { $_.Name } } |
                Format-Table -AutoSize
            }
            else {
                Write-Host "`n$($Name): None found." -ForegroundColor Gray
            }
        }

        & $ShowStat "Detected String Literals" $Stats.StringLiterals
        & $ShowStat "Detected WHERE Clauses" $Stats.WhereClauses
        & $ShowStat "Detected HAVING Clauses" $Stats.HavingClauses
        
        Write-Host "`nAnalysis Complete. Use this info to refine -SensitiveKeywords or -RedactLiterals." -ForegroundColor Green
    }
}
