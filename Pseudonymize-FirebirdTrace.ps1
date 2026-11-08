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
    Switch to forcefully hash ALL string and numeric literals.

.PARAMETER KeyFile
    File with the secret key (Base64, at least 32 bytes) for HMAC-SHA256 pseudonyms. Created with a random key if it
    does not exist. Keep it like a password and never share it: with the key, pseudonyms can be checked against guesses.
    Same key = same pseudonyms across runs (trends, before/after comparisons). Without -KeyFile a random key is used
    for this run only (pseudonyms not comparable between runs). See docs/architecture/ADR/ADR-001-pseudonymisierung-hmac.md

.PARAMETER MappingFile
    Optional CSV (Pseudonym;Original) for the data controller to map results back to real values. Contains plaintext -
    keep it with the key, never share it.
#>
# HashLength is used inside the nested function in begin{}; PSScriptAnalyzer does not see that.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'HashLength', Justification = 'used in nested function')]
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [PSObject]$InputObject,
    
    [Parameter(HelpMessage = "List of sensitive table names or keywords. If an SQL statement contains these, the WHERE/HAVING clause will be pseudonymized.")]
    [string[]]$SensitiveKeywords,

    [Parameter(HelpMessage = "Hash/Pseudonymize ALL string literals and numbers (literals consisting only of % stay). Keywords are always redacted.")]
    [switch]$RedactLiterals,

    [Parameter(HelpMessage = "Only analyze the trace data and output grouped statistics of potential sensitive data (WHERE/HAVING/Strings). Does NOT output trace records.")]
    [switch]$AnalyzeOnly,

    [Parameter(HelpMessage = "Length of the generated hash string.")]
    [ValidateRange(8, 64)]
    [int]$HashLength = 12,

    [Parameter(HelpMessage = "Secret key file (Base64, >= 32 bytes) for HMAC pseudonyms; created if missing. Never share it.")]
    [string]$KeyFile,

    [Parameter(HelpMessage = "Optional CSV mapping Pseudonym;Original for the data controller. Contains plaintext - never share it.")]
    [string]$MappingFile
)

begin {
    function Show-AnalysisReport {
        # -AnalyzeOnly prints an interactive console report (not pipeline output), so Write-Host is intended here.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'interactive -AnalyzeOnly report')]
        [CmdletBinding()]
        param([Parameter(Mandatory)] [hashtable]$Stats)

        Write-Host "--- Trace Analysis Report ---" -ForegroundColor Cyan

        # Helper to output tables
        $ShowStat = {
            param($Name, $Dict)
            if ($Dict.Count -gt 0) {
                Write-Host "$($Name) ($($Dict.Count) unique patterns):" -ForegroundColor Yellow
                $Dict.GetEnumerator() |
                Sort-Object Value -Descending |
                Select-Object -First 50 @{N = 'Count'; E = { $_.Value } }, @{N = 'Content'; E = { $_.Name } } |
                Format-Table -AutoSize | Out-Host
            }
            else {
                Write-Host "$($Name): None found." -ForegroundColor Gray
            }
        }

        & $ShowStat "Detected String Literals" $Stats.StringLiterals
        & $ShowStat "Detected WHERE Clauses" $Stats.WhereClauses
        & $ShowStat "Detected HAVING Clauses" $Stats.HavingClauses

        Write-Host "Analysis Complete. Use this info to refine -SensitiveKeywords or -RedactLiterals." -ForegroundColor Green
    }

    # --- Key for HMAC-SHA256 (I3, ADR-001). The key is never written to output, logs or the mapping file. ---
    function Protect-PrivateFile {
        param([string]$FilePath)
        # Only the current user may read the file (key / mapping contain secrets)
        try {
            if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
                $acl = Get-Acl -LiteralPath $FilePath
                $acl.SetAccessRuleProtection($true, $false)
                foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
                $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($me, 'FullControl', 'Allow'))
                Set-Acl -LiteralPath $FilePath -AclObject $acl
            }
            else {
                [System.IO.File]::SetUnixFileMode($FilePath, [System.IO.UnixFileMode]'UserRead, UserWrite')
            }
        }
        catch {
            Write-Warning "Could not restrict access to '$FilePath': $($_.Exception.Message). Restrict it manually."
        }
    }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    if ($KeyFile) {
        if (-not (Test-Path -LiteralPath $KeyFile)) {
            $newKey = [byte[]]::new(32)
            $rng.GetBytes($newKey)
            $dir = Split-Path -Parent $KeyFile
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
            [System.IO.File]::WriteAllText($KeyFile, [Convert]::ToBase64String($newKey))
            [Array]::Clear($newKey, 0, $newKey.Length)
            Protect-PrivateFile $KeyFile
            Write-Warning "New pseudonymization key created: $KeyFile. Keep it safe and never share it. Use the same key for comparable runs."
        }
        try {
            $keyBytes = [Convert]::FromBase64String(([System.IO.File]::ReadAllText($KeyFile)).Trim())
        }
        catch {
            throw "Key file '$KeyFile' is not valid Base64."
        }
        if ($keyBytes.Length -lt 32) {
            throw "Key file '$KeyFile' must contain at least 32 bytes (Base64); found $($keyBytes.Length)."
        }
    }
    else {
        $keyBytes = [byte[]]::new(32)
        $rng.GetBytes($keyBytes)
        Write-Warning "No -KeyFile given: using a random key for this run only. Pseudonyms are consistent within this run but not comparable with other runs."
    }
    $rng.Dispose()
    $Algorithm = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    [Array]::Clear($keyBytes, 0, $keyBytes.Length)

    # Optional mapping pseudonym -> original (for the data controller only)
    $Mapping = if ($MappingFile) { [System.Collections.Generic.Dictionary[string, string]]::new() } else { $null }
    $Collisions = 0

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
    
    # Numeric literals outside of strings and quoted identifiers (I2): q/s are kept, n is pseudonymized
    $RxNumberToken = [System.Text.RegularExpressions.Regex]::new('(?<q>"(?:""|[^"])*")|(?<s>''(?:''''|[^''])*'')|(?<p><HASH:[0-9a-f]+>)|(?<n>(?<![\w$.:])\d+(?:\.\d+)?(?![\w$]))', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    # Where/Having Extraction
    $RxWhere = [System.Text.RegularExpressions.Regex]::new('(?is)\bwhere\b\s+(.*?)(\b(?:group\s+by|order\s+by|rows|plan|union)\b|$)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
    $RxHaving = [System.Text.RegularExpressions.Regex]::new('(?is)\bhaving\b\s+(.*?)(\b(?:order\s+by|rows|plan|union)\b|$)', [System.Text.RegularExpressions.RegexOptions]::Compiled)

    function Get-ShortHash {
        param([string]$Value)
        if ([string]::IsNullOrEmpty($Value)) { return $Value }
        
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hashBytes = $Algorithm.ComputeHash($bytes)   # HMAC-SHA256 with the secret key (I3)
        $hashStr = [System.BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
        # Cap length at max hex string length (64 for SHA256)
        $len = [Math]::Min($HashLength, $hashStr.Length)
        $pseudonym = $hashStr.Substring(0, $len)
        if ($null -ne $Mapping) {
            if (-not $Mapping.ContainsKey($pseudonym)) { $Mapping[$pseudonym] = $Value }
            elseif ($Mapping[$pseudonym] -ne $Value) { $script:Collisions++ }
        }
        return $pseudonym
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

        # 2. RedactLiterals Check: every non-empty literal (ignoring %); single characters can be personal data (I2)
        if ($RedactLiterals) {
            $cleaned = $Content -replace '%', ''
            if ($cleaned.Length -ge 1) {
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
            $literalMatches = $RxStringLiteral.Matches($item.SqlStatement)
            foreach ($m in $literalMatches) {
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
    # Select-Object copies only the first level: give the per-table objects (I11) their own copies, so changes to the
    # output never reach the input. Table names and counters stay plain text, like TableStats (decision I2).
    if ($item.PSObject.Properties['TableCounts'] -and $item.TableCounts) {
        $item.TableCounts = @($item.TableCounts | ForEach-Object { $_ | Select-Object * })
    }
    
    # 1. User
    if ($item.User) {
        $item.User = Get-ShortHash $item.User
    }
    
    # 2. ApplicationPath
    if ($item.ApplicationPath) {
        $item.ApplicationPath = Get-ShortHash $item.ApplicationPath
    }
    
    # 2b. DatabasePath (server, folder and customer names, I2)
    if ($item.PSObject.Properties['DatabasePath'] -and $item.DatabasePath) {
        $item.DatabasePath = Get-ShortHash $item.DatabasePath
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

        # A2. Numeric literals (I2) - only with -RedactLiterals; digits in identifiers and pseudonyms stay
        if ($RedactLiterals) {
            $item.SqlStatement = $RxNumberToken.Replace($item.SqlStatement, {
                    param($match)
                    if ($match.Groups['n'].Success) { return "<HASH:$(Get-ShortHash $match.Value)>" }
                    return $match.Value
                })
        }

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
                $item.SqlStatement = [System.Text.RegularExpressions.Regex]::Replace($item.SqlStatement, '(?is)^(.*?\b(?:where|having)\b)(.*)$', {
                        param($match)
                        $prefix = $match.Groups[1].Value
                        $condition = $match.Groups[2].Value
                        $hashedCondition = Get-ShortHash $condition
                        return "$prefix <REDACTED_CLAUSE:$hashedCondition>"
                    })
            }
        }
    }
    
    # 7. Error messages (ERROR AT / WARNING AT, I10). Constraint and table names stay readable (metadata);
    #    values are hashed: key values like ("ID" = 42) and string literals like 'text'.
    if ($RedactLiterals -and $item.PSObject.Properties['ErrorMessages'] -and $item.ErrorMessages) {
        $item.ErrorMessages = [System.Text.RegularExpressions.Regex]::Replace($item.ErrorMessages,
            '("[^"]+"\s*=\s*)(''(?:''''|[^''])*''|[^,)]+)', {
                param($match)
                $value = $match.Groups[2].Value.Trim()
                return "$($match.Groups[1].Value)<HASH:$(Get-ShortHash $value)>"
            })
        $item.ErrorMessages = [System.Text.RegularExpressions.Regex]::Replace($item.ErrorMessages,
            '''((?:''''|[^''])*)''', {
                param($match)
                $content = $match.Groups[1].Value
                if (Test-ShouldRedact -Content $content) { return "'<HASH:$(Get-ShortHash $content)>'" }
                return $match.Value
            })
    }

    # Output the copy
    $item
}

end {
    $Algorithm.Dispose()

    if ($null -ne $Mapping) {
        $Mapping.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Pseudonym = $_.Key; Original = $_.Value } } |
            Export-Csv -LiteralPath $MappingFile -Delimiter ';' -NoTypeInformation -Encoding UTF8
        Protect-PrivateFile $MappingFile
        Write-Warning "Mapping file written: $MappingFile ($($Mapping.Count) entries). It contains plaintext - keep it with the key, never share it."
        if ($Collisions -gt 0) {
            Write-Warning "$Collisions pseudonym collision(s): different values got the same pseudonym. Increase -HashLength."
        }
    }
    Write-Progress -Activity "Pseudonymizing Trace Data" -Completed

    if ($AnalyzeOnly) {
        Show-AnalysisReport -Stats $Stats
    }
}
