# Settings for PSScriptAnalyzer (Gate 1, docs/CONVENTIONS.md section 9).
# Used locally and in CI via tools/Invoke-QualityGate.ps1.
# All three blocking severities are reported; 'Information' (style hints such as trailing
# whitespace) is not a gate. Exceptions are made in the code with a SuppressMessageAttribute
# and a Justification - never by excluding a rule here.
@{
    Severity     = @('ParseError', 'Error', 'Warning')
    ExcludeRules = @()
}
