using System;
using System.Text.RegularExpressions;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Regex of the parser. Patterns and options are copied literally from Show-TraceStructure.ps1 (ADR-003): any change
    /// must be made in both places, the parity test fails otherwise. Example lines are fictitious.
    /// </summary>
    internal sealed class TracePatterns
    {
        private const RegexOptions MultilineCompiled = RegexOptions.Multiline | RegexOptions.Compiled;

        /// <summary>Block start: a line beginning with a timestamp. Anchored and linear, therefore without time limit.</summary>
        public static readonly Regex BlockStart = new Regex(
            @"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,}", MultilineCompiled);

        public TracePatterns(TimeSpan timeout)
        {
            // "2026-11-08T10:00:00.0000 (4321:000001A2B3C4D5E0) EXECUTE_STATEMENT_FINISH"; Windows or Linux (0x...) address;
            // FAILED/UNAUTHORIZED stay in Action; "ERROR AT <component>" gives Action ERROR and ErrorSource
            Header = new Regex(
                @"^(?<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{4,})\s+\((?<ProcessID>\d+):(?<SessionID>(?:0x)?[0-9A-Fa-f]+)\)\s+(?<Action>(?:(?:FAILED|UNAUTHORIZED)\s+)?\S+)(?:\s+AT\s+(?<ErrorSource>\S+))?",
                MultilineCompiled, timeout);
        }

        public Regex Header { get; }
    }
}
