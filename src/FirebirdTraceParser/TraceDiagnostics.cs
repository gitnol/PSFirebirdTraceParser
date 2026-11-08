using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Warnings with line numbers and the per-action summary (I13). Mirrors Write-BlockWarning, Test-Preamble,
    /// Measure-Newline and Get-LineEnd of Show-TraceStructure.ps1. Warnings hold line numbers and fixed texts only.
    /// Line numbers are computed only when a warning is written: LineBase is the line number of text[0]; when lines were
    /// dropped from an oversized carry, positions from ShiftFrom on lie Shift lines further down in the file.
    /// </summary>
    [SuppressMessage("Globalization", "CA1307", Justification = "Same culture-sensitive IndexOf(string) as the script (parity, ADR-003)")]
    [SuppressMessage("Globalization", "CA1310", Justification = "Same culture-sensitive IndexOf(string) as the script (parity, ADR-003)")]
    [SuppressMessage("Performance", "CA1865", Justification = "IndexOf(string) is culture-sensitive, the char overload is not (parity, ADR-003)")]
    [SuppressMessage("Performance", "CA1866", Justification = "IndexOf(string) is culture-sensitive, the char overload is not (parity, ADR-003)")]
    internal sealed class TraceDiagnostics
    {
        public const string HeaderNotReadable = "(header not readable)";
        private static readonly Regex StartLine = new Regex(@"^Trace session ID \d+ started\s*$", RegexOptions.IgnoreCase);
        private readonly Action<string> _warning;
        private readonly Hashtable _actionCount = PowerShellSemantics.NewHashtable();
        private string? _lnText;
        private int _lnIndex;
        private int _lnCount;

        public TraceDiagnostics(Action<string> warning)
        {
            _warning = warning;
        }

        public int LineBase { get; set; } = 1;
        public int ShiftFrom { get; set; } = int.MaxValue;
        public int Shift { get; set; }
        public int WarningCount { get; private set; }

        /// <summary>Number of line breaks in text[from..to).</summary>
        public static int MeasureNewline(string text, int from, int to)
        {
            var n = 0;
            for (var i = from; i < to; i++)
            {
                if (text[i] == '\n')
                {
                    n++;
                }
            }

            return n;
        }

        /// <summary>
        /// Index after the n-th line break, or -1 if the text has fewer line breaks. Ordinal char search like the script
        /// since I21 (K8: the culture-sensitive string search costs time proportional to the rest of the text per call).
        /// </summary>
        public static int GetLineEnd(string text, int lines)
        {
            var pos = -1;
            for (var k = 0; k < lines; k++)
            {
                pos = text.IndexOf('\n', pos + 1);
                if (pos < 0)
                {
                    return -1;
                }
            }

            return pos + 1;
        }

        public void BlockWarning(string text, int start, string message)
        {
            // The last result is cached, so many warnings in one chunk stay linear
            if (!ReferenceEquals(text, _lnText) || start < _lnIndex)
            {
                _lnText = text;
                _lnIndex = 0;
                _lnCount = 0;
            }

            _lnCount += MeasureNewline(text, _lnIndex, start);
            _lnIndex = start;
            var line = LineBase + _lnCount;
            if (start >= ShiftFrom)
            {
                line += Shift;
            }

            WarningCount++;
            _warning("Line " + line + ": " + message);
        }

        /// <summary>Text before the first event: empty lines and the start line of fbtracemgr are expected.</summary>
        public void Preamble(string text)
        {
            var lines = text.Split('\n');
            for (var k = 0; k < lines.Length; k++)
            {
                if (lines[k].Trim().Length > 0 && !StartLine.IsMatch(lines[k]))
                {
                    WarningCount++;
                    _warning("Line " + (LineBase + k) + ": text before the first event skipped");
                    return;
                }
            }
        }

        /// <summary>Counts the event per action and reports events that cannot be assigned.</summary>
        public void CountEvent(string text, int start, string block, string? action)
        {
            if (string.IsNullOrEmpty(action))
            {
                Increment(HeaderNotReadable);
                BlockWarning(text, start, "event header not readable, fields left empty");
                return;
            }

            Increment(action!);
            if (PowerShellSemantics.Eq(action, "Unknown"))
            {
                // Firebird writes fixed texts like "Unknown event in ATTACH_DATABASE" (TracePluginImpl.cpp)
                var line = block.Substring(0, Math.Max(0, block.IndexOf("\n")));
                BlockWarning(text, start, string.Concat("unknown event '", line.AsSpan(line.IndexOf(") ") + 2), "'"));
            }
        }

        /// <summary>Summary lines: count per action (descending, then name like Sort-Object), then the warnings.</summary>
        public IEnumerable<string> Summary()
        {
            var keyOrder = StringComparer.Create(CultureInfo.CurrentCulture, true);
            var entries = _actionCount.Cast<DictionaryEntry>()
                .OrderByDescending(e => (int)e.Value!)
                .ThenBy(e => (string)e.Key, keyOrder);
            foreach (var e in entries)
            {
                yield return "Summary: " + e.Key + " = " + e.Value;
            }

            yield return "Summary: " + WarningCount + " warning(s)";
        }

        private void Increment(string key) => _actionCount[key] = (_actionCount[key] is int n ? n : 0) + 1;
    }
}
