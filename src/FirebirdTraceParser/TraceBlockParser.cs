using System;

namespace FirebirdTraceParser
{
    /// <summary>One trace event (block of lines) -> one entry. Mirrors ConvertFrom-TraceBlock in Show-TraceStructure.ps1.</summary>
    internal sealed class TraceBlockParser
    {
        private readonly TracePatterns _rx;

        public TraceBlockParser(TimeSpan regexTimeout)
        {
            _rx = new TracePatterns(regexTimeout);
        }

        public TraceEntry Parse(string text, int start, int length)
        {
            var block = text.Substring(start, length);
            var entry = new TraceEntry();

            // --- Header ---
            var m = _rx.Header.Match(block);
            if (m.Success)
            {
                entry[TraceField.Timestamp] = m.Groups["Timestamp"].Value;
                entry[TraceField.Action] = m.Groups["Action"].Value;
                entry[TraceField.ProcessID] = m.Groups["ProcessID"].Value;
                entry[TraceField.SessionID] = m.Groups["SessionID"].Value;
                if (m.Groups["ErrorSource"].Success)
                {
                    entry[TraceField.ErrorSource] = m.Groups["ErrorSource"].Value;
                }
            }

            return entry;
        }
    }
}
