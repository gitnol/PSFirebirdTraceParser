using System;
using System.IO;
using System.Management.Automation;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Parses a Firebird trace log into one PSCustomObject per trace event, with the same fields, order and types as
    /// Show-TraceStructure.ps1 (docs/features/TRACE_PARSING.md, ADR-003).
    /// </summary>
    [Cmdlet(VerbsData.ConvertFrom, "FirebirdTrace")]
    [OutputType(typeof(PSObject))]
    public sealed class ConvertFromFirebirdTraceCommand : PSCmdlet
    {
        private const string ProgressActivity = "Parsing Firebird trace";

        /// <summary>Path of the trace file (literal, relative to the current PowerShell location).</summary>
        [Parameter(Mandatory = true, Position = 0)]
        public string Path { get; set; } = string.Empty;

        /// <summary>Upper limit of lines per event; a longer event is cut (warning).</summary>
        [Parameter]
        [ValidateRange(1, int.MaxValue)]
        public int MaxBlockLines { get; set; } = 100000;

        /// <summary>Time limit per regex evaluation in an event (seconds).</summary>
        [Parameter]
        [ValidateRange(0.001, 3600.0)]
        public double RegexTimeoutSeconds { get; set; } = 2;

        /// <summary>Parses the file and writes one object per event as soon as it is complete.</summary>
        protected override void ProcessRecord()
        {
            var full = SessionState.Path.GetUnresolvedProviderPathFromPSPath(Path);
            if (!File.Exists(full))
            {
                WriteError(new ErrorRecord(new FileNotFoundException("File not found: " + Path), "FileNotFound", ErrorCategory.ObjectNotFound, Path));
                return;
            }

            var parser = new TraceStreamParser(full, TimeSpan.FromSeconds(RegexTimeoutSeconds), WriteChunkProgress);
            try
            {
                foreach (var entry in parser.Parse())
                {
                    WriteObject(entry.ToPSObject());
                }
            }
            finally
            {
                WriteProgress(new ProgressRecord(1, ProgressActivity, "Completed") { RecordType = ProgressRecordType.Completed });
            }
        }

        private void WriteChunkProgress(int events, int percent)
        {
            WriteProgress(new ProgressRecord(1, ProgressActivity, events + " events") { PercentComplete = percent });
        }
    }
}
