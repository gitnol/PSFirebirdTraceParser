using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management.Automation;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Parses a Firebird trace log into one PSCustomObject per trace event, with the same fields, order and types as
    /// Show-TraceStructure.ps1 (docs/features/TRACE_PARSING.md, ADR-003). Warnings and verbose messages have the same
    /// texts as the script; they hold line numbers and fixed texts, never trace content.
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

            var sw = Stopwatch.StartNew();
            var diagnostics = new TraceDiagnostics(WriteWarning);
            var parser = new TraceStreamParser(full, new TraceParserOptions(MaxBlockLines, RegexTimeoutSeconds), diagnostics, WriteChunkProgress, WriteVerbose);
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

            // Summary (I13): verbose stream only, the pipeline output stays the same
            foreach (var line in diagnostics.Summary())
            {
                WriteVerbose(line);
            }

            sw.Stop();
            WriteVerbose("Parsed " + parser.Count + " events in " + sw.Elapsed.TotalSeconds.ToString("N2", CultureInfo.CurrentCulture) + " seconds.");
        }

        private void WriteChunkProgress(int events, int percent)
        {
            WriteProgress(new ProgressRecord(1, ProgressActivity, events + " events") { PercentComplete = percent });
        }
    }
}
