using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FirebirdTraceParser
{
    /// <summary>Progress of the streaming loop (events so far, percent of the file read).</summary>
    internal delegate void TraceProgress(int events, int percent);

    /// <summary>Parameters of one run, same names and ranges as Show-TraceStructure.ps1.</summary>
    internal sealed record TraceParserOptions(int MaxBlockLines, double RegexTimeoutSeconds);

    /// <summary>
    /// Streaming loop of Show-TraceStructure.ps1: reads the file in chunks of 4 MB, splits each chunk at block starts and
    /// carries the unfinished last block into the next chunk. Memory is bounded by the chunk size plus the largest block;
    /// a carried block (or text without any event) longer than MaxBlockLines lines is cut while it is carried.
    /// </summary>
    internal sealed class TraceStreamParser
    {
        private const int ReaderBufferSize = 1024 * 1024;
        private const int ChunkSize = 4 * 1024 * 1024;

        private readonly string _path;
        private readonly int _maxBlockLines;
        private readonly TraceBlockParser _blocks;
        private readonly TraceProgress _progress;

        public TraceStreamParser(string path, TraceParserOptions options, TraceDiagnostics diagnostics, TraceProgress progress, Action<string> verbose)
        {
            _path = path;
            _maxBlockLines = options.MaxBlockLines;
            Diagnostics = diagnostics;
            _blocks = new TraceBlockParser(options, diagnostics, verbose);
            _progress = progress;
        }

        /// <summary>Number of events parsed so far.</summary>
        public int Count { get; private set; }

        public TraceDiagnostics Diagnostics { get; }

        public IEnumerable<TraceEntry> Parse()
        {
            using (var reader = new StreamReader(_path, Encoding.UTF8, true, ReaderBufferSize))
            {
                var chunk = new char[ChunkSize];
                var carry = string.Empty;
                var carryCut = false; // lines of the carried block were dropped (MaxBlockLines)
                var seenBlock = false;
                var length = Math.Max(1L, reader.BaseStream.Length);
                int read;
                while ((read = reader.Read(chunk, 0, chunk.Length)) > 0)
                {
                    // Trace files mix CRLF and LF; blocks are processed with LF only
                    var text = carry + new string(chunk, 0, read).Replace("\r", string.Empty);
                    var starts = TracePatterns.BlockStart.Matches(text);
                    var carryStart = 0;
                    if (starts.Count > 0)
                    {
                        // Everything before the first block start (e.g. "Trace session ID n started") is skipped
                        if (!seenBlock)
                        {
                            seenBlock = true;
                            if (starts[0].Index > 0)
                            {
                                Diagnostics.Preamble(text.Substring(0, starts[0].Index));
                            }
                        }

                        for (var i = 0; i < starts.Count - 1; i++)
                        {
                            yield return _blocks.Parse(text, starts[i].Index, starts[i + 1].Index - starts[i].Index, carryCut && i == 0);
                            Count++;
                        }

                        if (starts.Count > 1)
                        {
                            carryCut = false;
                        }

                        carryStart = starts[starts.Count - 1].Index;
                    }

                    // Line number of the new carry start (only the text before it is finished)
                    if (carryStart > 0)
                    {
                        Diagnostics.LineBase += TraceDiagnostics.MeasureNewline(text, 0, carryStart);
                        if (carryStart >= Diagnostics.ShiftFrom)
                        {
                            Diagnostics.LineBase += Diagnostics.Shift;
                            Diagnostics.Shift = 0;
                            Diagnostics.ShiftFrom = int.MaxValue;
                        }
                    }

                    carry = text.Substring(carryStart);
                    if (carry.Length > _maxBlockLines)
                    {
                        var end = TraceDiagnostics.GetLineEnd(carry, _maxBlockLines);
                        if (end > 0 && end < carry.Length)
                        {
                            Diagnostics.Shift += TraceDiagnostics.MeasureNewline(carry, end, carry.Length);
                            Diagnostics.ShiftFrom = end;
                            carry = carry.Substring(0, end);
                            carryCut = seenBlock;
                        }
                    }

                    _progress(Count, (int)Math.Min(100, 100 * reader.BaseStream.Position / length));
                }

                if (TracePatterns.BlockStart.Match(carry).Index == 0 && TracePatterns.BlockStart.IsMatch(carry))
                {
                    yield return _blocks.Parse(carry, 0, carry.Length, carryCut);
                    Count++;
                }
                else if (!seenBlock)
                {
                    Diagnostics.Preamble(carry);
                }
            }
        }
    }
}
