using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FirebirdTraceParser
{
    /// <summary>Progress of the streaming loop (events so far, percent of the file read).</summary>
    internal delegate void TraceProgress(int events, int percent);

    /// <summary>
    /// Streaming loop of Show-TraceStructure.ps1: reads the file in chunks of 4 MB, splits each chunk at block starts and
    /// carries the unfinished last block into the next chunk. Memory is bounded by the chunk size plus the largest block.
    /// </summary>
    internal sealed class TraceStreamParser
    {
        private const int ReaderBufferSize = 1024 * 1024;
        private const int ChunkSize = 4 * 1024 * 1024;

        private readonly string _path;
        private readonly TraceBlockParser _blocks;
        private readonly TraceProgress _progress;

        public TraceStreamParser(string path, TimeSpan regexTimeout, TraceProgress progress)
        {
            _path = path;
            _blocks = new TraceBlockParser(regexTimeout);
            _progress = progress;
        }

        /// <summary>Number of events parsed so far.</summary>
        public int Count { get; private set; }

        public IEnumerable<TraceEntry> Parse()
        {
            using (var reader = new StreamReader(_path, Encoding.UTF8, true, ReaderBufferSize))
            {
                var chunk = new char[ChunkSize];
                var carry = string.Empty;
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
                        for (var i = 0; i < starts.Count - 1; i++)
                        {
                            yield return _blocks.Parse(text, starts[i].Index, starts[i + 1].Index - starts[i].Index);
                            Count++;
                        }

                        carryStart = starts[starts.Count - 1].Index;
                    }

                    carry = text.Substring(carryStart);
                    _progress(Count, (int)Math.Min(100, 100 * reader.BaseStream.Position / length));
                }

                if (TracePatterns.BlockStart.Match(carry).Index == 0 && TracePatterns.BlockStart.IsMatch(carry))
                {
                    yield return _blocks.Parse(carry, 0, carry.Length);
                    Count++;
                }
            }
        }
    }
}
