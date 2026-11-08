using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Table statistics -> one object per table. Mirrors ConvertFrom-TableStat in Show-TraceStructure.ps1: Firebird
    /// (appendTableCounts) pads the name column to max(32, longest name in bytes) (Firebird 3: 31) and writes each counter
    /// right-aligned in 10 characters, 0 as blanks. The name column width comes from the header.
    /// </summary>
    internal static class TableStatParser
    {
        private const int CellWidth = 10;
        private const int Cells = 8;
        private const string NaturalHeader = "Natural";
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);
        private static readonly string[] Columns = { "Natural", "Index", "Update", "Insert", "Delete", "Backout", "Purge", "Expunge" };

        [SuppressMessage("Globalization", "CA1307", Justification = "Same culture-sensitive IndexOf(string) as the script (parity, ADR-003)")]
        [SuppressMessage("Globalization", "CA1310", Justification = "Same culture-sensitive IndexOf(string) as the script (parity, ADR-003)")]
        [SuppressMessage("Performance", "CA1866", Justification = "IndexOf(string) is culture-sensitive, IndexOf(char) is not (parity, ADR-003)")]
        public static object[]? Parse(string tableStats, Action<string> verbose)
        {
            var lines = tableStats.Split('\n');
            var nameWidth = lines[0].IndexOf(NaturalHeader) + NaturalHeader.Length - CellWidth;
            if (nameWidth <= 0)
            {
                return null;
            }

            var rows = new List<object>();
            for (var i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (line.Length == 0 || line[0] == '*')
                {
                    continue;
                }

                var head = line.Substring(0, Math.Min(nameWidth, line.Length));
                var cellStart = nameWidth - (Utf8.GetByteCount(head) - head.Length);
                var space = line.IndexOf(" ");
                var token = space < 0 ? line : line.Substring(0, space);
                if (token.Length > cellStart)
                {
                    // Longer than the column - unless the rest is one full cell (name fills the column, 10-digit number)
                    var rest = token.Substring(cellStart);
                    if (!(rest.Length == CellWidth && Regex.IsMatch(rest, @"^\d+$", RegexOptions.IgnoreCase)))
                    {
                        cellStart = token.Length;
                    }
                }

                // Outside the try as in the script: a negative width is an error of the whole event, not of the row
                var c = line.PadRight(cellStart + (Cells * CellWidth));
                try
                {
                    rows.Add(ReadRow(line, c, cellStart));
                }
#pragma warning disable CA1031 // The script skips a row on any error (catch without type)
                catch (Exception)
#pragma warning restore CA1031
                {
                    verbose("Table statistics: row " + i + " not readable, skipped");
                }
            }

            return rows.Count == 0 ? null : rows.ToArray();
        }

        private static PSObject ReadRow(string line, string padded, int cellStart)
        {
            // Evaluated in the order of the script; a blank cell is '0' + '' (PowerShell cannot cast blanks)
            var table = line.Substring(0, Math.Min(cellStart, line.Length)).Trim();
            var values = new long[Cells];
            for (var k = 0; k < Cells; k++)
            {
                values[k] = PowerShellSemantics.ToLong("0" + padded.Substring(cellStart + (k * CellWidth), CellWidth).Trim());
            }

            var row = new PSObject();
            row.Properties.Add(new PSNoteProperty("Table", table));
            for (var k = 0; k < Cells; k++)
            {
                row.Properties.Add(new PSNoteProperty(Columns[k], values[k]));
            }

            return row;
        }
    }
}
