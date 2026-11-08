using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.RegularExpressions;

namespace FirebirdTraceParser
{
    /// <summary>
    /// One trace event (block of lines) -> one entry. Mirrors ConvertFrom-TraceBlock in Show-TraceStructure.ps1 section by
    /// section, in the same order and with the same .NET calls (ADR-003). Only state across blocks: open connections.
    /// </summary>
    [SuppressMessage("Globalization", "CA1307", Justification = "Same culture-sensitive string calls as the script (parity, ADR-003)")]
    [SuppressMessage("Globalization", "CA1310", Justification = "Same culture-sensitive string calls as the script (parity, ADR-003)")]
    [SuppressMessage("Performance", "CA1866", Justification = "LastIndexOf(string) is culture-sensitive, the char overload is not (parity, ADR-003)")]
    internal sealed class TraceBlockParser
    {
        private const string RecordsFetchedMarker = " records fetched";
        private const string TimestampFormat = "yyyy-MM-ddTHH:mm:ss.FFFFFFF";
        private const string WaitPrefix = "WAIT ";

        private readonly TracePatterns _rx;
        private readonly Action<string> _verbose;

        // Parts of the transaction line -> field (Firebird register_transaction); a hashtable literal in the script
        private readonly System.Collections.Hashtable _txOptionField = PowerShellSemantics.NewHashtable();

        // Open connections for ConnectionDurationMs: "<database>|<ATT number>" -> time of ATTACH_DATABASE/CREATE_DATABASE
        private readonly Dictionary<string, DateTime> _openAttach = new Dictionary<string, DateTime>();

        public TraceBlockParser(TimeSpan regexTimeout, Action<string> verbose)
        {
            _rx = new TracePatterns(regexTimeout);
            _verbose = verbose;
            foreach (var p in new[] { "READ_COMMITTED", "CONCURRENCY", "CONSISTENCY", "<unknown>" }) { _txOptionField[p] = TraceField.TxIsolation; }
            foreach (var p in new[] { "REC_VERSION", "NO_REC_VERSION", "READ_CONSISTENCY" }) { _txOptionField[p] = TraceField.TxReadMode; }
            foreach (var p in new[] { "WAIT", "NOWAIT" }) { _txOptionField[p] = TraceField.TxWaitMode; }
            foreach (var p in new[] { "READ_WRITE", "READ_ONLY" }) { _txOptionField[p] = TraceField.TxAccessMode; }
        }

        public TraceEntry Parse(string text, int start, int length)
        {
            var block = text.Substring(start, length);
            var entry = new TraceEntry();
            ReadHeader(block, entry);
            ReadErrorLines(block, entry);
            ReadConnection(block, entry);
            var hasStatement = block.Contains("Statement ");
            ReadRoutineOrDuration(block, entry, hasStatement);
            ReadService(block, entry);
            ReadSweep(block, entry);
            ReadTransaction(block, entry);
            ReadStatement(block, entry, hasStatement);
            ReadRecordsFetched(block, entry);
            ReadPerformance(block, entry);
            return entry;
        }

        private static void Set(TraceEntry entry, TraceField field, Match m, string group) => entry[field] = m.Groups[group].Value;

        private void ReadHeader(string block, TraceEntry entry)
        {
            var m = _rx.Header.Match(block);
            if (!m.Success)
            {
                return;
            }

            Set(entry, TraceField.Timestamp, m, "Timestamp");
            Set(entry, TraceField.Action, m, "Action");
            Set(entry, TraceField.ProcessID, m, "ProcessID");
            Set(entry, TraceField.SessionID, m, "SessionID");
            if (m.Groups["ErrorSource"].Success)
            {
                Set(entry, TraceField.ErrorSource, m, "ErrorSource");
            }
        }

        private void ReadErrorLines(string block, TraceEntry entry)
        {
            var action = entry.Text(TraceField.Action);
            if (!PowerShellSemantics.Eq(action, "ERROR") && !PowerShellSemantics.Eq(action, "WARNING"))
            {
                return;
            }

            var codes = new List<string>();
            var messages = new List<string>();
            foreach (Match em in _rx.ErrorLine.Matches(block))
            {
                codes.Add(em.Groups["Code"].Value);
                messages.Add(em.Groups["Message"].Value);
            }

            if (codes.Count > 0)
            {
                entry[TraceField.ErrorCodes] = string.Join(", ", codes);
                entry[TraceField.ErrorMessages] = string.Join(" | ", messages);
            }
        }

        private void ReadConnection(string block, TraceEntry entry)
        {
            var m = _rx.Db.Match(block);
            if (m.Success)
            {
                Set(entry, TraceField.DatabasePath, m, "DatabasePath");
                Set(entry, TraceField.AttachID, m, "AttachID");
                Set(entry, TraceField.User, m, "User");
                Set(entry, TraceField.ProtocolInfo, m, "ProtocolInfo");
                Set(entry, TraceField.ClientIP, m, "IPAddress");
                Set(entry, TraceField.ClientPort, m, "Port");
            }

            m = _rx.App.Match(block);
            if (m.Success)
            {
                Set(entry, TraceField.ApplicationPath, m, "ApplicationPath");
                Set(entry, TraceField.ApplicationPID, m, "ApplicationPID");
            }
        }

        // Statement events (most blocks) carry neither a connection end nor a routine: both checks are skipped for them
        private void ReadRoutineOrDuration(string block, TraceEntry entry, bool hasStatement)
        {
            var action = entry.Text(TraceField.Action);
            if (string.IsNullOrEmpty(action) || hasStatement)
            {
                return;
            }

            if (action!.EndsWith("_DATABASE"))
            {
                ReadConnectionDuration(entry, action);
            }
            else if (action.Contains("TRIGGER"))
            {
                var m = _rx.Trigger.Match(block);
                if (m.Success)
                {
                    entry[TraceField.RoutineType] = "Trigger";
                    var name = m.Groups["Name"].Value;
                    if (name.Length > 0 && !PowerShellSemantics.Eq(name, "<unknown>"))
                    {
                        entry[TraceField.RoutineName] = name;
                    }

                    if (m.Groups["Table"].Success)
                    {
                        Set(entry, TraceField.TriggerTable, m, "Table");
                    }

                    Set(entry, TraceField.TriggerTime, m, "Time");
                    Set(entry, TraceField.TriggerEvent, m, "Event");
                }
            }
            else if (action.Contains("PROCEDURE") || action.Contains("FUNCTION"))
            {
                var m = _rx.Routine.Match(block);
                if (m.Success)
                {
                    Set(entry, TraceField.RoutineType, m, "Type");
                    Set(entry, TraceField.RoutineName, m, "Name");
                }
            }
        }

        private void ReadConnectionDuration(TraceEntry entry, string action)
        {
            var attachId = entry.Text(TraceField.AttachID);
            if (string.IsNullOrEmpty(attachId)
                || !DateTime.TryParseExact(entry.Text(TraceField.Timestamp), TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp))
            {
                return;
            }

            var key = entry.Text(TraceField.DatabasePath) + "|" + attachId;
            if (PowerShellSemantics.Eq(action, "ATTACH_DATABASE") || PowerShellSemantics.Eq(action, "CREATE_DATABASE"))
            {
                _openAttach[key] = stamp;
            }
            else if (PowerShellSemantics.Eq(action, "DETACH_DATABASE") && _openAttach.TryGetValue(key, out var opened))
            {
                entry[TraceField.ConnectionDurationMs] = (long)Math.Round((stamp - opened).TotalMilliseconds);
                _openAttach.Remove(key);
            }
        }

        private void ReadService(string block, TraceEntry entry)
        {
            var action = entry.Text(TraceField.Action);
            if (string.IsNullOrEmpty(action) || !action!.EndsWith("_SERVICE"))
            {
                return;
            }

            var m = _rx.Service.Match(block);
            if (m.Success)
            {
                Set(entry, TraceField.ServiceID, m, "ServiceID");
                Set(entry, TraceField.User, m, "User");
                Set(entry, TraceField.ProtocolInfo, m, "ProtocolInfo");
                if (m.Groups["IPAddress"].Success) { Set(entry, TraceField.ClientIP, m, "IPAddress"); }
                if (m.Groups["Port"].Success) { Set(entry, TraceField.ClientPort, m, "Port"); }
                if (m.Groups["ApplicationPath"].Success)
                {
                    Set(entry, TraceField.ApplicationPath, m, "ApplicationPath");
                    Set(entry, TraceField.ApplicationPID, m, "ApplicationPID");
                }
            }

            m = _rx.ServiceName.Match(block);
            if (m.Success)
            {
                Set(entry, TraceField.ServiceName, m, "ServiceName");
            }
        }

        private void ReadSweep(string block, TraceEntry entry)
        {
            if (!block.Contains("Transaction counters"))
            {
                return;
            }

            var m = _rx.Sweep.Match(block);
            if (m.Success)
            {
                entry[TraceField.SweepOIT] = PowerShellSemantics.ToLong(m.Groups["OIT"].Value);
                entry[TraceField.SweepOAT] = PowerShellSemantics.ToLong(m.Groups["OAT"].Value);
                entry[TraceField.SweepOST] = PowerShellSemantics.ToLong(m.Groups["OST"].Value);
                entry[TraceField.SweepNext] = PowerShellSemantics.ToLong(m.Groups["Next"].Value);
            }
        }

        private void ReadTransaction(string block, TraceEntry entry)
        {
            var m = _rx.Tx.Match(block);
            if (!m.Success)
            {
                return;
            }

            Set(entry, TraceField.TransactionID, m, "TransactionID");
            var initId = m.Groups["InitID"].Value;
            var options = m.Groups["TxOpts"].Value;
            entry[TraceField.TransactionOptions] = options;

            // "READ_COMMITTED | REC_VERSION | WAIT 10 | READ_WRITE" -> separate fields
            foreach (var part in options.Split('|'))
            {
                var p = part.Trim();
                if (_txOptionField[p] is TraceField field)
                {
                    entry[field] = p;
                }
                else if (p.StartsWith(WaitPrefix) && int.TryParse(p.AsSpan(WaitPrefix.Length), out var timeout))
                {
                    entry[TraceField.TxWaitMode] = "WAIT";
                    entry[TraceField.TxLockTimeout] = timeout;
                }
            }

            if (!string.IsNullOrWhiteSpace(initId))
            {
                entry[TraceField.RootTxID] = initId;
            }
            else if (!string.IsNullOrWhiteSpace(entry.Text(TraceField.TransactionID)))
            {
                entry[TraceField.RootTxID] = entry.Text(TraceField.TransactionID);
            }
        }

        private void ReadStatement(string block, TraceEntry entry, bool hasStatement)
        {
            // Cheap pre-checks before each regex, as in the script
            var m = hasStatement ? _rx.Sql.Match(block) : Match.Empty;
            if (m.Success) { entry[TraceField.SqlStatement] = m.Groups["SqlStatement"].Value.Trim(); }

            m = block.Contains("param") ? _rx.Params.Match(block) : Match.Empty;
            if (m.Success) { entry[TraceField.Params] = m.Groups["Params"].Value.Trim(); }

            m = block.Contains("PLAN") ? _rx.Plan.Match(block) : Match.Empty;
            if (m.Success) { entry[TraceField.SqlPlan] = m.Groups["SqlPlan"].Value.Trim(); }

            m = block.Contains("Natural") ? _rx.TableStats.Match(block) : Match.Empty;
            if (m.Success)
            {
                var stats = m.Groups["TableStats"].Value; // not trimmed: column alignment
                entry[TraceField.TableStats] = stats;
                entry[TraceField.TableCounts] = TableStatParser.Parse(stats, _verbose);
            }
        }

        private static void ReadRecordsFetched(string block, TraceEntry entry)
        {
            // The number is the whole line before the marker; an occurrence inside the SQL text is skipped
            var at = block.IndexOf(RecordsFetchedMarker, StringComparison.Ordinal);
            while (at > 0)
            {
                var lineStart = block.LastIndexOf("\n", at - 1) + 1;
                if (long.TryParse(block.AsSpan(lineStart, at - lineStart), NumberStyles.None, null, out var rows))
                {
                    entry[TraceField.RecordsFetched] = rows;
                    break;
                }

                at = block.IndexOf(RecordsFetchedMarker, at + 1, StringComparison.Ordinal);
            }
        }

        private void ReadPerformance(string block, TraceEntry entry)
        {
            var m = block.Contains(" ms") ? _rx.Perf.Match(block) : Match.Empty;
            if (!m.Success)
            {
                return;
            }

            entry[TraceField.DurationMs] = PowerShellSemantics.ToLong(m.Groups["DurationMs"].Value);
            foreach (var (field, group) in new[] { (TraceField.Reads, "Reads"), (TraceField.Writes, "Writes"), (TraceField.Fetches, "Fetches"), (TraceField.Marks, "Marks") })
            {
                if (m.Groups[group].Success)
                {
                    entry[field] = PowerShellSemantics.ToLong(m.Groups[group].Value);
                }
            }
        }
    }
}
