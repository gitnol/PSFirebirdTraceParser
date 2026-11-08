using System;
using System.Management.Automation;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Fields of one trace event, in the order of the output contract (docs/features/TRACE_PARSING.md). The names are
    /// the property names of the output object; keep them identical to Show-TraceStructure.ps1.
    /// </summary>
    internal enum TraceField
    {
        Timestamp, Action, ProcessID, SessionID,
        DatabasePath, AttachID, User, ProtocolInfo,
        ClientIP, ClientPort,
        ApplicationPath, ApplicationPID,
        TransactionID, RootTxID, TransactionOptions,
        Params,
        SqlStatement, SqlPlan,
        TableStats,
        DurationMs, Reads, Writes, Fetches, Marks,
        ErrorSource, ErrorCodes, ErrorMessages,
        ServiceName, ServiceID,
        SweepOIT, SweepOAT, SweepOST, SweepNext,
        RecordsFetched,
        TxIsolation, TxReadMode, TxWaitMode, TxLockTimeout, TxAccessMode,
        TableCounts,
        RoutineType, RoutineName,
        TriggerTable, TriggerTime, TriggerEvent,
        ConnectionDurationMs,
    }

    /// <summary>Values of one event: defaults as in the script, then filled by the block parser.</summary>
    internal sealed class TraceEntry
    {
        private static readonly string[] Names = Enum.GetNames<TraceField>();
        private readonly object?[] _values = new object?[Names.Length];

        public TraceEntry()
        {
            this[TraceField.RootTxID] = "NoTx";
            this[TraceField.DurationMs] = 0L;
            this[TraceField.Reads] = 0L;
            this[TraceField.Writes] = 0L;
            this[TraceField.Fetches] = 0L;
            this[TraceField.Marks] = 0L;
            this[TraceField.RecordsFetched] = 0L;
        }

        public object? this[TraceField field]
        {
            get => _values[(int)field];
            set => _values[(int)field] = value;
        }

        /// <summary>Text value of a field ($null when not set or not a string).</summary>
        public string? Text(TraceField field) => _values[(int)field] as string;

        /// <summary>The output object: a PSCustomObject with one NoteProperty per field, like [PSCustomObject]$entry.</summary>
        public PSObject ToPSObject()
        {
            var result = new PSObject();
            for (var i = 0; i < Names.Length; i++)
            {
                result.Properties.Add(new PSNoteProperty(Names[i], _values[i]));
            }

            return result;
        }
    }
}
