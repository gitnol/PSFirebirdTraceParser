using System;
using System.Text.RegularExpressions;

namespace FirebirdTraceParser
{
    /// <summary>
    /// Regex of the parser. Patterns and options are copied literally from Show-TraceStructure.ps1 (ADR-003): any change
    /// must be made in both places, the parity test fails otherwise. Line breaks that the script writes literally inside
    /// a pattern are written as \n here (same meaning for the regex engine). Example lines are fictitious.
    /// </summary>
    internal sealed class TracePatterns
    {
        private const RegexOptions MultilineCompiled = RegexOptions.Multiline | RegexOptions.Compiled;
        private const RegexOptions SinglelineCompiled = RegexOptions.Singleline | RegexOptions.Compiled;

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

            // "335544665 : violation of PRIMARY or UNIQUE KEY constraint" (%9lu : <text>)
            ErrorLine = new Regex(@"^\s*(?<Code>\d{1,10})\s:\s(?<Message>.*?)\s*$", MultilineCompiled, timeout);

            // "<db path> (ATT_n, USER:ROLE, charset, TCPv4:192.0.2.10/50123 | XNET:HOST | <internal>)"
            Db = new Regex(
                @"^\s+(?<DatabasePath>\S.*?)\s+\(ATT_(?<AttachID>\d+),\s+(?<User>[^,]+),\s+(?<Encoding>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>[A-Za-z0-9]+):(?<IPAddress>[^/)]+)(?:/(?<Port>\d+))?|<[^>]+>)\)",
                MultilineCompiled, timeout);

            // "C:\Program Files\SampleApp\app.exe:5678" (not the connection line)
            App = new Regex(
                @"(?im)^\s+(?!.*\(ATT_)(?<ApplicationPath>(?:[a-z]:|\\\\).+?):(?<ApplicationPID>\d+)\s*$",
                MultilineCompiled, timeout);

            // "(TRA_345, INIT_340, CONCURRENCY | WAIT | READ_WRITE)"
            Tx = new Regex(@"^\s+\(TRA_(?<TransactionID>\d+)(?:,\s+INIT_(?<InitID>\d+))?,\s+(?<TxOpts>.+?)\)", MultilineCompiled, timeout);

            // Text after "Statement n:" and the dashes, up to plan, parameters, statistics or performance
            Sql = new Regex(
                @"Statement\s+\d+:\s*[\r\n]+(?:-{3,}[\r\n]+)(?<SqlStatement>.+?)(?=(?m)[\r\n]+\s*(\^{4,}|PLAN \(|param\d+|[0-9]+\s+records? fetched|\d+\s+ms|Table\s+Natural))",
                SinglelineCompiled, timeout);

            Plan = new Regex(@"(?<SqlPlan>(?:^\s*PLAN\b.*[\r\n]?)+)", MultilineCompiled, timeout);

            TableStats = new Regex(@"(?<TableStats>Table\s+Natural.+?[\r\n]+\*+[\r\n]+(?:.+[\r\n]?)+)", SinglelineCompiled, timeout);

            // "service_mgr, (Service <address>, <user>, <protocol:address>[, <process>:<pid>])"
            Service = new Regex(
                @"^\s+service_mgr,\s+\(Service\s+(?<ServiceID>(?:0x)?[0-9A-Fa-f]+),\s+(?<User>[^,]+),\s+(?<ProtocolInfo>(?<Protocol>[A-Za-z0-9]+):(?<IPAddress>[^/,)]+)(?:/(?<Port>\d+))?|[^,)]+)(?:,\s+(?<ApplicationPath>.+):(?<ApplicationPID>\d+))?\)\s*$",
                MultilineCompiled, timeout);

            // "\"Backup Database\"" on a line of its own
            ServiceName = new Regex(@"^\s+""(?<ServiceName>[^""\n]+)""\s*$", MultilineCompiled, timeout);

            // "Transaction counters:" block of SWEEP_START / SWEEP_FINISH
            Sweep = new Regex(
                @"^\s*Oldest interesting\s+(?<OIT>\d+)\s*\n\s*Oldest active\s+(?<OAT>\d+)\s*\n\s*Oldest snapshot\s+(?<OST>\d+)\s*\n\s*Next transaction\s+(?<Next>\d+)",
                MultilineCompiled, timeout);

            // "Procedure SAMPLE_PROC:" / "Function SAMPLE_FN:"
            Routine = new Regex(@"^(?<Type>Procedure|Function) (?<Name>.+?):[ \t]*$", MultilineCompiled, timeout);

            // Firebird 5 "Trigger <name> FOR <table> (<when> <action>):", Firebird 4 "<TAB><name> FOR <table> (<when> <action>) "
            Trigger = new Regex(
                @"^(?:Trigger(?: (?<Name>.+?))?|[ \t]+(?<Name>.+?))(?: FOR (?<Table>.+?))? \((?<Time>BEFORE|AFTER|ON|<unknown>) (?<Event>[^)]+)\):?[ \t]*$",
                MultilineCompiled, timeout);

            Params = new Regex(@"(?<Params>(?:^\s*param\d+\s*=\s*.+[\r\n]?)+)", MultilineCompiled, timeout);

            // "    420 ms, 310 read(s), 1 write(s), 25000 fetch(es), 3 mark(s)"
            Perf = new Regex(
                @"^\s+(?<DurationMs>\d+)\s+ms(?:,\s+(?<Reads>\d+)\s+read\(s\))?(?:,\s+(?<Writes>\d+)\s+write\(s\))?(?:,\s+(?<Fetches>\d+)\s+fetch\(es\))?(?:,\s+(?<Marks>\d+)\s+mark\(s\))?",
                MultilineCompiled, timeout);
        }

        public Regex Header { get; }
        public Regex ErrorLine { get; }
        public Regex Db { get; }
        public Regex App { get; }
        public Regex Tx { get; }
        public Regex Sql { get; }
        public Regex Plan { get; }
        public Regex TableStats { get; }
        public Regex Service { get; }
        public Regex ServiceName { get; }
        public Regex Sweep { get; }
        public Regex Routine { get; }
        public Regex Trigger { get; }
        public Regex Params { get; }
        public Regex Perf { get; }
    }
}
