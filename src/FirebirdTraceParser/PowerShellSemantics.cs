using System;
using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Management.Automation;

namespace FirebirdTraceParser
{
    /// <summary>
    /// What PowerShell does implicitly in Show-TraceStructure.ps1, made explicit so that both parsers behave the same
    /// (ADR-003): -eq on strings, [long] casts of text, hashtable keys without case.
    /// </summary>
    internal static class PowerShellSemantics
    {
        private const int MaxFastDigits = 18;

        /// <summary>PowerShell -eq for two strings: ignores case, invariant culture; $null equals nothing here.</summary>
        [SuppressMessage("Globalization", "CA1309", Justification = "PowerShell -eq compares linguistically (parity, ADR-003)")]
        public static bool Eq(string? left, string right) =>
            left != null && string.Compare(left, right, CultureInfo.InvariantCulture, CompareOptions.IgnoreCase) == 0;

        /// <summary>A PowerShell hashtable literal (@{}): keys compared with the current culture, ignoring case.</summary>
        public static Hashtable NewHashtable() => new Hashtable(StringComparer.CurrentCultureIgnoreCase);

        /// <summary>
        /// PowerShell [long]"text". Plain ASCII digits are parsed directly; anything else ("1e3", "0x1F", overflow) goes
        /// through LanguagePrimitives exactly like the cast in the script, including its exceptions.
        /// </summary>
        public static long ToLong(string text)
        {
            if (text.Length > 0 && text.Length <= MaxFastDigits)
            {
                long value = 0;
                var digits = true;
                foreach (var c in text)
                {
                    if (c < '0' || c > '9')
                    {
                        digits = false;
                        break;
                    }

                    value = (value * 10) + (c - '0');
                }

                if (digits)
                {
                    return value;
                }
            }

            return (long)LanguagePrimitives.ConvertTo(text, typeof(long), CultureInfo.InvariantCulture);
        }
    }
}
