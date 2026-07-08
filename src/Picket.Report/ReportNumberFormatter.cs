using System.Globalization;

namespace Picket.Report;

internal static class ReportNumberFormatter
{
    internal static string FormatJsonDouble(double value)
    {
        return double.IsFinite(value) ? value.ToString("G17", CultureInfo.InvariantCulture) : "0";
    }

    internal static string FormatGitleaksFloat(double value)
    {
        float narrowed = (float)value;
        return float.IsFinite(narrowed) ? narrowed.ToString("G", CultureInfo.InvariantCulture) : "0";
    }
}
