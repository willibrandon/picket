using Picket.Report;
using System.Globalization;

namespace Picket.Tui;

/// <summary>
/// Represents a non-secret finding row displayed by the terminal UI.
/// </summary>
/// <param name="finding">The source non-secret finding summary.</param>
/// <param name="index">The one-based display index.</param>
internal sealed class PicketTuiFindingRow(ReportFindingSummary finding, int index)
{
    /// <summary>
    /// Gets the source non-secret finding summary.
    /// </summary>
    internal ReportFindingSummary Finding { get; } = finding;

    /// <summary>
    /// Gets the one-based display index.
    /// </summary>
    internal int Index { get; } = index;

    /// <summary>
    /// Gets the stable row key used by Hex1b table focus.
    /// </summary>
    internal string Key { get; } = CreateKey(finding, index);

    /// <summary>
    /// Gets the displayed rule identifier.
    /// </summary>
    internal string RuleId { get; } = EmptyAsUnknown(finding.RuleId);

    /// <summary>
    /// Gets the displayed path.
    /// </summary>
    internal string Path { get; } = EmptyAsUnknown(finding.Path);

    /// <summary>
    /// Gets the displayed line number.
    /// </summary>
    internal string Line { get; } = finding.Line == 0 ? "unknown" : finding.Line.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Gets the one-based start column, or zero when unavailable.
    /// </summary>
    internal int StartColumn { get; } = finding.StartColumn;

    /// <summary>
    /// Gets the displayed source location.
    /// </summary>
    internal string Location { get; } = CreateLocation(finding);

    /// <summary>
    /// Gets the displayed fingerprint.
    /// </summary>
    internal string Fingerprint { get; } = EmptyAsUnknown(finding.Fingerprint);

    /// <summary>
    /// Gets the displayed randomness score and classification, or an empty string when unavailable.
    /// </summary>
    internal string Randomness { get; } = CreateRandomness(finding);

    /// <summary>
    /// Gets the displayed randomness model identifier, or an empty string when unavailable.
    /// </summary>
    internal string RandomnessModel { get; } = finding.RandomnessModel;

    private static string CreateKey(ReportFindingSummary finding, int index)
    {
        return string.Concat(
            index.ToString(CultureInfo.InvariantCulture),
            ":",
            finding.Fingerprint.Length == 0
                ? string.Concat(finding.RuleId, ":", finding.Path, ":", finding.Line.ToString(CultureInfo.InvariantCulture))
                : finding.Fingerprint);
    }

    private static string CreateLocation(ReportFindingSummary finding)
    {
        return finding.Line == 0
            ? EmptyAsUnknown(finding.Path)
            : string.Concat(finding.Path, ":", finding.Line.ToString(CultureInfo.InvariantCulture));
    }

    private static string CreateRandomness(ReportFindingSummary finding)
    {
        if (!finding.RandomnessScore.HasValue)
        {
            return string.Empty;
        }

        string score = finding.RandomnessScore.Value.ToString("0.######", CultureInfo.InvariantCulture);
        return finding.RandomnessClassification.Length == 0
            ? score
            : string.Concat(score, " (", finding.RandomnessClassification, ")");
    }

    private static string EmptyAsUnknown(string value)
    {
        return value.Length == 0 ? "unknown" : value;
    }
}
