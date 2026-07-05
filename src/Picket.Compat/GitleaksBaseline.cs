using System.Text.Json;
using Picket.Engine;

namespace Picket.Compat;

/// <summary>
/// Represents a Gitleaks-compatible baseline report used to suppress existing findings.
/// </summary>
/// <param name="findings">Findings loaded from an existing Gitleaks JSON report.</param>
public sealed class GitleaksBaseline(IReadOnlyList<Finding> findings)
{
    private readonly IReadOnlyList<Finding> _findings = findings ?? throw new ArgumentNullException(nameof(findings));

    /// <summary>
    /// Gets an empty baseline.
    /// </summary>
    public static GitleaksBaseline Empty { get; } = new([]);

    /// <summary>
    /// Gets the number of findings in the baseline.
    /// </summary>
    public int Count => _findings.Count;

    /// <summary>
    /// Loads a Gitleaks JSON report from disk as a baseline.
    /// </summary>
    /// <param name="path">The report path.</param>
    /// <returns>The loaded baseline.</returns>
    public static GitleaksBaseline Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            using FileStream stream = File.OpenRead(path);
            return new GitleaksBaseline(ReadFindings(stream, path));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException($"could not open {path}", exception);
        }
    }

    /// <summary>
    /// Returns findings not already present in this baseline.
    /// </summary>
    /// <param name="findings">Findings to filter.</param>
    /// <param name="redactionPercent">The active redaction percentage.</param>
    /// <returns>The findings that are new relative to the baseline.</returns>
    public IReadOnlyList<Finding> Filter(IReadOnlyList<Finding> findings, int redactionPercent = 0)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ValidateRedactionPercent(redactionPercent);

        if (_findings.Count == 0 || findings.Count == 0)
        {
            return findings;
        }

        var filtered = new List<Finding>(findings.Count);
        foreach (Finding finding in findings)
        {
            if (IsNew(finding, redactionPercent))
            {
                filtered.Add(finding);
            }
        }

        return filtered;
    }

    /// <summary>
    /// Returns a value indicating whether a finding is new relative to this baseline.
    /// </summary>
    /// <param name="finding">The finding to test.</param>
    /// <param name="redactionPercent">The active redaction percentage.</param>
    /// <returns><see langword="true" /> when the finding is not present in the baseline.</returns>
    public bool IsNew(Finding finding, int redactionPercent = 0)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ValidateRedactionPercent(redactionPercent);

        foreach (Finding baselineFinding in _findings)
        {
            if (Matches(finding, baselineFinding, redactionPercent))
            {
                return false;
            }
        }

        return true;
    }

    private static List<Finding> ReadFindings(Stream stream, string path)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(stream);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException();
            }

            var findings = new List<Finding>();
            foreach (JsonElement element in document.RootElement.EnumerateArray())
            {
                findings.Add(ReadFinding(element));
            }

            return findings;
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or InvalidOperationException or FormatException)
        {
            throw new InvalidDataException($"the format of the file {path} is not supported", exception);
        }
    }

    private static Finding ReadFinding(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }

        return new Finding(
            GetString(element, "RuleID"),
            GetString(element, "Description"),
            GetInt32(element, "StartLine"),
            GetInt32(element, "EndLine"),
            GetInt32(element, "StartColumn"),
            GetInt32(element, "EndColumn"),
            GetString(element, "Match"),
            GetString(element, "Secret"),
            GetString(element, "File"),
            GetString(element, "SymlinkFile"),
            GetString(element, "Commit"),
            GetDouble(element, "Entropy"),
            GetString(element, "Author"),
            GetString(element, "Email"),
            GetString(element, "Date"),
            GetString(element, "Message"),
            GetStringArray(element, "Tags"),
            GetString(element, "Fingerprint"),
            link: GetString(element, "Link"));
    }

    private static string GetString(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return string.Empty;
        }

        return property.GetString() ?? string.Empty;
    }

    private static int GetInt32(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        return property.GetInt32();
    }

    private static double GetDouble(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        return property.GetDouble();
    }

    private static List<string> GetStringArray(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return [];
        }

        if (property.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException();
        }

        var values = new List<string>();
        foreach (JsonElement item in property.EnumerateArray())
        {
            values.Add(item.GetString() ?? string.Empty);
        }

        return values;
    }

    private static bool Matches(Finding finding, Finding baselineFinding, int redactionPercent)
    {
        return finding.RuleID == baselineFinding.RuleID
            && finding.Description == baselineFinding.Description
            && finding.StartLine == baselineFinding.StartLine
            && finding.EndLine == baselineFinding.EndLine
            && finding.StartColumn == baselineFinding.StartColumn
            && finding.EndColumn == baselineFinding.EndColumn
            && (redactionPercent > 0 || (finding.Match == baselineFinding.Match && finding.Secret == baselineFinding.Secret))
            && finding.File == baselineFinding.File
            && finding.Commit == baselineFinding.Commit
            && finding.Author == baselineFinding.Author
            && finding.Email == baselineFinding.Email
            && finding.Date == baselineFinding.Date
            && finding.Message == baselineFinding.Message
            && finding.Entropy == baselineFinding.Entropy;
    }

    private static void ValidateRedactionPercent(int redactionPercent)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(redactionPercent);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(redactionPercent, 100);
    }
}
