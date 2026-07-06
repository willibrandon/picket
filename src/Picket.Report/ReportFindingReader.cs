using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text.Json;
using Picket.Engine;

namespace Picket.Report;

/// <summary>
/// Reads finding records from reports that preserve raw secret material.
/// </summary>
public static class ReportFindingReader
{
    /// <summary>
    /// Attempts to read findings from a supported report file.
    /// </summary>
    /// <param name="path">The report path to read.</param>
    /// <param name="findings">The findings read from the report when the format is supported.</param>
    /// <returns><see langword="true" /> when the report format is supported and findings were read.</returns>
    public static bool TryRead(string path, [NotNullWhen(true)] out List<Finding>? findings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            if (Path.GetExtension(path).Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
            {
                return TryReadJsonLines(path, out findings);
            }

            using FileStream stream = File.OpenRead(path);
            using JsonDocument document = JsonDocument.Parse(stream);
            return TryReadJson(document.RootElement, out findings);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or InvalidOperationException or FormatException)
        {
            findings = null;
            return false;
        }
    }

    private static bool TryReadJsonLines(string path, [NotNullWhen(true)] out List<Finding>? findings)
    {
        var result = new List<Finding>();
        foreach (string line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using JsonDocument document = JsonDocument.Parse(line);
            if (!TryReadPicketFinding(document.RootElement, out Finding? finding))
            {
                findings = null;
                return false;
            }

            result.Add(finding);
        }

        findings = result;
        return true;
    }

    private static bool TryReadJson(JsonElement root, [NotNullWhen(true)] out List<Finding>? findings)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            return TryReadGitleaksJson(root, out findings);
        }

        if (root.ValueKind != JsonValueKind.Object)
        {
            findings = null;
            return false;
        }

        string schema = GetString(root, "schema");
        if (schema.Equals("picket.report.v1", StringComparison.Ordinal))
        {
            return TryReadPicketReport(root, out findings);
        }

        if (schema.Equals("picket.finding.v1", StringComparison.Ordinal)
            && TryReadPicketFinding(root, out Finding? finding))
        {
            findings = [finding];
            return true;
        }

        findings = null;
        return false;
    }

    private static bool TryReadPicketReport(JsonElement root, [NotNullWhen(true)] out List<Finding>? findings)
    {
        if (!root.TryGetProperty("findings", out JsonElement findingsElement)
            || findingsElement.ValueKind != JsonValueKind.Array)
        {
            findings = null;
            return false;
        }

        var result = new List<Finding>();
        foreach (JsonElement findingElement in findingsElement.EnumerateArray())
        {
            if (!TryReadPicketFinding(findingElement, out Finding? finding))
            {
                findings = null;
                return false;
            }

            result.Add(finding);
        }

        findings = result;
        return true;
    }

    private static bool TryReadPicketFinding(JsonElement element, [NotNullWhen(true)] out Finding? finding)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !GetString(element, "schema").Equals("picket.finding.v1", StringComparison.Ordinal))
        {
            finding = null;
            return false;
        }

        finding = new Finding(
            GetString(element, "ruleId"),
            GetString(element, "description"),
            GetInt32(element, "startLine"),
            GetInt32(element, "endLine"),
            GetInt32(element, "startColumn"),
            GetInt32(element, "endColumn"),
            GetString(element, "match"),
            GetString(element, "secret"),
            GetString(element, "file"),
            GetString(element, "symlinkFile"),
            GetString(element, "commit"),
            GetDouble(element, "entropy"),
            GetString(element, "author"),
            GetString(element, "email"),
            GetString(element, "date"),
            GetString(element, "message"),
            GetStringArray(element, "tags"),
            GetString(element, "fingerprint"),
            GetString(element, "line"),
            GetString(element, "link"),
            GetString(element, "secretSha256"),
            GetString(element, "matchSha256"),
            GetString(element, "validationState"),
            GetString(element, "blobSha256"),
            GetStringArray(element, "decodePath"));
        return true;
    }

    private static bool TryReadGitleaksJson(JsonElement root, [NotNullWhen(true)] out List<Finding>? findings)
    {
        var result = new List<Finding>();
        foreach (JsonElement element in root.EnumerateArray())
        {
            if (!TryReadGitleaksFinding(element, out Finding? finding))
            {
                findings = null;
                return false;
            }

            result.Add(finding);
        }

        findings = result;
        return true;
    }

    private static bool TryReadGitleaksFinding(JsonElement element, [NotNullWhen(true)] out Finding? finding)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty("RuleID", out _))
        {
            finding = null;
            return false;
        }

        finding = new Finding(
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
        return true;
    }

    private static string GetString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return string.Empty;
        }

        return property.ValueKind == JsonValueKind.String ? property.GetString() ?? string.Empty : string.Empty;
    }

    private static int GetInt32(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out int number))
        {
            return number;
        }

        return property.ValueKind == JsonValueKind.String
            && int.TryParse(property.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)
                ? number
                : 0;
    }

    private static double GetDouble(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetDouble(out double number))
        {
            return number;
        }

        return property.ValueKind == JsonValueKind.String
            && double.TryParse(property.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number)
                ? number
                : 0;
    }

    private static List<string> GetStringArray(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var values = new List<string>();
        foreach (JsonElement item in property.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                values.Add(item.GetString() ?? string.Empty);
            }
        }

        return values;
    }
}
