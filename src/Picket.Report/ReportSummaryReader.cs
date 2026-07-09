using System.Globalization;
using System.Text.Json;

namespace Picket.Report;

/// <summary>
/// Reads non-secret summaries from Picket, Gitleaks, and SARIF report files.
/// </summary>
public static class ReportSummaryReader
{
    /// <summary>
    /// Reads a non-secret summary from a report file.
    /// </summary>
    /// <param name="path">The report path to read.</param>
    /// <returns>The detected report summary.</returns>
    public static ReportSummary Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            if (Path.GetExtension(path).Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
            {
                return ReadJsonLines(path);
            }

            if (IsHtmlReportPath(path))
            {
                return ReadHtml(path);
            }

            using FileStream stream = File.OpenRead(path);
            using JsonDocument document = JsonDocument.Parse(stream);
            return ReadJsonDocument(document.RootElement, path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException($"could not open {path}", exception);
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or InvalidOperationException or FormatException or ArgumentOutOfRangeException)
        {
            throw new InvalidDataException($"the format of the file {path} is not supported", exception);
        }
    }

    private static ReportSummary ReadJsonLines(string path)
    {
        var findings = new List<ReportFindingSummary>();
        string? format = null;
        try
        {
            foreach (string line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                using JsonDocument document = JsonDocument.Parse(line);
                format ??= IsTruffleHogFinding(document.RootElement) ? "trufflehog-jsonl" : "picket-jsonl";
                findings.Add(format.Equals("trufflehog-jsonl", StringComparison.Ordinal)
                    ? ReadTruffleHogFinding(document.RootElement)
                    : ReadPicketFinding(document.RootElement));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException($"could not open {path}", exception);
        }

        return new ReportSummary(format ?? "picket-jsonl", findings);
    }

    private static ReportSummary ReadHtml(string path)
    {
        string html = File.ReadAllText(path);
        string json = ExtractPicketHtmlSummaryJson(html);
        using JsonDocument document = JsonDocument.Parse(json);
        return ReadPicketHtmlSummary(document.RootElement);
    }

    private static ReportSummary ReadPicketHtmlSummary(JsonElement root)
    {
        if (!GetString(root, "schema").Equals("picket.html-summary.v1", StringComparison.Ordinal)
            || !root.TryGetProperty("findings", out JsonElement findingsElement)
            || findingsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException();
        }

        var findings = new List<ReportFindingSummary>();
        foreach (JsonElement finding in findingsElement.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException();
            }

            findings.Add(new ReportFindingSummary(
                GetString(finding, "ruleId"),
                GetString(finding, "path"),
                GetInt32(finding, "line"),
                GetString(finding, "fingerprint"),
                GetInt32(finding, "startColumn")));
        }

        return new ReportSummary("picket-html", findings);
    }

    private static string ExtractPicketHtmlSummaryJson(string html)
    {
        const string summaryId = "id=\"picket-report-summary\"";
        int searchIndex = 0;
        while (searchIndex < html.Length)
        {
            int templateStart = html.IndexOf("<template", searchIndex, StringComparison.OrdinalIgnoreCase);
            if (templateStart < 0)
            {
                break;
            }

            int tagEnd = html.IndexOf('>', templateStart);
            if (tagEnd < 0)
            {
                throw new InvalidDataException();
            }

            ReadOnlySpan<char> tag = html.AsSpan(templateStart, tagEnd - templateStart + 1);
            if (tag.IndexOf(summaryId, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                int templateEnd = html.IndexOf("</template>", tagEnd + 1, StringComparison.OrdinalIgnoreCase);
                if (templateEnd < 0)
                {
                    throw new InvalidDataException();
                }

                return html[(tagEnd + 1)..templateEnd];
            }

            searchIndex = tagEnd + 1;
        }

        throw new InvalidDataException();
    }

    private static ReportSummary ReadJsonDocument(JsonElement root, string path)
    {
        return root.ValueKind switch
        {
            JsonValueKind.Array => ReadJsonArray(root, path),
            JsonValueKind.Object => ReadJsonObject(root, path),
            _ => throw new InvalidDataException(),
        };
    }

    private static ReportSummary ReadJsonArray(JsonElement root, string path)
    {
        foreach (JsonElement finding in root.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException();
            }

            if (finding.TryGetProperty("RuleID", out _))
            {
                return ReadGitleaksJson(root);
            }

            if (IsTruffleHogFinding(finding))
            {
                return ReadTruffleHogJson(root);
            }

            if (finding.TryGetProperty("check_name", out _) || finding.TryGetProperty("location", out _))
            {
                return ReadGitLabCodeQualityJson(root);
            }

            throw new InvalidDataException();
        }

        return new ReportSummary(IsGitLabCodeQualityReportPath(path) ? "gitlab-code-quality" : "gitleaks-json", []);
    }

    private static ReportSummary ReadJsonObject(JsonElement root, string path)
    {
        string schema = GetString(root, "schema");
        if (schema.Equals("picket.report.v1", StringComparison.Ordinal))
        {
            return ReadPicketJson(root);
        }

        if (schema.Equals("picket.finding.v1", StringComparison.Ordinal))
        {
            return new ReportSummary("picket-json", [ReadPicketFinding(root)]);
        }

        if (IsTruffleHogFinding(root))
        {
            return new ReportSummary("trufflehog-json", [ReadTruffleHogFinding(root)]);
        }

        if (root.TryGetProperty("results", out JsonElement results)
            && results.ValueKind == JsonValueKind.Array
            && IsTruffleHogResults(results))
        {
            return ReadTruffleHogJson(results);
        }

        if (GetString(root, "version").Equals("2.1.0", StringComparison.Ordinal) && root.TryGetProperty("runs", out _))
        {
            return ReadSarif(root);
        }

        if (Path.GetExtension(path).Equals(".sarif", StringComparison.OrdinalIgnoreCase))
        {
            return ReadSarif(root);
        }

        throw new InvalidDataException();
    }

    private static ReportSummary ReadPicketJson(JsonElement root)
    {
        var findings = new List<ReportFindingSummary>();
        if (!root.TryGetProperty("findings", out JsonElement findingsElement) || findingsElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException();
        }

        foreach (JsonElement finding in findingsElement.EnumerateArray())
        {
            findings.Add(ReadPicketFinding(finding));
        }

        return new ReportSummary("picket-json", findings);
    }

    private static ReportSummary ReadGitleaksJson(JsonElement root)
    {
        var findings = new List<ReportFindingSummary>();
        foreach (JsonElement finding in root.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException();
            }

            findings.Add(new ReportFindingSummary(
                GetString(finding, "RuleID"),
                GetDisplayPath(finding, "File", "SymlinkFile"),
                GetInt32(finding, "StartLine"),
                GetString(finding, "Fingerprint"),
                GetInt32(finding, "StartColumn")));
        }

        return new ReportSummary("gitleaks-json", findings);
    }

    private static ReportSummary ReadTruffleHogJson(JsonElement root)
    {
        var findings = new List<ReportFindingSummary>();
        foreach (JsonElement finding in root.EnumerateArray())
        {
            findings.Add(ReadTruffleHogFinding(finding));
        }

        return new ReportSummary("trufflehog-json", findings);
    }

    private static ReportSummary ReadGitLabCodeQualityJson(JsonElement root)
    {
        var findings = new List<ReportFindingSummary>();
        foreach (JsonElement finding in root.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException();
            }

            JsonElement location = GetObject(finding, "location");
            JsonElement lines = GetObject(location, "lines");
            findings.Add(new ReportFindingSummary(
                GetString(finding, "check_name"),
                GetString(location, "path"),
                GetInt32(lines, "begin"),
                GetString(finding, "fingerprint")));
        }

        return new ReportSummary("gitlab-code-quality", findings);
    }

    private static ReportFindingSummary ReadPicketFinding(JsonElement finding)
    {
        if (finding.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }

        return new ReportFindingSummary(
            GetString(finding, "ruleId"),
            GetDisplayPath(finding, "file", "symlinkFile"),
            GetInt32(finding, "startLine"),
            GetString(finding, "fingerprint"),
            GetInt32(finding, "startColumn"));
    }

    private static ReportFindingSummary ReadTruffleHogFinding(JsonElement finding)
    {
        if (finding.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }

        JsonElement sourceMetadata = finding.TryGetProperty("SourceMetadata", out JsonElement metadata)
            || finding.TryGetProperty("sourceMetadata", out metadata)
            ? metadata
            : default;
        string detectorName = GetFirstNonEmptyString(
            GetString(finding, "DetectorName"),
            GetString(finding, "detectorName"),
            GetString(finding, "DetectorDescription"),
            GetString(finding, "detectorDescription"),
            "unknown");
        string path = GetFirstNonEmptyString(
            FindString(sourceMetadata, "file", "path", "filename"),
            GetString(finding, "File"),
            GetString(finding, "file"));
        int line = GetFirstPositiveInt32(
            FindInt32(sourceMetadata, "line", "line_number", "linenumber", "startline"),
            GetOptionalInt32(finding, "Line"),
            GetOptionalInt32(finding, "line"));
        int startColumn = GetFirstPositiveInt32(
            FindInt32(sourceMetadata, "column", "col", "startcolumn", "start_column"),
            GetOptionalInt32(finding, "StartColumn"),
            GetOptionalInt32(finding, "startColumn"),
            GetOptionalInt32(finding, "column"));
        string fingerprint = GetFirstNonEmptyString(
            GetString(finding, "Fingerprint"),
            GetString(finding, "fingerprint"),
            CreateTruffleHogFingerprint(detectorName, path, line));

        return new ReportFindingSummary(detectorName, path, line, fingerprint, startColumn);
    }

    private static ReportSummary ReadSarif(JsonElement root)
    {
        var findings = new List<ReportFindingSummary>();
        if (!root.TryGetProperty("runs", out JsonElement runs) || runs.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException();
        }

        foreach (JsonElement run in runs.EnumerateArray())
        {
            if (!run.TryGetProperty("results", out JsonElement results) || results.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (JsonElement result in results.EnumerateArray())
            {
                findings.Add(ReadSarifResult(result));
            }
        }

        return new ReportSummary("sarif", findings);
    }

    private static ReportFindingSummary ReadSarifResult(JsonElement result)
    {
        if (result.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }

        JsonElement location = GetFirstArrayObject(result, "locations");
        JsonElement physicalLocation = GetObject(location, "physicalLocation");
        JsonElement artifactLocation = GetObject(physicalLocation, "artifactLocation");
        JsonElement region = GetObject(physicalLocation, "region");
        JsonElement partialFingerprints = result.TryGetProperty("partialFingerprints", out JsonElement fingerprints)
            && fingerprints.ValueKind == JsonValueKind.Object
            ? fingerprints
            : default;
        JsonElement properties = result.TryGetProperty("properties", out JsonElement resultProperties)
            && resultProperties.ValueKind == JsonValueKind.Object
            ? resultProperties
            : default;

        string fingerprint = GetString(properties, "fingerprint");
        if (fingerprint.Length == 0)
        {
            fingerprint = GetString(partialFingerprints, "picketFingerprint");
        }

        return new ReportFindingSummary(
            GetString(result, "ruleId"),
            GetString(artifactLocation, "uri"),
            GetInt32(region, "startLine"),
            fingerprint,
            GetInt32(region, "startColumn"));
    }

    private static JsonElement GetFirstArrayObject(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException();
        }

        foreach (JsonElement item in property.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object)
            {
                return item;
            }
        }

        throw new InvalidDataException();
    }

    private static bool IsTruffleHogResults(JsonElement results)
    {
        foreach (JsonElement result in results.EnumerateArray())
        {
            return IsTruffleHogFinding(result);
        }

        return false;
    }

    private static bool IsTruffleHogFinding(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        bool hasDetector = HasProperty(element, "DetectorName")
            || HasProperty(element, "detectorName")
            || HasProperty(element, "DetectorDescription")
            || HasProperty(element, "detectorDescription");
        bool hasSourceMetadata = HasProperty(element, "SourceMetadata") || HasProperty(element, "sourceMetadata");
        bool hasSecretEvidence = HasProperty(element, "Raw")
            || HasProperty(element, "raw")
            || HasProperty(element, "RawV2")
            || HasProperty(element, "rawV2")
            || HasProperty(element, "Redacted")
            || HasProperty(element, "redacted")
            || HasProperty(element, "SecretParts")
            || HasProperty(element, "secretParts");
        return hasDetector || (hasSourceMetadata && hasSecretEvidence);
    }

    private static bool HasProperty(JsonElement element, string name)
    {
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out _);
    }

    private static JsonElement GetObject(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out JsonElement property) || property.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException();
        }

        return property;
    }

    private static string GetDisplayPath(JsonElement element, string pathName, string symlinkPathName)
    {
        string symlinkPath = GetString(element, symlinkPathName);
        return symlinkPath.Length == 0 ? GetString(element, pathName) : symlinkPath;
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

    private static string FindString(JsonElement element, params string[] names)
    {
        return FindString(element, names, depth: 0);
    }

    private static string FindString(JsonElement element, string[] names, int depth)
    {
        if (depth > 16)
        {
            return string.Empty;
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (IsNamed(property.Name, names))
                {
                    string value = GetScalarString(property.Value);
                    if (value.Length != 0)
                    {
                        return value;
                    }
                }
            }

            foreach (JsonProperty property in element.EnumerateObject())
            {
                string value = FindString(property.Value, names, depth + 1);
                if (value.Length != 0)
                {
                    return value;
                }
            }
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                string value = FindString(item, names, depth + 1);
                if (value.Length != 0)
                {
                    return value;
                }
            }
        }

        return string.Empty;
    }

    private static int FindInt32(JsonElement element, params string[] names)
    {
        return FindInt32(element, names, depth: 0);
    }

    private static int FindInt32(JsonElement element, string[] names, int depth)
    {
        if (depth > 16)
        {
            return 0;
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (IsNamed(property.Name, names))
                {
                    int value = GetScalarInt32(property.Value);
                    if (value > 0)
                    {
                        return value;
                    }
                }
            }

            foreach (JsonProperty property in element.EnumerateObject())
            {
                int value = FindInt32(property.Value, names, depth + 1);
                if (value > 0)
                {
                    return value;
                }
            }
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                int value = FindInt32(item, names, depth + 1);
                if (value > 0)
                {
                    return value;
                }
            }
        }

        return 0;
    }

    private static int GetInt32(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        return GetScalarInt32(property);
    }

    private static int GetOptionalInt32(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        return GetScalarInt32(property);
    }

    private static string GetScalarString(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.ToString(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => string.Empty,
        };
    }

    private static int GetScalarInt32(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Number when element.TryGetInt32(out int value) => value,
            JsonValueKind.String when int.TryParse(element.GetString(), CultureInfo.InvariantCulture, out int value) => value,
            _ => 0,
        };
    }

    private static bool IsNamed(string actual, string[] names)
    {
        for (int i = 0; i < names.Length; i++)
        {
            if (actual.Equals(names[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetFirstNonEmptyString(params string[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            if (values[i].Length != 0)
            {
                return values[i];
            }
        }

        return string.Empty;
    }

    private static int GetFirstPositiveInt32(params int[] values)
    {
        for (int i = 0; i < values.Length; i++)
        {
            if (values[i] > 0)
            {
                return values[i];
            }
        }

        return 0;
    }

    private static string CreateTruffleHogFingerprint(string detectorName, string path, int line)
    {
        return string.Concat("trufflehog:", detectorName, ':', path, ':', line.ToString(CultureInfo.InvariantCulture));
    }

    private static bool IsGitLabCodeQualityReportPath(string path)
    {
        string fileName = Path.GetFileName(path);
        return fileName.Equals("gl-code-quality-report.json", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".gitlab-code-quality.json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHtmlReportPath(string path)
    {
        string extension = Path.GetExtension(path);
        return extension.Equals(".html", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase);
    }
}
