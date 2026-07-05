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

            using FileStream stream = File.OpenRead(path);
            using JsonDocument document = JsonDocument.Parse(stream);
            return ReadJsonDocument(document.RootElement, path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException($"could not open {path}", exception);
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException or InvalidOperationException or FormatException)
        {
            throw new InvalidDataException($"the format of the file {path} is not supported", exception);
        }
    }

    private static ReportSummary ReadJsonLines(string path)
    {
        var findings = new List<ReportFindingSummary>();
        try
        {
            foreach (string line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                using JsonDocument document = JsonDocument.Parse(line);
                findings.Add(ReadPicketFinding(document.RootElement));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IOException($"could not open {path}", exception);
        }

        return new ReportSummary("picket-jsonl", findings);
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
                GetString(finding, "Fingerprint")));
        }

        return new ReportSummary("gitleaks-json", findings);
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
            GetString(finding, "fingerprint"));
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
            fingerprint);
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

        return property.GetString() ?? string.Empty;
    }

    private static int GetInt32(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object
            || !element.TryGetProperty(name, out JsonElement property)
            || property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return 0;
        }

        return property.GetInt32();
    }

    private static bool IsGitLabCodeQualityReportPath(string path)
    {
        string fileName = Path.GetFileName(path);
        return fileName.Equals("gl-code-quality-report.json", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".gitlab-code-quality.json", StringComparison.OrdinalIgnoreCase);
    }
}
