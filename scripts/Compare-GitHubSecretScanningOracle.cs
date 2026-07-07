#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text.Json.Nodes;

try
{
    return CompareGitHubSecretScanningOracleApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Compares sanitized GitHub hosted-alert metadata to a Picket JSONL report.
/// </summary>
internal static class CompareGitHubSecretScanningOracleApp
{
    /// <summary>
    /// Runs the GitHub hosted-alert oracle comparison app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            ["OraclePath", "PicketReportPath", "OutputPath"],
            [],
            ["FailOnDifference"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string oraclePath = ScriptSupport.GetString(
            values,
            "OraclePath",
            Path.Combine(repositoryRoot, "artifacts", "oracles", "github-secret-scanning", "alerts.json"));
        string picketReportPath = ScriptSupport.GetString(
            values,
            "PicketReportPath",
            Path.Combine(repositoryRoot, "artifacts", "oracles", "github-secret-scanning", "picket-scan.jsonl"));
        string outputPath = ScriptSupport.GetString(
            values,
            "OutputPath",
            Path.Combine(repositoryRoot, "artifacts", "oracles", "github-secret-scanning", "comparison.json"));
        bool failOnDifference = ScriptSupport.GetSwitch(switches, "FailOnDifference");
        var githubToPicketRuleIds = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["google_api_key"] = ["picket-google-api-key"],
        };

        JsonObject oracle = ReadRequiredJsonObject(oraclePath, "GitHub secret-scanning oracle");
        if (!ScriptSupport.GetString(oracle, "Schema").Equals("picket.github-secret-scanning-oracle.v1", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Unsupported GitHub oracle schema in '{oraclePath}'.");
        }

        JsonArray picketFindings = ScriptSupport.ReadJsonLines(picketReportPath);
        var allSecretTypes = new SortedSet<string>(StringComparer.Ordinal);
        foreach (JsonNode? alert in ScriptSupport.GetArray(oracle, "Alerts"))
        {
            allSecretTypes.Add(ScriptSupport.GetString(alert, "SecretType"));
        }

        foreach (string secretType in githubToPicketRuleIds.Keys)
        {
            allSecretTypes.Add(secretType);
        }

        var typeComparisons = new JsonArray();
        var missingLocations = new JsonArray();
        var unexpectedLocations = new JsonArray();
        var unmappedAlertTypes = new JsonArray();
        var unmappedPicketRuleIds = new SortedSet<string>(StringComparer.Ordinal);

        foreach (string secretType in allSecretTypes)
        {
            if (string.IsNullOrWhiteSpace(secretType))
            {
                continue;
            }

            string[] mappedRuleIds = githubToPicketRuleIds.TryGetValue(secretType, out string[]? ruleIds) ? ruleIds : [];
            bool hasMappedRuleIds = mappedRuleIds.Length != 0;
            if (!hasMappedRuleIds)
            {
                ScriptSupport.AddString(unmappedAlertTypes, secretType);
            }

            JsonArray githubLocations = CollectGitHubLocations(oracle, secretType, out Dictionary<string, List<JsonObject>> githubLocationMap);
            JsonArray picketLocations = hasMappedRuleIds
                ? CollectPicketLocations(picketFindings, secretType, mappedRuleIds, out Dictionary<string, List<JsonObject>> picketLocationMap)
                : CreateEmptyPicketLocationMap(out picketLocationMap);

            int matchingLocationCount = 0;
            int missingLocationCount = 0;
            int unexpectedLocationCount = 0;
            if (hasMappedRuleIds)
            {
                foreach (string githubKey in githubLocationMap.Keys.Order(StringComparer.Ordinal))
                {
                    if (!picketLocationMap.ContainsKey(githubKey))
                    {
                        foreach (JsonObject location in githubLocationMap[githubKey])
                        {
                            ScriptSupport.AddNode(missingLocations, location.DeepClone());
                        }
                    }
                }

                foreach (string picketKey in picketLocationMap.Keys.Order(StringComparer.Ordinal))
                {
                    if (!githubLocationMap.ContainsKey(picketKey))
                    {
                        foreach (JsonObject location in picketLocationMap[picketKey])
                        {
                            ScriptSupport.AddNode(unexpectedLocations, location.DeepClone());
                        }
                    }
                }

                foreach (string githubKey in githubLocationMap.Keys)
                {
                    if (picketLocationMap.TryGetValue(githubKey, out List<JsonObject>? picketMappedLocations))
                    {
                        matchingLocationCount += Math.Min(githubLocationMap[githubKey].Count, picketMappedLocations.Count);
                    }
                }

                missingLocationCount = Math.Max(0, githubLocations.Count - matchingLocationCount);
                unexpectedLocationCount = Math.Max(0, picketLocations.Count - matchingLocationCount);
            }

            ScriptSupport.AddNode(typeComparisons, new JsonObject
            {
                ["SecretType"] = secretType,
                ["PicketRuleIds"] = ScriptSupport.ToJsonArray(mappedRuleIds),
                ["AlertCount"] = CountAlerts(oracle, secretType),
                ["GitHubLocationCount"] = githubLocations.Count,
                ["PicketFindingCount"] = picketLocations.Count,
                ["MatchingLocationCount"] = matchingLocationCount,
                ["MissingLocationCount"] = missingLocationCount,
                ["UnexpectedLocationCount"] = unexpectedLocationCount,
            });
        }

        foreach (JsonNode? finding in picketFindings)
        {
            string ruleId = ScriptSupport.GetString(finding, "ruleId");
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                continue;
            }

            bool mapped = false;
            foreach (string secretType in githubToPicketRuleIds.Keys)
            {
                if (TestRuleMapsToSecretType(ruleId, secretType, githubToPicketRuleIds))
                {
                    mapped = true;
                    break;
                }
            }

            if (!mapped)
            {
                unmappedPicketRuleIds.Add(ruleId);
            }
        }

        var metadata = new JsonObject
        {
            ["Schema"] = "picket.github-secret-scanning-comparison.v1",
            ["OraclePath"] = Path.GetFullPath(oraclePath),
            ["PicketReportPath"] = Path.GetFullPath(picketReportPath),
            ["ComparedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["AlertCount"] = ScriptSupport.GetInt(oracle, "AlertCount"),
            ["PicketFindingCount"] = picketFindings.Count,
            ["TypeComparisons"] = typeComparisons,
            ["MissingLocationCount"] = missingLocations.Count,
            ["UnexpectedLocationCount"] = unexpectedLocations.Count,
            ["UnmappedAlertTypeCount"] = unmappedAlertTypes.Count,
            ["UnmappedPicketRuleIdCount"] = unmappedPicketRuleIds.Count,
            ["MissingLocations"] = missingLocations,
            ["UnexpectedLocations"] = unexpectedLocations,
            ["UnmappedAlertTypes"] = unmappedAlertTypes,
            ["UnmappedPicketRuleIds"] = ScriptSupport.ToJsonArray(unmappedPicketRuleIds),
        };

        ScriptSupport.WriteJsonFile(outputPath, metadata);
        if (failOnDifference && (missingLocations.Count != 0 || unmappedAlertTypes.Count != 0))
        {
            throw new InvalidOperationException(
                $"GitHub secret-scanning oracle comparison has {missingLocations.Count} missing locations and {unmappedAlertTypes.Count} unmapped alert types. See '{outputPath}'.");
        }

        Console.Out.WriteLine($"Compared GitHub secret-scanning oracle metadata in '{outputPath}'.");
        return 0;
    }

    /// <summary>
    /// Reads a required JSON object from disk.
    /// </summary>
    /// <param name="path">The JSON file path.</param>
    /// <param name="description">A description for diagnostics.</param>
    /// <returns>The parsed JSON object.</returns>
    private static JsonObject ReadRequiredJsonObject(string path, string description)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"{description} '{path}' does not exist.");
        }

        return ScriptSupport.ReadJsonObject(path);
    }

    /// <summary>
    /// Collects hosted alert locations for a secret type.
    /// </summary>
    /// <param name="oracle">The hosted alert oracle.</param>
    /// <param name="secretType">The secret type to collect.</param>
    /// <param name="locationMap">The resulting key-indexed location map.</param>
    /// <returns>The collected locations.</returns>
    private static JsonArray CollectGitHubLocations(
        JsonObject oracle,
        string secretType,
        out Dictionary<string, List<JsonObject>> locationMap)
    {
        var locations = new JsonArray();
        locationMap = new Dictionary<string, List<JsonObject>>(StringComparer.Ordinal);
        foreach (JsonNode? alert in ScriptSupport.GetArray(oracle, "Alerts"))
        {
            if (!ScriptSupport.GetString(alert, "SecretType").Equals(secretType, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (JsonNode? location in ScriptSupport.GetArray(alert, "Locations"))
            {
                JsonObject safeLocation = ConvertToGitHubLocation(alert, location);
                ScriptSupport.AddNode(locations, safeLocation.DeepClone());
                AddLocation(
                    locationMap,
                    NewLocationKey(
                        ScriptSupport.GetString(safeLocation, "Path"),
                        ScriptSupport.GetInt(safeLocation, "StartLine"),
                        ScriptSupport.GetString(safeLocation, "CommitSha")),
                    safeLocation);
            }
        }

        return locations;
    }

    /// <summary>
    /// Collects Picket findings for a mapped hosted alert type.
    /// </summary>
    /// <param name="picketFindings">The Picket JSONL findings.</param>
    /// <param name="secretType">The mapped hosted alert type.</param>
    /// <param name="mappedRuleIds">The Picket rule IDs that map to the alert type.</param>
    /// <param name="locationMap">The resulting key-indexed location map.</param>
    /// <returns>The collected locations.</returns>
    private static JsonArray CollectPicketLocations(
        JsonArray picketFindings,
        string secretType,
        string[] mappedRuleIds,
        out Dictionary<string, List<JsonObject>> locationMap)
    {
        var locations = new JsonArray();
        locationMap = new Dictionary<string, List<JsonObject>>(StringComparer.Ordinal);
        foreach (JsonNode? finding in picketFindings)
        {
            string ruleId = ScriptSupport.GetString(finding, "ruleId");
            if (!mappedRuleIds.Contains(ruleId, StringComparer.Ordinal))
            {
                continue;
            }

            JsonObject safeFinding = ConvertToPicketLocation(finding, secretType);
            ScriptSupport.AddNode(locations, safeFinding.DeepClone());
            AddLocation(
                locationMap,
                NewLocationKey(
                    ScriptSupport.GetString(safeFinding, "Path"),
                    ScriptSupport.GetInt(safeFinding, "StartLine"),
                    ScriptSupport.GetString(safeFinding, "Commit")),
                safeFinding);
        }

        return locations;
    }

    /// <summary>
    /// Creates an empty Picket location map.
    /// </summary>
    /// <param name="locationMap">The resulting empty map.</param>
    /// <returns>An empty location array.</returns>
    private static JsonArray CreateEmptyPicketLocationMap(out Dictionary<string, List<JsonObject>> locationMap)
    {
        locationMap = new Dictionary<string, List<JsonObject>>(StringComparer.Ordinal);
        return [];
    }

    /// <summary>
    /// Counts hosted alerts for a secret type.
    /// </summary>
    /// <param name="oracle">The hosted alert oracle.</param>
    /// <param name="secretType">The secret type.</param>
    /// <returns>The alert count.</returns>
    private static int CountAlerts(JsonObject oracle, string secretType)
    {
        int count = 0;
        foreach (JsonNode? alert in ScriptSupport.GetArray(oracle, "Alerts"))
        {
            if (ScriptSupport.GetString(alert, "SecretType").Equals(secretType, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }

    /// <summary>
    /// Creates a normalized location comparison key.
    /// </summary>
    /// <param name="path">The source path.</param>
    /// <param name="line">The source line.</param>
    /// <param name="commit">The optional commit SHA.</param>
    /// <returns>The normalized location key.</returns>
    private static string NewLocationKey(string path, int line, string commit = "")
    {
        string normalizedPath = ScriptSupport.NormalizePathSeparators(path);
        return string.IsNullOrWhiteSpace(commit) ? $"{normalizedPath}:{line}" : $"{commit}:{normalizedPath}:{line}";
    }

    /// <summary>
    /// Adds a location to a key-indexed map.
    /// </summary>
    /// <param name="map">The map to update.</param>
    /// <param name="key">The normalized location key.</param>
    /// <param name="location">The location object.</param>
    private static void AddLocation(Dictionary<string, List<JsonObject>> map, string key, JsonObject location)
    {
        if (!map.TryGetValue(key, out List<JsonObject>? locations))
        {
            locations = [];
            map.Add(key, locations);
        }

        locations.Add(location);
    }

    /// <summary>
    /// Converts a GitHub alert location to the comparison schema.
    /// </summary>
    /// <param name="alert">The sanitized GitHub alert.</param>
    /// <param name="location">The sanitized GitHub location.</param>
    /// <returns>The comparison location.</returns>
    private static JsonObject ConvertToGitHubLocation(JsonNode? alert, JsonNode? location)
    {
        return new JsonObject
        {
            ["AlertNumber"] = ScriptSupport.GetInt(alert, "Number"),
            ["SecretType"] = ScriptSupport.GetString(alert, "SecretType"),
            ["SecretTypeDisplayName"] = ScriptSupport.GetString(alert, "SecretTypeDisplayName"),
            ["Path"] = ScriptSupport.GetString(location, "Path"),
            ["StartLine"] = ScriptSupport.GetInt(location, "StartLine"),
            ["StartColumn"] = ScriptSupport.GetInt(location, "StartColumn"),
            ["EndLine"] = ScriptSupport.GetInt(location, "EndLine"),
            ["EndColumn"] = ScriptSupport.GetInt(location, "EndColumn"),
            ["CommitSha"] = ScriptSupport.GetString(location, "CommitSha"),
        };
    }

    /// <summary>
    /// Converts a Picket finding to the comparison schema.
    /// </summary>
    /// <param name="finding">The Picket JSONL finding.</param>
    /// <param name="secretType">The mapped GitHub secret type.</param>
    /// <returns>The comparison location.</returns>
    private static JsonObject ConvertToPicketLocation(JsonNode? finding, string secretType)
    {
        return new JsonObject
        {
            ["SecretType"] = secretType,
            ["RuleId"] = ScriptSupport.GetString(finding, "ruleId"),
            ["Path"] = ScriptSupport.GetString(finding, "file"),
            ["StartLine"] = ScriptSupport.GetInt(finding, "startLine"),
            ["StartColumn"] = ScriptSupport.GetInt(finding, "startColumn"),
            ["Commit"] = ScriptSupport.GetString(finding, "commit"),
            ["Fingerprint"] = ScriptSupport.GetString(finding, "fingerprint"),
        };
    }

    /// <summary>
    /// Determines whether a Picket rule maps to a hosted alert type.
    /// </summary>
    /// <param name="ruleId">The Picket rule ID.</param>
    /// <param name="secretType">The GitHub secret type.</param>
    /// <param name="githubToPicketRuleIds">The mapping table.</param>
    /// <returns><see langword="true"/> when the rule maps to the secret type.</returns>
    private static bool TestRuleMapsToSecretType(
        string ruleId,
        string secretType,
        Dictionary<string, string[]> githubToPicketRuleIds)
    {
        return githubToPicketRuleIds.TryGetValue(secretType, out string[]? ruleIds)
            && ruleIds.Contains(ruleId, StringComparer.Ordinal);
    }
}
