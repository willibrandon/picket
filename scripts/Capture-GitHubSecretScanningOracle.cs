#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text.Json.Nodes;

try
{
    return CaptureGitHubSecretScanningOracleApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Captures sanitized GitHub Secret Protection alert metadata.
/// </summary>
internal static class CaptureGitHubSecretScanningOracleApp
{
    /// <summary>
    /// Runs the GitHub hosted-alert oracle capture app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            ["Repository", "State", "OutputPath"],
            [],
            ["IncludeLocations"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string repository = ScriptSupport.GetString(values, "Repository");
        string state = ScriptSupport.GetString(values, "State", "open");
        string outputPath = ScriptSupport.GetString(
            values,
            "OutputPath",
            Path.Combine(repositoryRoot, "artifacts", "oracles", "github-secret-scanning", "alerts.json"));
        bool includeLocations = ScriptSupport.GetSwitch(switches, "IncludeLocations");

        ScriptSupport.RequireValueInSet("State", state, ["open", "resolved", "all"]);
        string ghExecutable = ScriptSupport.ResolveCommandPath("gh", "GitHub CLI");
        string resolvedRepository = ResolveGitHubRepository(ghExecutable, repository);
        string stateQuery = state.Equals("all", StringComparison.Ordinal) ? string.Empty : $"state={state}&";
        string alertsEndpoint = $"repos/{resolvedRepository}/secret-scanning/alerts?{stateQuery}per_page=100";
        JsonArray rawAlerts = GetPagedGitHubArray(ghExecutable, alertsEndpoint);
        var safeAlerts = new JsonArray();

        foreach (JsonNode? alert in rawAlerts)
        {
            var locations = new JsonArray();
            if (includeLocations && !string.IsNullOrWhiteSpace(ScriptSupport.GetString(alert, "locations_url")))
            {
                string locationsEndpoint = $"repos/{resolvedRepository}/secret-scanning/alerts/{ScriptSupport.GetInt(alert, "number")}/locations?per_page=100";
                foreach (JsonNode? location in GetPagedGitHubArray(ghExecutable, locationsEndpoint))
                {
                    ScriptSupport.AddNode(locations, ConvertToSafeLocation(location));
                }
            }

            ScriptSupport.AddNode(safeAlerts, ConvertToSafeAlert(alert, locations));
        }

        JsonArray summary = CreateSummary(safeAlerts);
        var metadata = new JsonObject
        {
            ["Schema"] = "picket.github-secret-scanning-oracle.v1",
            ["Repository"] = resolvedRepository,
            ["State"] = state,
            ["IncludeLocations"] = includeLocations,
            ["CapturedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["AlertCount"] = safeAlerts.Count,
            ["Summary"] = summary,
            ["Alerts"] = safeAlerts,
        };

        ScriptSupport.WriteJsonFile(outputPath, metadata);
        Console.Out.WriteLine($"Captured GitHub secret scanning oracle metadata in '{outputPath}'.");
        return 0;
    }

    /// <summary>
    /// Resolves the target GitHub repository.
    /// </summary>
    /// <param name="ghExecutable">The resolved GitHub CLI executable path.</param>
    /// <param name="repository">The optional repository argument.</param>
    /// <returns>The repository in owner/name form.</returns>
    private static string ResolveGitHubRepository(string ghExecutable, string repository)
    {
        if (!string.IsNullOrWhiteSpace(repository))
        {
            return repository;
        }

        (int exitCode, string stdout, _) = ScriptSupport.RunProcess(
            ghExecutable,
            ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
            Directory.GetCurrentDirectory());
        if (exitCode != 0 || string.IsNullOrWhiteSpace(stdout))
        {
            throw new InvalidOperationException("Could not resolve the current GitHub repository. Pass -Repository owner/name.");
        }

        return stdout.Trim();
    }

    /// <summary>
    /// Invokes a paged GitHub REST API request and flattens the page array returned by gh.
    /// </summary>
    /// <param name="ghExecutable">The resolved GitHub CLI executable path.</param>
    /// <param name="endpoint">The GitHub REST endpoint.</param>
    /// <returns>The flattened item array.</returns>
    private static JsonArray GetPagedGitHubArray(string ghExecutable, string endpoint)
    {
        (int exitCode, string stdout, string stderr) = ScriptSupport.RunProcess(
            ghExecutable,
            [
                "api",
                "--paginate",
                "--slurp",
                "-H",
                "Accept: application/vnd.github+json",
                endpoint,
            ],
            Directory.GetCurrentDirectory());
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"gh api --paginate --slurp failed. {stderr}".Trim());
        }

        var items = new JsonArray();
        if (string.IsNullOrWhiteSpace(stdout))
        {
            return items;
        }

        JsonNode? root = JsonNode.Parse(stdout);
        if (root is not JsonArray pages)
        {
            return items;
        }

        foreach (JsonNode? page in pages)
        {
            if (page is JsonArray pageItems)
            {
                foreach (JsonNode? item in pageItems)
                {
                    ScriptSupport.AddNode(items, item?.DeepClone());
                }
            }
            else
            {
                ScriptSupport.AddNode(items, page?.DeepClone());
            }
        }

        return items;
    }

    /// <summary>
    /// Converts a GitHub alert location to the sanitized oracle location schema.
    /// </summary>
    /// <param name="location">The raw GitHub location object.</param>
    /// <returns>A sanitized location object.</returns>
    private static JsonObject ConvertToSafeLocation(JsonNode? location)
    {
        JsonNode? details = location?["details"];
        return new JsonObject
        {
            ["Type"] = ScriptSupport.GetString(location, "type"),
            ["Path"] = ScriptSupport.GetString(details, "path"),
            ["StartLine"] = ScriptSupport.GetInt(details, "start_line"),
            ["EndLine"] = ScriptSupport.GetInt(details, "end_line"),
            ["StartColumn"] = ScriptSupport.GetInt(details, "start_column"),
            ["EndColumn"] = ScriptSupport.GetInt(details, "end_column"),
            ["BlobSha"] = ScriptSupport.GetString(details, "blob_sha"),
            ["CommitSha"] = ScriptSupport.GetString(details, "commit_sha"),
        };
    }

    /// <summary>
    /// Converts a GitHub alert to the sanitized oracle alert schema.
    /// </summary>
    /// <param name="alert">The raw GitHub alert object.</param>
    /// <param name="locations">The sanitized locations for the alert.</param>
    /// <returns>A sanitized alert object.</returns>
    private static JsonObject ConvertToSafeAlert(JsonNode? alert, JsonArray locations)
    {
        return new JsonObject
        {
            ["Number"] = ScriptSupport.GetInt(alert, "number"),
            ["State"] = ScriptSupport.GetString(alert, "state"),
            ["SecretType"] = ScriptSupport.GetString(alert, "secret_type"),
            ["SecretTypeDisplayName"] = ScriptSupport.GetString(alert, "secret_type_display_name"),
            ["CreatedAt"] = ScriptSupport.GetString(alert, "created_at"),
            ["UpdatedAt"] = ScriptSupport.GetString(alert, "updated_at"),
            ["ResolvedAt"] = ScriptSupport.GetString(alert, "resolved_at"),
            ["Resolution"] = ScriptSupport.GetString(alert, "resolution"),
            ["HtmlUrl"] = ScriptSupport.GetString(alert, "html_url"),
            ["LocationsUrl"] = ScriptSupport.GetString(alert, "locations_url"),
            ["Locations"] = locations,
        };
    }

    /// <summary>
    /// Creates alert counts grouped by secret type.
    /// </summary>
    /// <param name="safeAlerts">The sanitized alerts.</param>
    /// <returns>The summary array.</returns>
    private static JsonArray CreateSummary(JsonArray safeAlerts)
    {
        var counts = new SortedDictionary<string, int>(StringComparer.Ordinal);
        foreach (JsonNode? alert in safeAlerts)
        {
            string secretType = ScriptSupport.GetString(alert, "SecretType");
            counts.TryGetValue(secretType, out int count);
            counts[secretType] = count + 1;
        }

        var summary = new JsonArray();
        foreach ((string secretType, int count) in counts)
        {
            ScriptSupport.AddNode(summary, new JsonObject
            {
                ["SecretType"] = secretType,
                ["Count"] = count,
            });
        }

        return summary;
    }
}
