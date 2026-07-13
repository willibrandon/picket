#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false

using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

try
{
    return PicketGitHubActionApp.Run();
}
catch (Exception ex)
{
    PicketGitHubActionApp.WriteError("Picket action failed", ex.Message);
    return 1;
}

/// <summary>
/// Runs the Picket composite GitHub Action helper.
/// </summary>
internal static class PicketGitHubActionApp
{
    /// <summary>
    /// Built-in rule packs that callers may add to a native scan.
    /// </summary>
    private static readonly string[] s_supportedRulePacks = ["picket-experimental", "picket-strict"];

    /// <summary>
    /// UTF-8 without a byte order mark.
    /// </summary>
    private static readonly UTF8Encoding s_utf8NoBom = new(false);

    /// <summary>
    /// Executes the action helper.
    /// </summary>
    /// <param name="sourceFilePath">The source file path supplied by the compiler.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run([CallerFilePath] string sourceFilePath = "")
    {
        string actionPath = ResolveActionPath(sourceFilePath);
        string scanPath = ResolveWorkspacePath(GetActionInput("PICKET_PATH", "."));
        string configPath = GetActionInput("PICKET_CONFIG_PATH");
        string baselinePath = GetActionInput("PICKET_BASELINE_PATH");
        List<string> rulePacks = ParseRulePacks(GetActionInput("PICKET_RULE_PACKS"));
        string cacheEnabled = GetActionInput("PICKET_CACHE_ENABLED", "true");
        string cacheMode = GetActionInput("PICKET_CACHE_MODE", "secret-hash-only").Trim().ToLowerInvariant();
        string cachePath = GetActionInput("PICKET_CACHE_PATH", ".picket/cache");
        string reportDirectory = ResolveWorkspacePath(GetActionInput("PICKET_REPORT_DIRECTORY", "picket-results"));
        string failOn = GetActionInput("PICKET_FAIL_ON", "findings").Trim().ToLowerInvariant();
        string summaryEnabled = GetActionInput("PICKET_SUMMARY", "true").Trim().ToLowerInvariant();
        string validationResults = GetActionInput("PICKET_RESULTS");
        string onlyVerified = GetActionInput("PICKET_ONLY_VERIFIED", "false").Trim().ToLowerInvariant();
        string annotationsEnabled = GetActionInput("PICKET_ANNOTATIONS", "true");
        int annotationLimit = ConvertToPositiveInt(GetActionInput("PICKET_ANNOTATION_LIMIT", "50"), "annotation-limit");
        string redact = GetActionInput("PICKET_REDACT", "100");
        string maxTargetMegabytes = GetActionInput("PICKET_MAX_TARGET_MEGABYTES");
        string timeout = GetActionInput("PICKET_TIMEOUT");
        string maxArchiveDepth = GetActionInput("PICKET_MAX_ARCHIVE_DEPTH");
        string maxArchiveEntries = GetActionInput("PICKET_MAX_ARCHIVE_ENTRIES");
        string maxArchiveMegabytes = GetActionInput("PICKET_MAX_ARCHIVE_MEGABYTES");
        string maxArchiveRatio = GetActionInput("PICKET_MAX_ARCHIVE_RATIO");

        RequireValueInSet("fail-on", failOn, ["findings", "errors", "never"], "fail-on must be findings, errors, or never.");
        RequireValueInSet("cache-mode", cacheMode, ["secret-hash-only", "raw"], "cache-mode must be secret-hash-only or raw.");
        RequireValueInSet("summary", summaryEnabled, ["true", "false"], "summary must be true or false.");
        RequireValueInSet("only-verified", onlyVerified, ["true", "false"], "only-verified must be true or false.");
        if (onlyVerified.Equals("true", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(validationResults))
        {
            WriteError("Invalid validation filter", "results and only-verified cannot both be set.");
            return 1;
        }

        Directory.CreateDirectory(reportDirectory);
        string sarifPath = Path.Combine(reportDirectory, "picket.sarif");
        string jsonlPath = Path.Combine(reportDirectory, "picket.jsonl");
        string projectPath = Path.Combine(actionPath, "src", "Picket.Cli", "Picket.Cli.csproj");
        var arguments = new List<string>
        {
            "run",
            "--project",
            projectPath,
            "--configuration",
            "Release",
            "--no-restore",
            "--",
            "scan",
            scanPath,
            "-r",
            sarifPath,
            "-r",
            jsonlPath,
            $"--redact={redact}",
        };

        AddOptionalPathOption(arguments, "-c", configPath);
        AddOptionalPathOption(arguments, "-b", baselinePath);
        foreach (string rulePack in rulePacks)
        {
            AddOptionalValueOption(arguments, "--rule-pack", rulePack);
        }

        if (cacheEnabled.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            string resolvedCachePath = ResolveWorkspacePath(cachePath);
            Directory.CreateDirectory(resolvedCachePath);
            arguments.Add("--cache-dir");
            arguments.Add(resolvedCachePath);
            arguments.Add("--cache-mode");
            arguments.Add(cacheMode);
        }

        if (onlyVerified.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            arguments.Add("--only-verified");
        }
        else if (!string.IsNullOrWhiteSpace(validationResults))
        {
            arguments.Add("--results");
            arguments.Add(validationResults);
        }

        AddOptionalValueOption(arguments, "--max-target-megabytes", maxTargetMegabytes);
        AddOptionalValueOption(arguments, "--timeout", timeout);
        AddOptionalValueOption(arguments, "--max-archive-depth", maxArchiveDepth);
        AddOptionalValueOption(arguments, "--max-archive-entries", maxArchiveEntries);
        AddOptionalValueOption(arguments, "--max-archive-megabytes", maxArchiveMegabytes);
        AddOptionalValueOption(arguments, "--max-archive-ratio", maxArchiveRatio);

        int scannerExitCode = RunDotNet(arguments);
        int findingCount = CountFindings(jsonlPath);
        int annotationCount = annotationsEnabled.Equals("true", StringComparison.OrdinalIgnoreCase)
            ? WriteFindingAnnotations(jsonlPath, annotationLimit)
            : 0;

        (bool shouldFail, int failureCode) = EvaluateFailure(failOn, scannerExitCode, findingCount);
        AddActionOutput("exit-code", scannerExitCode.ToString(CultureInfo.InvariantCulture));
        AddActionOutput("findings", findingCount.ToString(CultureInfo.InvariantCulture));
        AddActionOutput("sarif-path", sarifPath);
        AddActionOutput("jsonl-path", jsonlPath);
        AddActionOutput("annotations", annotationCount.ToString(CultureInfo.InvariantCulture));
        AddActionOutput("should-fail", shouldFail.ToString().ToLowerInvariant());
        AddActionOutput("failure-code", failureCode.ToString(CultureInfo.InvariantCulture));

        if (summaryEnabled.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            AddStepSummary(CreateSummaryLines(scannerExitCode, findingCount, annotationCount, failOn, validationResults, onlyVerified, sarifPath, jsonlPath));
        }

        return 0;
    }

    /// <summary>
    /// Writes a GitHub Actions error command.
    /// </summary>
    /// <param name="title">The error title.</param>
    /// <param name="message">The error message.</param>
    internal static void WriteError(string title, string message)
    {
        Console.Out.WriteLine($"::error title={ConvertToGitHubCommandProperty(title)}::{ConvertToGitHubCommandMessage(message)}");
    }

    /// <summary>
    /// Resolves the action root path.
    /// </summary>
    /// <param name="sourceFilePath">The source file path supplied by the compiler.</param>
    /// <returns>The action root path.</returns>
    private static string ResolveActionPath(string sourceFilePath)
    {
        string? actionPath = Environment.GetEnvironmentVariable("GITHUB_ACTION_PATH");
        if (!string.IsNullOrWhiteSpace(actionPath))
        {
            return Path.GetFullPath(actionPath);
        }

        string? scriptDirectory = Path.GetDirectoryName(sourceFilePath);
        string? repositoryRoot = Directory.GetParent(scriptDirectory ?? Directory.GetCurrentDirectory())?.Parent?.FullName;
        return Path.GetFullPath(repositoryRoot ?? Directory.GetCurrentDirectory());
    }

    /// <summary>
    /// Gets an action input from the environment.
    /// </summary>
    /// <param name="name">The environment variable name.</param>
    /// <param name="defaultValue">The fallback value.</param>
    /// <returns>The input value.</returns>
    private static string GetActionInput(string name, string defaultValue = "")
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
    }

    /// <summary>
    /// Resolves a path relative to the GitHub workspace.
    /// </summary>
    /// <param name="path">The path value.</param>
    /// <returns>The full path.</returns>
    private static string ResolveWorkspacePath(string path)
    {
        if (Path.IsPathRooted(path))
        {
            return Path.GetFullPath(path);
        }

        string workspace = GetActionInput("GITHUB_WORKSPACE", Directory.GetCurrentDirectory());
        return Path.GetFullPath(Path.Combine(workspace, path));
    }

    /// <summary>
    /// Requires that a value belongs to an allowed set.
    /// </summary>
    /// <param name="name">The input name.</param>
    /// <param name="value">The input value.</param>
    /// <param name="allowedValues">The allowed values.</param>
    /// <param name="message">The validation message.</param>
    private static void RequireValueInSet(string name, string value, string[] allowedValues, string message)
    {
        if (allowedValues.Contains(value, StringComparer.Ordinal))
        {
            return;
        }

        WriteError($"Invalid {name}", message);
        Environment.Exit(1);
    }

    /// <summary>
    /// Converts an input to a non-negative integer.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <param name="name">The input name.</param>
    /// <returns>The parsed integer.</returns>
    private static int ConvertToPositiveInt(string value, string name)
    {
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) && parsed >= 0)
        {
            return parsed;
        }

        WriteError($"Invalid {name}", $"{name} must be a non-negative integer.");
        Environment.Exit(1);
        return 0;
    }

    /// <summary>
    /// Adds an optional path argument after resolving it against the workspace.
    /// </summary>
    /// <param name="arguments">The argument list.</param>
    /// <param name="option">The option name.</param>
    /// <param name="value">The option value.</param>
    private static void AddOptionalPathOption(List<string> arguments, string option, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        arguments.Add(option);
        arguments.Add(ResolveWorkspacePath(value));
    }

    /// <summary>
    /// Adds an optional value argument.
    /// </summary>
    /// <param name="arguments">The argument list.</param>
    /// <param name="option">The option name.</param>
    /// <param name="value">The option value.</param>
    private static void AddOptionalValueOption(List<string> arguments, string option, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        arguments.Add(option);
        arguments.Add(value);
    }

    /// <summary>
    /// Parses and validates the comma-separated built-in rule-pack input.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <returns>The distinct normalized rule-pack identifiers.</returns>
    private static List<string> ParseRulePacks(string value)
    {
        List<string> rulePacks = [];
        foreach (string candidate in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string rulePack = candidate.ToLowerInvariant();
            if (!s_supportedRulePacks.Contains(rulePack, StringComparer.Ordinal))
            {
                WriteError(
                    "Invalid rule-packs",
                    $"Unsupported built-in rule pack '{candidate}'. Use picket-strict or picket-experimental.");
                Environment.Exit(1);
            }

            if (!rulePacks.Contains(rulePack, StringComparer.Ordinal))
            {
                rulePacks.Add(rulePack);
            }
        }

        return rulePacks;
    }

    /// <summary>
    /// Runs dotnet with inherited output.
    /// </summary>
    /// <param name="arguments">The dotnet arguments.</param>
    /// <returns>The dotnet exit code.</returns>
    private static int RunDotNet(List<string> arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false,
            },
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        try
        {
            process.Start();
            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            WriteError("Picket process failed", ex.Message.Replace('\r', ' ').Replace('\n', ' '));
            return 1;
        }
    }

    /// <summary>
    /// Counts JSONL findings in a report.
    /// </summary>
    /// <param name="jsonlPath">The JSONL report path.</param>
    /// <returns>The non-empty line count.</returns>
    private static int CountFindings(string jsonlPath)
    {
        return File.Exists(jsonlPath)
            ? File.ReadLines(jsonlPath).Count(static line => !string.IsNullOrWhiteSpace(line))
            : 0;
    }

    /// <summary>
    /// Emits GitHub warning annotations for JSONL findings.
    /// </summary>
    /// <param name="jsonlPath">The JSONL report path.</param>
    /// <param name="limit">The maximum number of annotations to write.</param>
    /// <returns>The number of emitted annotations.</returns>
    private static int WriteFindingAnnotations(string jsonlPath, int limit)
    {
        if (limit == 0 || !File.Exists(jsonlPath))
        {
            return 0;
        }

        int emitted = 0;
        foreach (string line in File.ReadLines(jsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            if (emitted >= limit)
            {
                break;
            }

            JsonNode? finding;
            try
            {
                finding = JsonNode.Parse(line);
            }
            catch (JsonException)
            {
                WriteWarning("Picket annotation skipped", "Could not parse a JSONL finding for annotation output.");
                continue;
            }

            string ruleId = GetJsonPropertyString(finding, "ruleId");
            string file = GetJsonPropertyString(finding, "file");
            if (string.IsNullOrWhiteSpace(file))
            {
                continue;
            }

            int lineNumber = Math.Max(1, GetJsonPropertyInt(finding, "startLine", 1));
            int columnNumber = Math.Max(1, GetJsonPropertyInt(finding, "startColumn", 1));
            string properties = string.Create(
                CultureInfo.InvariantCulture,
                $"file={ConvertToGitHubCommandProperty(file)},line={lineNumber},col={columnNumber},title={ConvertToGitHubCommandProperty($"Picket secret: {ruleId}")}");
            string message = ConvertToGitHubCommandMessage($"Picket detected rule {ruleId} at {file}:{lineNumber}:{columnNumber}.");
            Console.Out.WriteLine($"::warning {properties}::{message}");
            emitted++;
        }

        return emitted;
    }

    /// <summary>
    /// Writes a GitHub Actions warning command.
    /// </summary>
    /// <param name="title">The warning title.</param>
    /// <param name="message">The warning message.</param>
    private static void WriteWarning(string title, string message)
    {
        Console.Out.WriteLine($"::warning title={ConvertToGitHubCommandProperty(title)}::{ConvertToGitHubCommandMessage(message)}");
    }

    /// <summary>
    /// Evaluates whether the action should fail after scanning.
    /// </summary>
    /// <param name="failOn">The fail mode.</param>
    /// <param name="scannerExitCode">The scanner exit code.</param>
    /// <param name="findingCount">The finding count.</param>
    /// <returns>The failure decision and failure code.</returns>
    private static (bool ShouldFail, int FailureCode) EvaluateFailure(string failOn, int scannerExitCode, int findingCount)
    {
        return failOn switch
        {
            "findings" when findingCount > 0 => (true, scannerExitCode != 0 ? scannerExitCode : 1),
            "findings" when scannerExitCode != 0 => (true, scannerExitCode),
            "errors" when scannerExitCode != 0 && findingCount == 0 => (true, scannerExitCode),
            _ => (false, 0),
        };
    }

    /// <summary>
    /// Creates the action summary lines.
    /// </summary>
    /// <param name="scannerExitCode">The scanner exit code.</param>
    /// <param name="findingCount">The finding count.</param>
    /// <param name="annotationCount">The annotation count.</param>
    /// <param name="failOn">The fail mode.</param>
    /// <param name="validationResults">The validation result filter.</param>
    /// <param name="onlyVerified">The only-verified value.</param>
    /// <param name="sarifPath">The SARIF report path.</param>
    /// <param name="jsonlPath">The JSONL report path.</param>
    /// <returns>The action summary lines.</returns>
    private static List<string> CreateSummaryLines(
        int scannerExitCode,
        int findingCount,
        int annotationCount,
        string failOn,
        string validationResults,
        string onlyVerified,
        string sarifPath,
        string jsonlPath)
    {
        string resultFilterSummary = "all";
        if (onlyVerified.Equals("true", StringComparison.OrdinalIgnoreCase))
        {
            resultFilterSummary = "only-verified";
        }
        else if (!string.IsNullOrWhiteSpace(validationResults))
        {
            resultFilterSummary = validationResults;
        }

        var lines = new List<string>
        {
            "# Picket scan",
            string.Empty,
            "| Field | Value |",
            "| --- | --- |",
            $"| Scanner exit code | {scannerExitCode.ToString(CultureInfo.InvariantCulture)} |",
            $"| Findings | {findingCount.ToString(CultureInfo.InvariantCulture)} |",
            $"| Annotations | {annotationCount.ToString(CultureInfo.InvariantCulture)} |",
            $"| Fail on | {failOn} |",
            $"| Result filter | {resultFilterSummary} |",
            $"| SARIF | {sarifPath} |",
            $"| JSONL | {jsonlPath} |",
        };
        lines.AddRange(GetFindingBreakdownSummaryLines(jsonlPath, 10));
        return lines;
    }

    /// <summary>
    /// Appends action output values.
    /// </summary>
    /// <param name="name">The output name.</param>
    /// <param name="value">The output value.</param>
    private static void AddActionOutput(string name, string value)
    {
        string outputPath = GetActionInput("GITHUB_OUTPUT");
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return;
        }

        File.AppendAllText(outputPath, $"{name}={value}\n", s_utf8NoBom);
    }

    /// <summary>
    /// Appends step summary lines.
    /// </summary>
    /// <param name="lines">The summary lines.</param>
    private static void AddStepSummary(IEnumerable<string> lines)
    {
        string summaryPath = GetActionInput("GITHUB_STEP_SUMMARY");
        if (string.IsNullOrWhiteSpace(summaryPath))
        {
            return;
        }

        File.AppendAllLines(summaryPath, lines, s_utf8NoBom);
    }

    /// <summary>
    /// Builds finding breakdown summary lines.
    /// </summary>
    /// <param name="jsonlPath">The JSONL report path.</param>
    /// <param name="limit">The maximum number of rows per breakdown table.</param>
    /// <returns>The summary lines.</returns>
    private static List<string> GetFindingBreakdownSummaryLines(string jsonlPath, int limit)
    {
        if (limit == 0 || !File.Exists(jsonlPath))
        {
            return [];
        }

        var ruleCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var fileCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(jsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            JsonNode? finding;
            try
            {
                finding = JsonNode.Parse(line);
            }
            catch (JsonException)
            {
                WriteWarning("Picket summary skipped", "Could not parse a JSONL finding for summary output.");
                continue;
            }

            AddFindingSummaryCount(ruleCounts, GetJsonPropertyString(finding, "ruleId"), "(unknown rule)");
            AddFindingSummaryCount(fileCounts, GetJsonPropertyString(finding, "file"), "(unknown file)");
        }

        List<string> lines = [];
        lines.AddRange(GetFindingBreakdownTableLines("Findings by rule", "Rule", ruleCounts, limit));
        lines.AddRange(GetFindingBreakdownTableLines("Findings by file", "File", fileCounts, limit));
        return lines;
    }

    /// <summary>
    /// Increments a finding summary count.
    /// </summary>
    /// <param name="counts">The count map.</param>
    /// <param name="value">The raw value.</param>
    /// <param name="defaultValue">The default value for blank entries.</param>
    private static void AddFindingSummaryCount(Dictionary<string, int> counts, string value, string defaultValue)
    {
        string key = string.IsNullOrWhiteSpace(value) ? defaultValue : value;
        counts[key] = counts.TryGetValue(key, out int count) ? count + 1 : 1;
    }

    /// <summary>
    /// Builds a Markdown finding breakdown table.
    /// </summary>
    /// <param name="title">The table title.</param>
    /// <param name="columnName">The first column name.</param>
    /// <param name="counts">The count map.</param>
    /// <param name="limit">The maximum number of rows.</param>
    /// <returns>The Markdown table lines.</returns>
    private static List<string> GetFindingBreakdownTableLines(string title, string columnName, Dictionary<string, int> counts, int limit)
    {
        if (counts.Count == 0)
        {
            return [];
        }

        var lines = new List<string>
        {
            string.Empty,
            $"## {title}",
            string.Empty,
            $"| {columnName} | Count |",
            "| --- | ---: |",
        };
        foreach (KeyValuePair<string, int> row in counts.OrderByDescending(static pair => pair.Value).ThenBy(static pair => pair.Key, StringComparer.Ordinal).Take(limit))
        {
            lines.Add($"| {ConvertToMarkdownCell(row.Key)} | {row.Value.ToString(CultureInfo.InvariantCulture)} |");
        }

        if (counts.Count > limit)
        {
            lines.Add(string.Empty);
            lines.Add($"_Showing top {limit.ToString(CultureInfo.InvariantCulture)} of {counts.Count.ToString(CultureInfo.InvariantCulture)}._");
        }

        return lines;
    }

    /// <summary>
    /// Gets a string property from a JSON object.
    /// </summary>
    /// <param name="node">The JSON node.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The property value, or an empty string.</returns>
    private static string GetJsonPropertyString(JsonNode? node, string name)
    {
        JsonNode? value = node?[name];
        return value?.GetValueKind() switch
        {
            JsonValueKind.String => value.GetValue<string>(),
            JsonValueKind.Number => value.ToJsonString(),
            JsonValueKind.True => bool.TrueString,
            JsonValueKind.False => bool.FalseString,
            _ => string.Empty,
        };
    }

    /// <summary>
    /// Gets an integer property from a JSON object.
    /// </summary>
    /// <param name="node">The JSON node.</param>
    /// <param name="name">The property name.</param>
    /// <param name="defaultValue">The fallback value.</param>
    /// <returns>The property value.</returns>
    private static int GetJsonPropertyInt(JsonNode? node, string name, int defaultValue)
    {
        JsonNode? value = node?[name];
        if (value is null)
        {
            return defaultValue;
        }

        if (value.GetValueKind() == JsonValueKind.Number && value.AsValue().TryGetValue(out int integer))
        {
            return integer;
        }

        return int.TryParse(GetJsonPropertyString(node, name), NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : defaultValue;
    }

    /// <summary>
    /// Escapes a GitHub command property value.
    /// </summary>
    /// <param name="value">The value to escape.</param>
    /// <returns>The escaped value.</returns>
    private static string ConvertToGitHubCommandProperty(string value)
    {
        return value.Replace("%", "%25", StringComparison.Ordinal)
            .Replace("\r", "%0D", StringComparison.Ordinal)
            .Replace("\n", "%0A", StringComparison.Ordinal)
            .Replace(":", "%3A", StringComparison.Ordinal)
            .Replace(",", "%2C", StringComparison.Ordinal);
    }

    /// <summary>
    /// Escapes a GitHub command message.
    /// </summary>
    /// <param name="value">The value to escape.</param>
    /// <returns>The escaped value.</returns>
    private static string ConvertToGitHubCommandMessage(string value)
    {
        return value.Replace("%", "%25", StringComparison.Ordinal)
            .Replace("\r", "%0D", StringComparison.Ordinal)
            .Replace("\n", "%0A", StringComparison.Ordinal);
    }

    /// <summary>
    /// Escapes a value for a Markdown table cell.
    /// </summary>
    /// <param name="value">The value to escape.</param>
    /// <returns>The escaped Markdown cell.</returns>
    private static string ConvertToMarkdownCell(string value)
    {
        return value.Replace("|", "\\|", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();
    }
}
