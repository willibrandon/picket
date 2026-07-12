#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScannerPerformanceSupport.cs
#:include ScriptSupport.cs

using System.Text.Json.Nodes;

try
{
    return await MeasureScannerPerformanceApp.RunAsync(args).ConfigureAwait(false);
}
catch (Exception ex) when (ex is ArgumentException
    or DirectoryNotFoundException
    or FileNotFoundException
    or InvalidDataException
    or InvalidOperationException
    or TimeoutException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Measures external scanner processes from a reproducible scenario manifest.
/// </summary>
internal static class MeasureScannerPerformanceApp
{
    /// <summary>
    /// Runs the scanner performance measurement app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static async Task<int> RunAsync(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            [
                "ScenarioPath",
                "OutputPath",
                "ColdIterations",
                "WarmupIterations",
                "WarmIterations",
                "ProcessTimeoutSeconds",
            ],
            [],
            [
                "FailOnParityDifference",
                "KeepWork",
            ]);

        string scenarioPath = ScriptSupport.GetString(values, "ScenarioPath");
        if (string.IsNullOrWhiteSpace(scenarioPath))
        {
            throw new ArgumentException("-ScenarioPath is required.");
        }

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string resolvedScenarioPath = ScriptSupport.ResolveExistingPath(scenarioPath, "performance scenario", Directory.GetCurrentDirectory());
        JsonObject scenario = ScriptSupport.ReadJsonObject(resolvedScenarioPath);
        string scenarioName = ScriptSupport.GetString(scenario, "Name");
        if (string.IsNullOrWhiteSpace(scenarioName))
        {
            throw new InvalidDataException($"Performance scenario '{resolvedScenarioPath}' does not define Name.");
        }

        string outputPath = ScriptSupport.GetString(
            values,
            "OutputPath",
            Path.Combine(repositoryRoot, "artifacts", "performance", "results", $"{ScannerPerformanceSupport.SanitizeFileName(scenarioName)}.json"));
        string resolvedOutputPath = Path.GetFullPath(outputPath);
        int coldIterations = ReadOptionalPositiveInt(values, "ColdIterations", ScannerPerformanceSupport.GetPositiveInt(scenario, "ColdIterations", 1));
        int warmupIterations = ReadOptionalNonNegativeInt(values, "WarmupIterations", ScannerPerformanceSupport.GetNonNegativeInt(scenario, "WarmupIterations", 1));
        int warmIterations = ReadOptionalPositiveInt(values, "WarmIterations", ScannerPerformanceSupport.GetPositiveInt(scenario, "WarmIterations", 5));
        int processTimeoutSeconds = ReadOptionalPositiveInt(
            values,
            "ProcessTimeoutSeconds",
            ScannerPerformanceSupport.GetPositiveInt(scenario, "ProcessTimeoutSeconds", 300));
        bool failOnParityDifference = ScriptSupport.GetSwitch(switches, "FailOnParityDifference");
        bool keepWork = ScriptSupport.GetSwitch(switches, "KeepWork");

        JsonObject result = await ScannerPerformanceSupport.MeasureAsync(
            scenario,
            resolvedScenarioPath,
            resolvedOutputPath,
            repositoryRoot,
            coldIterations,
            warmupIterations,
            warmIterations,
            processTimeoutSeconds,
            keepWork).ConfigureAwait(false);

        ScriptSupport.WriteJsonFile(resolvedOutputPath, result);
        Console.WriteLine($"performance result written: {resolvedOutputPath}");
        Console.WriteLine($"parity: {(result["ParityPassed"]?.GetValue<bool>() == true ? "passed" : "not established")}");

        return failOnParityDifference && result["ParityPassed"]?.GetValue<bool>() != true ? 2 : 0;
    }

    /// <summary>
    /// Reads a positive integer command-line override.
    /// </summary>
    /// <param name="values">The parsed command-line values.</param>
    /// <param name="name">The option name.</param>
    /// <param name="defaultValue">The default value.</param>
    /// <returns>The parsed positive integer.</returns>
    private static int ReadOptionalPositiveInt(Dictionary<string, List<string>> values, string name, int defaultValue)
    {
        string value = ScriptSupport.GetString(values, name);
        if (value.Length == 0)
        {
            return defaultValue;
        }

        return int.TryParse(value, out int parsed) && parsed > 0
            ? parsed
            : throw new ArgumentException($"-{name} must be a positive integer.");
    }

    /// <summary>
    /// Reads a non-negative integer command-line override.
    /// </summary>
    /// <param name="values">The parsed command-line values.</param>
    /// <param name="name">The option name.</param>
    /// <param name="defaultValue">The default value.</param>
    /// <returns>The parsed non-negative integer.</returns>
    private static int ReadOptionalNonNegativeInt(Dictionary<string, List<string>> values, string name, int defaultValue)
    {
        string value = ScriptSupport.GetString(values, name);
        if (value.Length == 0)
        {
            return defaultValue;
        }

        return int.TryParse(value, out int parsed) && parsed >= 0
            ? parsed
            : throw new ArgumentException($"-{name} must be a non-negative integer.");
    }
}
