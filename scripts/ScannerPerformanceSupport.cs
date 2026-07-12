using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// Provides reproducible external scanner performance measurement helpers.
/// </summary>
internal static class ScannerPerformanceSupport
{
    /// <summary>
    /// Schema identifier for scenario manifests.
    /// </summary>
    private const string ScenarioSchema = "picket.performance-scenario.v1";

    /// <summary>
    /// Schema identifier for measurement results.
    /// </summary>
    private const string ResultSchema = "picket.performance-result.v1";

    /// <summary>
    /// Measures every tool in a scanner performance scenario.
    /// </summary>
    /// <param name="scenario">The parsed scenario.</param>
    /// <param name="scenarioPath">The scenario manifest path.</param>
    /// <param name="outputPath">The result output path.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="coldIterations">The number of first-run measurements.</param>
    /// <param name="warmupIterations">The number of discarded warmup rounds.</param>
    /// <param name="warmIterations">The number of warmed measurement rounds.</param>
    /// <param name="processTimeoutSeconds">The timeout for one scanner invocation.</param>
    /// <param name="keepWork">Whether generated corpus and report files should be retained.</param>
    /// <returns>The performance result document.</returns>
    internal static async Task<JsonObject> MeasureAsync(
        JsonObject scenario,
        string scenarioPath,
        string outputPath,
        string repositoryRoot,
        int coldIterations,
        int warmupIterations,
        int warmIterations,
        int processTimeoutSeconds,
        bool keepWork)
    {
        ValidateScenario(scenario, scenarioPath);
        string scenarioName = ScriptSupport.GetString(scenario, "Name");
        string outputDirectory = Path.GetDirectoryName(outputPath)
            ?? throw new InvalidDataException($"Output path '{outputPath}' does not have a parent directory.");
        string workRoot = Path.Combine(outputDirectory, ".work");
        string sessionDirectory = Path.Combine(workRoot, $"{SanitizeFileName(scenarioName)}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(sessionDirectory);

        try
        {
            JsonObject corpus = PrepareCorpus(scenario, scenarioPath, repositoryRoot, sessionDirectory);
            string corpusPath = ScriptSupport.GetString(corpus, "Path");
            JsonArray tools = ResolveTools(scenario, scenarioPath, repositoryRoot, corpusPath);
            TimeSpan timeout = TimeSpan.FromSeconds(processTimeoutSeconds);

            foreach (JsonNode? toolNode in tools)
            {
                JsonObject tool = RequireObject(toolNode, "tool");
                tool["Version"] = await ReadVersionAsync(tool, repositoryRoot, timeout).ConfigureAwait(false);
            }

            await RunRoundsAsync(tools, "cold", coldIterations, record: true, sessionDirectory, repositoryRoot, corpusPath, timeout).ConfigureAwait(false);
            await RunRoundsAsync(tools, "warmup", warmupIterations, record: false, sessionDirectory, repositoryRoot, corpusPath, timeout).ConfigureAwait(false);
            await RunRoundsAsync(tools, "warm", warmIterations, record: true, sessionDirectory, repositoryRoot, corpusPath, timeout).ConfigureAwait(false);

            foreach (JsonNode? toolNode in tools)
            {
                JsonObject tool = RequireObject(toolNode, "tool");
                tool["Summary"] = CreateSummary(ScriptSupport.GetArray(tool, "Runs"));
            }

            (JsonArray parityGroups, bool parityPassed) = CreateParityGroups(tools);
            JsonObject result = new()
            {
                ["Schema"] = ResultSchema,
                ["ScenarioName"] = scenarioName,
                ["Description"] = ScriptSupport.GetString(scenario, "Description"),
                ["Comparability"] = ScriptSupport.GetString(scenario, "Comparability"),
                ["CapturedUtc"] = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                ["PicketCommit"] = TryReadGitValue(repositoryRoot, "rev-parse", "HEAD"),
                ["ScenarioPath"] = Path.GetRelativePath(repositoryRoot, scenarioPath).Replace('\\', '/'),
                ["ScenarioSha256"] = ScriptSupport.GetFileSha256(scenarioPath),
                ["ColdIterations"] = coldIterations,
                ["WarmupIterations"] = warmupIterations,
                ["WarmIterations"] = warmIterations,
                ["ProcessTimeoutSeconds"] = processTimeoutSeconds,
                ["Conditions"] = scenario["Conditions"]?.DeepClone(),
                ["Host"] = CreateHostMetadata(corpusPath),
                ["Corpus"] = CreatePublishedCorpus(corpus, keepWork),
                ["Tools"] = tools,
                ["ParityGroups"] = parityGroups,
                ["ParityPassed"] = parityPassed,
            };

            if (keepWork)
            {
                result["WorkDirectory"] = sessionDirectory;
            }

            return result;
        }
        finally
        {
            if (!keepWork)
            {
                DeleteGeneratedWorkDirectory(workRoot, sessionDirectory);
            }
        }
    }

    /// <summary>
    /// Gets a positive integer property.
    /// </summary>
    /// <param name="node">The source object.</param>
    /// <param name="name">The property name.</param>
    /// <param name="defaultValue">The default value.</param>
    /// <returns>The positive property value.</returns>
    internal static int GetPositiveInt(JsonObject node, string name, int defaultValue)
    {
        int value = node[name]?.GetValue<int>() ?? defaultValue;
        return value > 0 ? value : throw new InvalidDataException($"{name} must be a positive integer.");
    }

    /// <summary>
    /// Gets a non-negative integer property.
    /// </summary>
    /// <param name="node">The source object.</param>
    /// <param name="name">The property name.</param>
    /// <param name="defaultValue">The default value.</param>
    /// <returns>The non-negative property value.</returns>
    internal static int GetNonNegativeInt(JsonObject node, string name, int defaultValue)
    {
        int value = node[name]?.GetValue<int>() ?? defaultValue;
        return value >= 0 ? value : throw new InvalidDataException($"{name} must be a non-negative integer.");
    }

    /// <summary>
    /// Converts a display name to a portable file name.
    /// </summary>
    /// <param name="value">The display name.</param>
    /// <returns>The portable file name.</returns>
    internal static string SanitizeFileName(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (char character in value)
        {
            if (char.IsAsciiLetterOrDigit(character) || character is '-' or '_')
            {
                builder.Append(char.ToLowerInvariant(character));
            }
            else if (builder.Length != 0 && builder[^1] != '-')
            {
                builder.Append('-');
            }
        }

        string result = builder.ToString().Trim('-');
        return result.Length == 0 ? "scenario" : result;
    }

    /// <summary>
    /// Validates the scenario root and tool definitions.
    /// </summary>
    /// <param name="scenario">The scenario object.</param>
    /// <param name="scenarioPath">The scenario path for diagnostics.</param>
    private static void ValidateScenario(JsonObject scenario, string scenarioPath)
    {
        string schema = ScriptSupport.GetString(scenario, "Schema");
        if (!schema.Equals(ScenarioSchema, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Performance scenario '{scenarioPath}' must use schema '{ScenarioSchema}'.");
        }

        if (string.IsNullOrWhiteSpace(ScriptSupport.GetString(scenario, "Name")))
        {
            throw new InvalidDataException($"Performance scenario '{scenarioPath}' must define Name.");
        }

        JsonArray tools = ScriptSupport.GetArray(scenario, "Tools");
        if (tools.Count < 2)
        {
            throw new InvalidDataException($"Performance scenario '{scenarioPath}' must define at least two tools.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonNode? toolNode in tools)
        {
            JsonObject tool = RequireObject(toolNode, "tool");
            string name = ScriptSupport.GetString(tool, "Name");
            if (string.IsNullOrWhiteSpace(name) || !names.Add(name))
            {
                throw new InvalidDataException($"Performance scenario '{scenarioPath}' has an empty or duplicate tool name.");
            }

            if (tool["Arguments"] is not JsonArray)
            {
                throw new InvalidDataException($"Performance tool '{name}' must define Arguments.");
            }
        }
    }

    /// <summary>
    /// Prepares the immutable source corpus requested by the scenario.
    /// </summary>
    /// <param name="scenario">The scenario object.</param>
    /// <param name="scenarioPath">The scenario path.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="sessionDirectory">The generated session directory.</param>
    /// <returns>The corpus metadata.</returns>
    private static JsonObject PrepareCorpus(JsonObject scenario, string scenarioPath, string repositoryRoot, string sessionDirectory)
    {
        JsonObject corpus = RequireObject(scenario["Corpus"], "Corpus");
        string kind = ScriptSupport.GetString(corpus, "Kind");
        if (!kind.Equals("git-tracked-copy", StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Performance scenario '{scenarioPath}' uses unsupported corpus kind '{kind}'.");
        }

        string scenarioDirectory = Path.GetDirectoryName(scenarioPath) ?? repositoryRoot;
        string sourceRepositoryValue = ReplacePathPlaceholders(
            GetString(corpus, "Repository", "{repositoryRoot}"),
            repositoryRoot,
            scenarioDirectory,
            string.Empty,
            string.Empty);
        string sourceRepository = Path.GetFullPath(sourceRepositoryValue, scenarioDirectory);
        if (!Directory.Exists(Path.Combine(sourceRepository, ".git")))
        {
            throw new DirectoryNotFoundException($"Corpus repository '{sourceRepository}' is not a Git working tree.");
        }

        string[] prefixes = ReadStringArray(corpus, "PathPrefixes");
        var gitArguments = new List<string>
        {
            "-C",
            sourceRepository,
            "ls-files",
            "-z",
            "--",
        };
        gitArguments.AddRange(prefixes);
        (int exitCode, string stdout, string stderr) = ScriptSupport.RunProcess("git", gitArguments, repositoryRoot);
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"Could not enumerate tracked performance corpus files: {stderr.Trim()}");
        }

        string destination = Path.Combine(sessionDirectory, "corpus");
        Directory.CreateDirectory(destination);
        string sourceRoot = Path.GetFullPath(sourceRepository);
        string destinationRoot = Path.GetFullPath(destination);
        using IncrementalHash aggregateHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        int fileCount = 0;
        long totalBytes = 0;

        foreach (string relativePath in stdout.Split('\0', StringSplitOptions.RemoveEmptyEntries).Order(StringComparer.Ordinal))
        {
            string normalizedPath = relativePath.Replace('\\', '/');
            string sourcePath = ResolveContainedPath(sourceRoot, normalizedPath, "tracked corpus source");
            string destinationPath = ResolveContainedPath(destinationRoot, normalizedPath, "tracked corpus destination");
            string? parent = Path.GetDirectoryName(destinationPath);
            if (parent is not null)
            {
                Directory.CreateDirectory(parent);
            }

            File.Copy(sourcePath, destinationPath, overwrite: false);
            var info = new FileInfo(sourcePath);
            byte[] pathBytes = Encoding.UTF8.GetBytes(normalizedPath);
            aggregateHash.AppendData(pathBytes);
            aggregateHash.AppendData([0]);
            using FileStream stream = File.OpenRead(sourcePath);
            byte[] fileHash = SHA256.HashData(stream);
            aggregateHash.AppendData(fileHash);
            fileCount++;
            totalBytes += info.Length;
        }

        return new JsonObject
        {
            ["Kind"] = kind,
            ["Path"] = destinationRoot,
            ["SourceRepository"] = sourceRoot,
            ["SourceCommit"] = TryReadGitValue(sourceRoot, "rev-parse", "HEAD"),
            ["PathPrefixes"] = ToJsonArray(prefixes),
            ["FileCount"] = fileCount,
            ["TotalBytes"] = totalBytes,
            ["ManifestSha256"] = Convert.ToHexString(aggregateHash.GetHashAndReset()).ToLowerInvariant(),
        };
    }

    /// <summary>
    /// Resolves and validates the scenario tool definitions.
    /// </summary>
    /// <param name="scenario">The scenario object.</param>
    /// <param name="scenarioPath">The scenario path.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="corpusPath">The prepared corpus path.</param>
    /// <returns>The resolved tools.</returns>
    private static JsonArray ResolveTools(JsonObject scenario, string scenarioPath, string repositoryRoot, string corpusPath)
    {
        string scenarioDirectory = Path.GetDirectoryName(scenarioPath) ?? repositoryRoot;
        var result = new JsonArray();
        foreach (JsonNode? toolNode in ScriptSupport.GetArray(scenario, "Tools"))
        {
            JsonObject source = RequireObject(toolNode, "tool");
            string name = ScriptSupport.GetString(source, "Name");
            string executableVariable = ScriptSupport.GetString(source, "ExecutableEnvironmentVariable");
            string executableValue = executableVariable.Length == 0
                ? string.Empty
                : Environment.GetEnvironmentVariable(executableVariable) ?? string.Empty;
            if (executableValue.Length == 0)
            {
                executableValue = ScriptSupport.GetString(source, "Executable");
            }

            if (executableValue.Length == 0)
            {
                throw new InvalidDataException($"Performance tool '{name}' must define Executable or ExecutableEnvironmentVariable.");
            }

            executableValue = ReplacePathPlaceholders(executableValue, repositoryRoot, scenarioDirectory, corpusPath, string.Empty);
            string executable = ScriptSupport.ResolveCommandPath(executableValue, $"{name} executable");
            string repositoryValue = ReplacePathPlaceholders(
                ScriptSupport.GetString(source, "Repository"),
                repositoryRoot,
                scenarioDirectory,
                corpusPath,
                string.Empty);
            string toolRepository = repositoryValue.Length == 0 ? string.Empty : Path.GetFullPath(repositoryValue, scenarioDirectory);
            string workingDirectory = ReplacePathPlaceholders(
                GetString(source, "WorkingDirectory", "{corpus}"),
                repositoryRoot,
                scenarioDirectory,
                corpusPath,
                string.Empty);
            workingDirectory = Path.GetFullPath(workingDirectory, scenarioDirectory);
            if (!Directory.Exists(workingDirectory))
            {
                throw new DirectoryNotFoundException($"Performance tool '{name}' working directory '{workingDirectory}' does not exist.");
            }

            var tool = new JsonObject
            {
                ["Name"] = name,
                ["Executable"] = executable,
                ["ExecutableSha256"] = ScriptSupport.GetFileSha256(executable),
                ["Repository"] = toolRepository,
                ["RepositoryCommit"] = toolRepository.Length == 0 ? string.Empty : TryReadGitValue(toolRepository, "rev-parse", "HEAD"),
                ["WorkingDirectory"] = workingDirectory,
                ["Arguments"] = source["Arguments"]?.DeepClone(),
                ["VersionArguments"] = source["VersionArguments"]?.DeepClone() ?? new JsonArray("--version"),
                ["AllowedExitCodes"] = source["AllowedExitCodes"]?.DeepClone() ?? new JsonArray(0),
                ["ReportFormat"] = GetString(source, "ReportFormat", "none"),
                ["ParityGroup"] = ScriptSupport.GetString(source, "ParityGroup"),
                ["StandardInputPath"] = ScriptSupport.GetString(source, "StandardInputPath"),
                ["Runs"] = new JsonArray(),
            };
            ScriptSupport.AddNode(result, tool);
        }

        return result;
    }

    /// <summary>
    /// Runs one phase for every tool while rotating first position between rounds.
    /// </summary>
    /// <param name="tools">The resolved tools.</param>
    /// <param name="phase">The phase name.</param>
    /// <param name="roundCount">The number of rounds.</param>
    /// <param name="record">Whether measurements should be retained.</param>
    /// <param name="sessionDirectory">The generated session directory.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="corpusPath">The prepared corpus path.</param>
    /// <param name="timeout">The per-process timeout.</param>
    private static async Task RunRoundsAsync(
        JsonArray tools,
        string phase,
        int roundCount,
        bool record,
        string sessionDirectory,
        string repositoryRoot,
        string corpusPath,
        TimeSpan timeout)
    {
        for (int round = 0; round < roundCount; round++)
        {
            for (int offset = 0; offset < tools.Count; offset++)
            {
                int toolIndex = (round + offset) % tools.Count;
                JsonObject tool = RequireObject(tools[toolIndex], "tool");
                JsonObject run = await RunToolAsync(
                    tool,
                    phase,
                    round + 1,
                    sessionDirectory,
                    repositoryRoot,
                    corpusPath,
                    timeout).ConfigureAwait(false);
                if (record)
                {
                    ScriptSupport.AddNode(ScriptSupport.GetArray(tool, "Runs"), run);
                }
            }
        }
    }

    /// <summary>
    /// Runs one measured scanner invocation.
    /// </summary>
    /// <param name="tool">The resolved tool.</param>
    /// <param name="phase">The phase name.</param>
    /// <param name="iteration">The one-based iteration.</param>
    /// <param name="sessionDirectory">The generated session directory.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="corpusPath">The prepared corpus path.</param>
    /// <param name="timeout">The process timeout.</param>
    /// <returns>The run metrics.</returns>
    private static async Task<JsonObject> RunToolAsync(
        JsonObject tool,
        string phase,
        int iteration,
        string sessionDirectory,
        string repositoryRoot,
        string corpusPath,
        TimeSpan timeout)
    {
        string name = ScriptSupport.GetString(tool, "Name");
        string reportDirectory = Path.Combine(sessionDirectory, "reports");
        Directory.CreateDirectory(reportDirectory);
        string reportPath = Path.Combine(reportDirectory, $"{SanitizeFileName(name)}-{phase}-{iteration}.report");
        string workingDirectory = ScriptSupport.GetString(tool, "WorkingDirectory");
        string[] arguments = ReadStringArray(tool, "Arguments")
            .Select(value => ReplacePathPlaceholders(value, repositoryRoot, workingDirectory, corpusPath, reportPath))
            .ToArray();
        string standardInputPath = ReplacePathPlaceholders(
            ScriptSupport.GetString(tool, "StandardInputPath"),
            repositoryRoot,
            workingDirectory,
            corpusPath,
            reportPath);
        if (standardInputPath.Length != 0)
        {
            standardInputPath = Path.GetFullPath(standardInputPath, workingDirectory);
        }

        JsonObject processResult = await RunProcessAsync(
            ScriptSupport.GetString(tool, "Executable"),
            arguments,
            workingDirectory,
            standardInputPath,
            timeout).ConfigureAwait(false);
        int exitCode = processResult["ExitCode"]?.GetValue<int>() ?? -1;
        int[] allowedExitCodes = ReadIntArray(tool, "AllowedExitCodes");
        if (!allowedExitCodes.Contains(exitCode))
        {
            throw new InvalidOperationException($"Performance tool '{name}' exited with code {exitCode} during {phase} iteration {iteration}.");
        }

        JsonObject report = AnalyzeReport(reportPath, ScriptSupport.GetString(tool, "ReportFormat"));
        processResult["Phase"] = phase;
        processResult["Iteration"] = iteration;
        processResult["ReportBytes"] = report["Bytes"]?.DeepClone();
        processResult["ReportSha256"] = report["Sha256"]?.DeepClone();
        processResult["FindingCount"] = report["FindingCount"]?.DeepClone();
        processResult["NormalizedFindingSetSha256"] = report["NormalizedFindingSetSha256"]?.DeepClone();
        return processResult;
    }

    /// <summary>
    /// Reads tool version output without retaining unbounded process text.
    /// </summary>
    /// <param name="tool">The resolved tool.</param>
    /// <param name="repositoryRoot">The Picket repository root.</param>
    /// <param name="timeout">The process timeout.</param>
    /// <returns>The bounded version text.</returns>
    private static async Task<string> ReadVersionAsync(JsonObject tool, string repositoryRoot, TimeSpan timeout)
    {
        string[] arguments = ReadStringArray(tool, "VersionArguments");
        JsonObject result = await RunProcessAsync(
            ScriptSupport.GetString(tool, "Executable"),
            arguments,
            repositoryRoot,
            string.Empty,
            timeout,
            includeOutput: true).ConfigureAwait(false);
        int exitCode = result["ExitCode"]?.GetValue<int>() ?? -1;
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"Could not read version for performance tool '{ScriptSupport.GetString(tool, "Name")}'.");
        }

        return ScriptSupport.GetString(result, "Output");
    }

    /// <summary>
    /// Runs a process and captures bounded metrics and hashes.
    /// </summary>
    /// <param name="filePath">The executable path.</param>
    /// <param name="arguments">The process arguments.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="standardInputPath">The optional standard-input path.</param>
    /// <param name="timeout">The process timeout.</param>
    /// <param name="includeOutput">Whether bounded text output should be returned.</param>
    /// <returns>The process metrics.</returns>
    private static async Task<JsonObject> RunProcessAsync(
        string filePath,
        string[] arguments,
        string workingDirectory,
        string standardInputPath,
        TimeSpan timeout,
        bool includeOutput = false)
    {
        var startInfo = new ProcessStartInfo(filePath)
        {
            RedirectStandardError = true,
            RedirectStandardInput = standardInputPath.Length != 0,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process
        {
            StartInfo = startInfo,
        };
        var stopwatch = Stopwatch.StartNew();
        if (!process.Start())
        {
            throw new InvalidOperationException($"Could not start '{filePath}'.");
        }

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        if (standardInputPath.Length != 0)
        {
            await using FileStream input = File.OpenRead(standardInputPath);
            await input.CopyToAsync(process.StandardInput.BaseStream).ConfigureAwait(false);
            process.StandardInput.Close();
        }

        using var timeoutSource = new CancellationTokenSource(timeout);
        long peakWorkingSetBytes = 0;
        TimeSpan processorTime = TimeSpan.Zero;
        try
        {
            Task exitTask = process.WaitForExitAsync(timeoutSource.Token);
            while (!exitTask.IsCompleted)
            {
                SampleProcessMetrics(process, ref peakWorkingSetBytes, ref processorTime);
                await Task.WhenAny(exitTask, Task.Delay(10, timeoutSource.Token)).ConfigureAwait(false);
            }

            await exitTask.ConfigureAwait(false);
            SampleProcessMetrics(process, ref peakWorkingSetBytes, ref processorTime);
        }
        catch (OperationCanceledException) when (timeoutSource.IsCancellationRequested)
        {
            TryKillProcessTree(process);
            throw new TimeoutException($"Process '{filePath}' exceeded the {timeout.TotalSeconds:0}-second performance timeout.");
        }

        string stdout = await stdoutTask.ConfigureAwait(false);
        string stderr = await stderrTask.ConfigureAwait(false);
        stopwatch.Stop();
        var result = new JsonObject
        {
            ["ExitCode"] = process.ExitCode,
            ["ElapsedMilliseconds"] = stopwatch.Elapsed.TotalMilliseconds,
            ["ProcessorMilliseconds"] = processorTime.TotalMilliseconds,
            ["PeakWorkingSetBytes"] = peakWorkingSetBytes,
            ["StdoutBytes"] = Encoding.UTF8.GetByteCount(stdout),
            ["StdoutSha256"] = HashText(stdout),
            ["StderrBytes"] = Encoding.UTF8.GetByteCount(stderr),
            ["StderrSha256"] = HashText(stderr),
        };
        if (includeOutput)
        {
            string output = stdout.Length != 0 ? stdout.Trim() : stderr.Trim();
            result["Output"] = output.Length <= 4096 ? output : output[..4096];
        }

        return result;
    }

    /// <summary>
    /// Samples resource metrics before a short-lived process releases its native handle data.
    /// </summary>
    /// <param name="process">The measured process.</param>
    /// <param name="peakWorkingSetBytes">The maximum observed working set.</param>
    /// <param name="processorTime">The latest observed processor time.</param>
    private static void SampleProcessMetrics(Process process, ref long peakWorkingSetBytes, ref TimeSpan processorTime)
    {
        try
        {
            process.Refresh();
            peakWorkingSetBytes = Math.Max(peakWorkingSetBytes, process.WorkingSet64);
            processorTime = process.TotalProcessorTime;
        }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
        }
    }

    /// <summary>
    /// Analyzes one scanner report without retaining finding contents.
    /// </summary>
    /// <param name="reportPath">The report path.</param>
    /// <param name="format">The report format.</param>
    /// <returns>The report metrics.</returns>
    private static JsonObject AnalyzeReport(string reportPath, string format)
    {
        if (format.Equals("none", StringComparison.Ordinal))
        {
            return new JsonObject
            {
                ["Bytes"] = 0,
                ["Sha256"] = string.Empty,
                ["FindingCount"] = -1,
                ["NormalizedFindingSetSha256"] = string.Empty,
            };
        }

        if (!File.Exists(reportPath))
        {
            throw new FileNotFoundException($"Scanner did not write expected report '{reportPath}'.", reportPath);
        }

        return format switch
        {
            "gitleaks-json" => AnalyzeJsonArrayReport(reportPath),
            "jsonl" => AnalyzeJsonLinesReport(reportPath),
            _ => throw new InvalidDataException($"Unsupported performance report format '{format}'."),
        };
    }

    /// <summary>
    /// Analyzes a Gitleaks-shaped JSON array report.
    /// </summary>
    /// <param name="reportPath">The report path.</param>
    /// <returns>The report metrics.</returns>
    private static JsonObject AnalyzeJsonArrayReport(string reportPath)
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(reportPath));
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"Expected a JSON array report in '{reportPath}'.");
        }

        var findings = new List<string>();
        foreach (JsonElement finding in document.RootElement.EnumerateArray())
        {
            var builder = new StringBuilder();
            AppendCanonicalJson(builder, finding);
            findings.Add(builder.ToString());
        }

        findings.Sort(StringComparer.Ordinal);
        return CreateReportMetrics(reportPath, findings);
    }

    /// <summary>
    /// Analyzes a JSON Lines report.
    /// </summary>
    /// <param name="reportPath">The report path.</param>
    /// <returns>The report metrics.</returns>
    private static JsonObject AnalyzeJsonLinesReport(string reportPath)
    {
        var findings = new List<string>();
        foreach (string line in File.ReadLines(reportPath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            using JsonDocument document = JsonDocument.Parse(line);
            var builder = new StringBuilder();
            AppendCanonicalJson(builder, document.RootElement);
            findings.Add(builder.ToString());
        }

        findings.Sort(StringComparer.Ordinal);
        return CreateReportMetrics(reportPath, findings);
    }

    /// <summary>
    /// Creates report metrics from canonical finding rows.
    /// </summary>
    /// <param name="reportPath">The report path.</param>
    /// <param name="findings">The canonical findings.</param>
    /// <returns>The report metrics.</returns>
    private static JsonObject CreateReportMetrics(string reportPath, List<string> findings)
    {
        string normalized = string.Join('\n', findings);
        return new JsonObject
        {
            ["Bytes"] = new FileInfo(reportPath).Length,
            ["Sha256"] = ScriptSupport.GetFileSha256(reportPath),
            ["FindingCount"] = findings.Count,
            ["NormalizedFindingSetSha256"] = HashText(normalized),
        };
    }

    /// <summary>
    /// Appends deterministic JSON with object properties sorted ordinally.
    /// </summary>
    /// <param name="builder">The destination builder.</param>
    /// <param name="element">The JSON element.</param>
    private static void AppendCanonicalJson(StringBuilder builder, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                builder.Append('{');
                bool firstProperty = true;
                foreach (JsonProperty property in element.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal))
                {
                    if (!firstProperty)
                    {
                        builder.Append(',');
                    }

                    AppendJsonString(builder, property.Name);
                    builder.Append(':');
                    AppendCanonicalJson(builder, property.Value);
                    firstProperty = false;
                }

                builder.Append('}');
                break;
            case JsonValueKind.Array:
                builder.Append('[');
                bool firstItem = true;
                foreach (JsonElement item in element.EnumerateArray())
                {
                    if (!firstItem)
                    {
                        builder.Append(',');
                    }

                    AppendCanonicalJson(builder, item);
                    firstItem = false;
                }

                builder.Append(']');
                break;
            case JsonValueKind.String:
                AppendJsonString(builder, element.GetString() ?? string.Empty);
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                builder.Append(element.GetRawText());
                break;
            default:
                throw new InvalidDataException($"Unsupported JSON value kind '{element.ValueKind}'.");
        }
    }

    /// <summary>
    /// Creates aggregate timing and resource metrics for a tool.
    /// </summary>
    /// <param name="runs">The recorded runs.</param>
    /// <returns>The aggregate summary.</returns>
    private static JsonObject CreateSummary(JsonArray runs)
    {
        JsonArray coldRuns = FilterRuns(runs, "cold");
        JsonArray warmRuns = FilterRuns(runs, "warm");
        return new JsonObject
        {
            ["Cold"] = CreatePhaseSummary(coldRuns),
            ["Warm"] = CreatePhaseSummary(warmRuns),
        };
    }

    /// <summary>
    /// Filters recorded runs by phase.
    /// </summary>
    /// <param name="runs">The recorded runs.</param>
    /// <param name="phase">The phase name.</param>
    /// <returns>The matching runs.</returns>
    private static JsonArray FilterRuns(JsonArray runs, string phase)
    {
        var result = new JsonArray();
        foreach (JsonNode? runNode in runs)
        {
            JsonObject run = RequireObject(runNode, "run");
            if (ScriptSupport.GetString(run, "Phase").Equals(phase, StringComparison.Ordinal))
            {
                result.Add(run.DeepClone());
            }
        }

        return result;
    }

    /// <summary>
    /// Creates summary statistics for one measurement phase.
    /// </summary>
    /// <param name="runs">The phase runs.</param>
    /// <returns>The phase summary.</returns>
    private static JsonObject CreatePhaseSummary(JsonArray runs)
    {
        double[] elapsed = ReadDoubleValues(runs, "ElapsedMilliseconds");
        double[] processor = ReadDoubleValues(runs, "ProcessorMilliseconds");
        long[] peakWorkingSet = ReadLongValues(runs, "PeakWorkingSetBytes");
        int[] findingCounts = ReadIntValues(runs, "FindingCount");
        return new JsonObject
        {
            ["RunCount"] = runs.Count,
            ["ElapsedMillisecondsMinimum"] = elapsed.Min(),
            ["ElapsedMillisecondsMedian"] = Median(elapsed),
            ["ElapsedMillisecondsP95"] = Percentile95(elapsed),
            ["ElapsedMillisecondsMaximum"] = elapsed.Max(),
            ["ProcessorMillisecondsMedian"] = Median(processor),
            ["PeakWorkingSetBytesMedian"] = Median(peakWorkingSet),
            ["PeakWorkingSetBytesMaximum"] = peakWorkingSet.Max(),
            ["FindingCount"] = findingCounts.Distinct().Count() == 1 ? findingCounts[0] : -1,
        };
    }

    /// <summary>
    /// Creates finding-parity summaries for named comparable tool groups.
    /// </summary>
    /// <param name="tools">The measured tools.</param>
    /// <returns>The parity summaries and overall result.</returns>
    private static (JsonArray Groups, bool Passed) CreateParityGroups(JsonArray tools)
    {
        string[] groupNames = [.. tools
            .Select(tool => ScriptSupport.GetString(tool, "ParityGroup"))
            .Where(group => group.Length != 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];
        var groups = new JsonArray();
        bool allPassed = groupNames.Length != 0;

        foreach (string groupName in groupNames)
        {
            JsonObject[] groupTools = [.. tools
                .Select(tool => RequireObject(tool, "tool"))
                .Where(tool => ScriptSupport.GetString(tool, "ParityGroup").Equals(groupName, StringComparison.Ordinal))];
            string[] hashes = [.. groupTools
                .SelectMany(tool => ScriptSupport.GetArray(tool, "Runs"))
                .Where(run => ScriptSupport.GetString(run, "Phase").Equals("warm", StringComparison.Ordinal))
                .Select(run => ScriptSupport.GetString(run, "NormalizedFindingSetSha256"))
                .Distinct(StringComparer.Ordinal)];
            int[] findingCounts = [.. groupTools
                .SelectMany(tool => ScriptSupport.GetArray(tool, "Runs"))
                .Where(run => ScriptSupport.GetString(run, "Phase").Equals("warm", StringComparison.Ordinal))
                .Select(run => run?["FindingCount"]?.GetValue<int>() ?? -1)
                .Distinct()];
            bool passed = groupTools.Length >= 2
                && hashes.Length == 1
                && hashes[0].Length != 0
                && findingCounts.Length == 1
                && findingCounts[0] >= 0;
            allPassed &= passed;
            ScriptSupport.AddNode(groups, new JsonObject
            {
                ["Name"] = groupName,
                ["Tools"] = ToJsonArray(groupTools.Select(tool => ScriptSupport.GetString(tool, "Name"))),
                ["FindingCount"] = findingCounts.Length == 1 ? findingCounts[0] : -1,
                ["NormalizedFindingSetSha256"] = hashes.Length == 1 ? hashes[0] : string.Empty,
                ["Passed"] = passed,
            });
        }

        return (groups, allPassed);
    }

    /// <summary>
    /// Creates host metadata needed to review benchmark results.
    /// </summary>
    /// <param name="corpusPath">The corpus path used to identify the filesystem.</param>
    /// <returns>The host metadata.</returns>
    private static JsonObject CreateHostMetadata(string corpusPath)
    {
        string root = Path.GetPathRoot(corpusPath) ?? corpusPath;
        var drive = new DriveInfo(root);
        return new JsonObject
        {
            ["OperatingSystem"] = RuntimeInformation.OSDescription,
            ["OSArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["ProcessArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["RuntimeVersion"] = RuntimeInformation.FrameworkDescription,
            ["DotNetSdkVersion"] = ReadDotNetSdkVersion(),
            ["ProcessorCount"] = Environment.ProcessorCount,
            ["Processor"] = ReadProcessorName(),
            ["GcTotalAvailableMemoryBytes"] = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes,
            ["FileSystem"] = drive.DriveFormat,
            ["Runner"] = ReadRunnerType(),
        };
    }

    /// <summary>
    /// Creates published corpus metadata without retaining a deleted path.
    /// </summary>
    /// <param name="corpus">The internal corpus metadata.</param>
    /// <param name="keepWork">Whether generated work is retained.</param>
    /// <returns>The published corpus metadata.</returns>
    private static JsonObject CreatePublishedCorpus(JsonObject corpus, bool keepWork)
    {
        return new JsonObject
        {
            ["Kind"] = corpus["Kind"]?.DeepClone(),
            ["SourceRepository"] = corpus["SourceRepository"]?.DeepClone(),
            ["SourceCommit"] = corpus["SourceCommit"]?.DeepClone(),
            ["PathPrefixes"] = corpus["PathPrefixes"]?.DeepClone(),
            ["FileCount"] = corpus["FileCount"]?.DeepClone(),
            ["TotalBytes"] = corpus["TotalBytes"]?.DeepClone(),
            ["ManifestSha256"] = corpus["ManifestSha256"]?.DeepClone(),
            ["GeneratedPath"] = keepWork ? corpus["Path"]?.DeepClone() : null,
        };
    }

    /// <summary>
    /// Reads the current .NET SDK version.
    /// </summary>
    /// <returns>The SDK version.</returns>
    private static string ReadDotNetSdkVersion()
    {
        try
        {
            (int exitCode, string stdout, _) = ScriptSupport.RunProcess("dotnet", ["--version"], Directory.GetCurrentDirectory());
            return exitCode == 0 ? stdout.Trim() : string.Empty;
        }
        catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Reads a useful processor model without adding a platform-management dependency.
    /// </summary>
    /// <returns>The processor model or an empty string.</returns>
    private static string ReadProcessorName()
    {
        string windowsName = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER") ?? string.Empty;
        if (windowsName.Length != 0)
        {
            return windowsName;
        }

        if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
        {
            foreach (string line in File.ReadLines("/proc/cpuinfo"))
            {
                int separator = line.IndexOf(':');
                if (separator > 0 && line[..separator].Trim().Equals("model name", StringComparison.Ordinal))
                {
                    return line[(separator + 1)..].Trim();
                }
            }
        }

        if (OperatingSystem.IsMacOS())
        {
            try
            {
                (int exitCode, string stdout, _) = ScriptSupport.RunProcess(
                    "sysctl",
                    ["-n", "machdep.cpu.brand_string"],
                    Directory.GetCurrentDirectory());
                return exitCode == 0 ? stdout.Trim() : string.Empty;
            }
            catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException)
            {
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Identifies the current automation runner type.
    /// </summary>
    /// <returns>The runner type.</returns>
    private static string ReadRunnerType()
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS")?.Equals("true", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "github-actions";
        }

        if (Environment.GetEnvironmentVariable("TF_BUILD")?.Equals("true", StringComparison.OrdinalIgnoreCase) == true)
        {
            return "azure-pipelines";
        }

        return "local";
    }

    /// <summary>
    /// Replaces supported scenario path placeholders.
    /// </summary>
    /// <param name="value">The source value.</param>
    /// <param name="repositoryRoot">The repository root.</param>
    /// <param name="scenarioDirectory">The scenario or working directory.</param>
    /// <param name="corpusPath">The corpus path.</param>
    /// <param name="reportPath">The report path.</param>
    /// <returns>The expanded value.</returns>
    private static string ReplacePathPlaceholders(
        string value,
        string repositoryRoot,
        string scenarioDirectory,
        string corpusPath,
        string reportPath)
    {
        return value
            .Replace("{repositoryRoot}", repositoryRoot, StringComparison.Ordinal)
            .Replace("{scenarioDirectory}", scenarioDirectory, StringComparison.Ordinal)
            .Replace("{corpus}", corpusPath, StringComparison.Ordinal)
            .Replace("{report}", reportPath, StringComparison.Ordinal);
    }

    /// <summary>
    /// Resolves a path and verifies that it stays inside the intended root.
    /// </summary>
    /// <param name="root">The containment root.</param>
    /// <param name="relativePath">The relative path.</param>
    /// <param name="description">The path description.</param>
    /// <returns>The contained full path.</returns>
    private static string ResolveContainedPath(string root, string relativePath, string description)
    {
        if (Path.IsPathRooted(relativePath))
        {
            throw new InvalidDataException($"{description} path '{relativePath}' must be relative.");
        }

        string fullPath = Path.GetFullPath(relativePath, root);
        string relative = Path.GetRelativePath(root, fullPath);
        if (relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathRooted(relative))
        {
            throw new InvalidDataException($"{description} path '{relativePath}' leaves its root.");
        }

        return fullPath;
    }

    /// <summary>
    /// Deletes only the generated per-run work directory.
    /// </summary>
    /// <param name="workRoot">The generated work root.</param>
    /// <param name="sessionDirectory">The generated session directory.</param>
    private static void DeleteGeneratedWorkDirectory(string workRoot, string sessionDirectory)
    {
        string fullRoot = Path.GetFullPath(workRoot);
        string fullSession = Path.GetFullPath(sessionDirectory);
        string relative = Path.GetRelativePath(fullRoot, fullSession);
        if (relative.Length == 0
            || relative.Equals("..", StringComparison.Ordinal)
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathRooted(relative))
        {
            throw new InvalidOperationException($"Refusing to delete performance work directory '{fullSession}'.");
        }

        if (Directory.Exists(fullSession))
        {
            Directory.Delete(fullSession, recursive: true);
        }
    }

    /// <summary>
    /// Creates an array of JSON strings.
    /// </summary>
    /// <param name="values">The string values.</param>
    /// <returns>The JSON array.</returns>
    private static JsonArray ToJsonArray(IEnumerable<string> values)
    {
        var result = new JsonArray();
        foreach (string value in values)
        {
            ScriptSupport.AddNode(result, JsonValue.Create(value));
        }

        return result;
    }

    /// <summary>
    /// Reads a required JSON object.
    /// </summary>
    /// <param name="node">The source node.</param>
    /// <param name="description">The object description.</param>
    /// <returns>The JSON object.</returns>
    private static JsonObject RequireObject(JsonNode? node, string description)
    {
        return node as JsonObject ?? throw new InvalidDataException($"Expected {description} to be a JSON object.");
    }

    /// <summary>
    /// Reads a string property with a default value.
    /// </summary>
    /// <param name="node">The source object.</param>
    /// <param name="name">The property name.</param>
    /// <param name="defaultValue">The default value.</param>
    /// <returns>The string property or default value.</returns>
    private static string GetString(JsonObject node, string name, string defaultValue)
    {
        string value = ScriptSupport.GetString(node, name);
        return value.Length == 0 ? defaultValue : value;
    }

    /// <summary>
    /// Appends one JSON string without reflection-based serialization.
    /// </summary>
    /// <param name="builder">The destination builder.</param>
    /// <param name="value">The string value.</param>
    private static void AppendJsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        builder.Append(JsonEncodedText.Encode(value).ToString());
        builder.Append('"');
    }

    /// <summary>
    /// Reads a string array property.
    /// </summary>
    /// <param name="node">The source object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The string values.</returns>
    private static string[] ReadStringArray(JsonObject node, string name)
    {
        JsonArray values = ScriptSupport.GetArray(node, name);
        return [.. values.Select(value => value?.GetValue<string>() ?? string.Empty)];
    }

    /// <summary>
    /// Reads an integer array property.
    /// </summary>
    /// <param name="node">The source object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The integer values.</returns>
    private static int[] ReadIntArray(JsonObject node, string name)
    {
        JsonArray values = ScriptSupport.GetArray(node, name);
        return [.. values.Select(value => value?.GetValue<int>() ?? int.MinValue)];
    }

    /// <summary>
    /// Reads double values from run objects.
    /// </summary>
    /// <param name="runs">The run array.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The values.</returns>
    private static double[] ReadDoubleValues(JsonArray runs, string name)
    {
        return [.. runs.Select(run => run?[name]?.GetValue<double>() ?? 0)];
    }

    /// <summary>
    /// Reads long values from run objects.
    /// </summary>
    /// <param name="runs">The run array.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The values.</returns>
    private static long[] ReadLongValues(JsonArray runs, string name)
    {
        return [.. runs.Select(run => run?[name]?.GetValue<long>() ?? 0)];
    }

    /// <summary>
    /// Reads integer values from run objects.
    /// </summary>
    /// <param name="runs">The run array.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The values.</returns>
    private static int[] ReadIntValues(JsonArray runs, string name)
    {
        return [.. runs.Select(run => run?[name]?.GetValue<int>() ?? -1)];
    }

    /// <summary>
    /// Computes the median of double values.
    /// </summary>
    /// <param name="values">The values.</param>
    /// <returns>The median.</returns>
    private static double Median(double[] values)
    {
        double[] sorted = [.. values.Order()];
        int midpoint = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[midpoint - 1] + sorted[midpoint]) / 2 : sorted[midpoint];
    }

    /// <summary>
    /// Computes the median of long values.
    /// </summary>
    /// <param name="values">The values.</param>
    /// <returns>The median.</returns>
    private static long Median(long[] values)
    {
        long[] sorted = [.. values.Order()];
        int midpoint = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[midpoint - 1] + sorted[midpoint]) / 2 : sorted[midpoint];
    }

    /// <summary>
    /// Computes the nearest-rank 95th percentile.
    /// </summary>
    /// <param name="values">The values.</param>
    /// <returns>The 95th percentile.</returns>
    private static double Percentile95(double[] values)
    {
        double[] sorted = [.. values.Order()];
        int index = Math.Max(0, (int)Math.Ceiling(sorted.Length * 0.95) - 1);
        return sorted[index];
    }

    /// <summary>
    /// Hashes UTF-8 text with SHA-256.
    /// </summary>
    /// <param name="value">The text.</param>
    /// <returns>The lowercase hash.</returns>
    private static string HashText(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    /// <summary>
    /// Reads a Git value without making optional metadata fatal.
    /// </summary>
    /// <param name="repositoryPath">The repository path.</param>
    /// <param name="arguments">The Git arguments.</param>
    /// <returns>The trimmed value or an empty string.</returns>
    private static string TryReadGitValue(string repositoryPath, params string[] arguments)
    {
        try
        {
            return ScriptSupport.RunGit(repositoryPath, arguments);
        }
        catch (InvalidOperationException)
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Terminates a timed-out process and its descendants when supported.
    /// </summary>
    /// <param name="process">The process.</param>
    private static void TryKillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
    }
}
