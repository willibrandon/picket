#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Runtime.InteropServices;
using System.Text.Json.Nodes;

try
{
    return CaptureCompatibilityOracleApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Captures side-by-side Gitleaks and Picket compatibility oracle output.
/// </summary>
internal static class CaptureCompatibilityOracleApp
{
    /// <summary>
    /// Runs the compatibility oracle capture app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            [
                "Mode",
                "Source",
                "Config",
                "BaselinePath",
                "ReportTemplate",
                "OutputDirectory",
                "GitleaksPath",
                "PicketPath",
                "StdinPath",
                "WorkingDirectory",
                "LogOptions",
                "Platform",
            ],
            ["ReportFormat", "AdditionalArguments"],
            [
                "Staged",
                "PreCommit",
                "FollowSymlinks",
                "FailOnFindings",
                "FailOnDifference",
                "AllowMissingClone",
            ]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string mode = ScriptSupport.GetString(values, "Mode", "dir");
        string source = ScriptSupport.GetString(values, "Source", ".");
        string[] reportFormats = ScriptSupport.GetStringArray(values, "ReportFormat", ["json"]);
        string config = ScriptSupport.GetString(values, "Config");
        string baselinePath = ScriptSupport.GetString(values, "BaselinePath");
        string reportTemplate = ScriptSupport.GetString(values, "ReportTemplate");
        string outputDirectory = ScriptSupport.GetString(values, "OutputDirectory", Path.Combine(repositoryRoot, "artifacts", "oracles", "compatibility"));
        string gitleaksPath = ScriptSupport.GetString(values, "GitleaksPath");
        string picketPath = ScriptSupport.GetString(values, "PicketPath");
        string stdinPath = ScriptSupport.GetString(values, "StdinPath");
        string workingDirectory = ScriptSupport.GetString(values, "WorkingDirectory");
        string logOptions = ScriptSupport.GetString(values, "LogOptions");
        string platform = ScriptSupport.GetString(values, "Platform");
        string[] additionalArguments = ScriptSupport.GetStringArray(values, "AdditionalArguments", splitCommas: false);
        bool staged = ScriptSupport.GetSwitch(switches, "Staged");
        bool preCommit = ScriptSupport.GetSwitch(switches, "PreCommit");
        bool followSymlinks = ScriptSupport.GetSwitch(switches, "FollowSymlinks");
        bool failOnFindings = ScriptSupport.GetSwitch(switches, "FailOnFindings");
        bool failOnDifference = ScriptSupport.GetSwitch(switches, "FailOnDifference");
        bool allowMissingClone = ScriptSupport.GetSwitch(switches, "AllowMissingClone");

        ScriptSupport.RequireValueInSet("Mode", mode, ["dir", "git", "stdin"]);
        ScriptSupport.RequireValuesInSet("ReportFormat", reportFormats, ["json", "csv", "junit", "sarif", "template"]);
        if (mode.Equals("stdin", StringComparison.Ordinal))
        {
            if (string.IsNullOrWhiteSpace(stdinPath))
            {
                throw new ArgumentException("Mode 'stdin' requires -StdinPath so oracle input is reproducible.");
            }
        }
        else if (string.IsNullOrWhiteSpace(source))
        {
            source = ".";
        }

        if (reportFormats.Contains("template", StringComparer.Ordinal) && string.IsNullOrWhiteSpace(reportTemplate))
        {
            throw new ArgumentException("Report format 'template' requires -ReportTemplate.");
        }

        Directory.CreateDirectory(outputDirectory);
        string resolvedOutputDirectory = Path.GetFullPath(outputDirectory);
        string gitleaksOutputDirectory = Path.Combine(resolvedOutputDirectory, "gitleaks");
        string picketOutputDirectory = Path.Combine(resolvedOutputDirectory, "picket");
        Directory.CreateDirectory(gitleaksOutputDirectory);
        Directory.CreateDirectory(picketOutputDirectory);
        string resolvedWorkingDirectory = ScriptSupport.ResolveWorkingDirectory(workingDirectory);

        RunGitleaksCapture(
            repositoryRoot,
            mode,
            source,
            reportFormats,
            config,
            baselinePath,
            reportTemplate,
            gitleaksOutputDirectory,
            gitleaksPath,
            stdinPath,
            resolvedWorkingDirectory,
            logOptions,
            platform,
            additionalArguments,
            staged,
            preCommit,
            followSymlinks,
            failOnFindings,
            allowMissingClone);

        string picketExecutable = ResolvePicketExecutable(repositoryRoot, picketPath);
        string resolvedSource = string.Empty;
        string resolvedStdinPath = string.Empty;
        if (mode.Equals("stdin", StringComparison.Ordinal))
        {
            resolvedStdinPath = ScriptSupport.ResolveExistingPath(stdinPath, "stdin fixture", resolvedWorkingDirectory);
        }
        else
        {
            resolvedSource = ScriptSupport.ResolveExistingPath(source, "source", resolvedWorkingDirectory);
        }

        string resolvedConfig = ScriptSupport.ResolveExistingPath(config, "config", resolvedWorkingDirectory);
        string resolvedBaselinePath = ScriptSupport.ResolveExistingPath(baselinePath, "baseline", resolvedWorkingDirectory);
        string resolvedReportTemplate = ScriptSupport.ResolveExistingPath(reportTemplate, "report template", resolvedWorkingDirectory);
        var picketResults = new JsonArray();

        foreach (string format in reportFormats.Distinct(StringComparer.Ordinal))
        {
            string extension = GetReportExtension(format);
            string baseName = $"picket-{mode}.{extension}";
            string reportPath = Path.Combine(picketOutputDirectory, baseName);
            string stdoutPath = Path.Combine(picketOutputDirectory, $"{baseName}.stdout.txt");
            string stderrPath = Path.Combine(picketOutputDirectory, $"{baseName}.stderr.txt");
            List<string> processArguments = NewPicketArguments(
                mode,
                format,
                reportPath,
                source,
                config,
                baselinePath,
                reportTemplate,
                logOptions,
                platform,
                additionalArguments,
                staged,
                preCommit,
                followSymlinks);
            (int exitCode, string stdout, string stderr) = ScriptSupport.RunProcess(
                picketExecutable,
                processArguments,
                resolvedWorkingDirectory,
                resolvedStdinPath);

            ScriptSupport.WriteTextFile(stdoutPath, stdout);
            ScriptSupport.WriteTextFile(stderrPath, stderr);
            if (exitCode > 1 || (failOnFindings && exitCode != 0))
            {
                throw new InvalidOperationException($"Picket exited with code {exitCode} for format '{format}'. See '{stderrPath}'.");
            }

            ScriptSupport.AddNode(picketResults, new JsonObject
            {
                ["Format"] = format,
                ["ExitCode"] = exitCode,
                ["Arguments"] = ScriptSupport.ToJsonArray(processArguments),
                ["ReportPath"] = reportPath,
                ["StdoutPath"] = stdoutPath,
                ["StderrPath"] = stderrPath,
            });
        }

        string gitleaksMetadataPath = Path.Combine(gitleaksOutputDirectory, "metadata.json");
        JsonObject gitleaksMetadata = ScriptSupport.ReadJsonObject(gitleaksMetadataPath);
        var comparisons = new JsonArray();
        foreach (JsonNode? picketResult in picketResults)
        {
            string format = ScriptSupport.GetString(picketResult, "Format");
            string extension = GetReportExtension(format);
            JsonObject gitleaksResult = FindResultByFormat(gitleaksMetadata, format);
            string gitleaksReportPath = Path.Combine(gitleaksOutputDirectory, $"gitleaks-{mode}.{extension}");
            string gitleaksStdoutPath = Path.Combine(gitleaksOutputDirectory, $"gitleaks-{mode}.{extension}.stdout.txt");
            string gitleaksStderrPath = Path.Combine(gitleaksOutputDirectory, $"gitleaks-{mode}.{extension}.stderr.txt");
            string picketReportPath = ScriptSupport.GetString(picketResult, "ReportPath");
            string picketStdoutPath = ScriptSupport.GetString(picketResult, "StdoutPath");
            string picketStderrPath = ScriptSupport.GetString(picketResult, "StderrPath");

            ScriptSupport.AddNode(comparisons, new JsonObject
            {
                ["Format"] = format,
                ["ExitCodeEqual"] = ScriptSupport.GetInt(gitleaksResult, "ExitCode") == ScriptSupport.GetInt(picketResult, "ExitCode"),
                ["ReportBytesEqual"] = ScriptSupport.FileBytesEqual(gitleaksReportPath, picketReportPath),
                ["StdoutBytesEqual"] = ScriptSupport.FileBytesEqual(gitleaksStdoutPath, picketStdoutPath),
                ["StderrBytesEqual"] = ScriptSupport.FileBytesEqual(gitleaksStderrPath, picketStderrPath),
                ["GitleaksExitCode"] = ScriptSupport.GetInt(gitleaksResult, "ExitCode"),
                ["PicketExitCode"] = ScriptSupport.GetInt(picketResult, "ExitCode"),
                ["GitleaksReportPath"] = gitleaksReportPath,
                ["PicketReportPath"] = picketReportPath,
                ["GitleaksReportSha256"] = ScriptSupport.GetFileSha256(gitleaksReportPath),
                ["PicketReportSha256"] = ScriptSupport.GetFileSha256(picketReportPath),
                ["GitleaksStdoutPath"] = gitleaksStdoutPath,
                ["PicketStdoutPath"] = picketStdoutPath,
                ["GitleaksStderrPath"] = gitleaksStderrPath,
                ["PicketStderrPath"] = picketStderrPath,
            });
        }

        string comparisonPath = Path.Combine(resolvedOutputDirectory, "comparison.json");
        var metadata = new JsonObject
        {
            ["Tool"] = "picket-compatibility-oracle",
            ["Mode"] = mode,
            ["WorkingDirectory"] = resolvedWorkingDirectory,
            ["Source"] = resolvedSource,
            ["StdinPath"] = resolvedStdinPath,
            ["Config"] = resolvedConfig,
            ["BaselinePath"] = resolvedBaselinePath,
            ["ReportTemplate"] = resolvedReportTemplate,
            ["GitleaksMetadataPath"] = gitleaksMetadataPath,
            ["PicketBinary"] = picketExecutable,
            ["PicketResults"] = picketResults,
            ["CapturedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["Comparisons"] = comparisons,
        };
        ScriptSupport.WriteJsonFile(comparisonPath, metadata);

        if (failOnDifference)
        {
            foreach (JsonNode? comparison in comparisons)
            {
                bool exitCodeEqual = comparison?["ExitCodeEqual"]?.GetValue<bool>() ?? false;
                bool reportBytesEqual = comparison?["ReportBytesEqual"]?.GetValue<bool>() ?? false;
                if (!exitCodeEqual || !reportBytesEqual)
                {
                    throw new InvalidOperationException($"Compatibility oracle differs for format '{ScriptSupport.GetString(comparison, "Format")}'. See '{comparisonPath}'.");
                }
            }
        }

        Console.Out.WriteLine($"Captured compatibility oracle bundle in '{resolvedOutputDirectory}'.");
        return 0;
    }

    /// <summary>
    /// Invokes the Gitleaks oracle capture file-based app.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="mode">The scan mode.</param>
    /// <param name="source">The source argument.</param>
    /// <param name="reportFormats">The report formats to capture.</param>
    /// <param name="config">The config path argument.</param>
    /// <param name="baselinePath">The baseline path argument.</param>
    /// <param name="reportTemplate">The report template argument.</param>
    /// <param name="outputDirectory">The Gitleaks output directory.</param>
    /// <param name="gitleaksPath">The optional Gitleaks executable path.</param>
    /// <param name="stdinPath">The stdin fixture path.</param>
    /// <param name="workingDirectory">The resolved working directory.</param>
    /// <param name="logOptions">The git log options.</param>
    /// <param name="platform">The git platform value.</param>
    /// <param name="additionalArguments">Additional arguments appended verbatim.</param>
    /// <param name="staged">Whether staged mode is enabled.</param>
    /// <param name="preCommit">Whether pre-commit mode is enabled.</param>
    /// <param name="followSymlinks">Whether directory scans follow symlinks.</param>
    /// <param name="failOnFindings">Whether findings should fail capture.</param>
    /// <param name="allowMissingClone">Whether missing upstream clone metadata should be represented instead of failing.</param>
    private static void RunGitleaksCapture(
        string repositoryRoot,
        string mode,
        string source,
        string[] reportFormats,
        string config,
        string baselinePath,
        string reportTemplate,
        string outputDirectory,
        string gitleaksPath,
        string stdinPath,
        string workingDirectory,
        string logOptions,
        string platform,
        string[] additionalArguments,
        bool staged,
        bool preCommit,
        bool followSymlinks,
        bool failOnFindings,
        bool allowMissingClone)
    {
        string captureApp = Path.Combine(repositoryRoot, "scripts", "Capture-GitleaksOracle.cs");
        (int buildExitCode, string buildStdout, string buildStderr) = ScriptSupport.RunProcess(
            "dotnet",
            ["build", captureApp, "--nologo", "--verbosity", "quiet"],
            repositoryRoot);
        if (!string.IsNullOrWhiteSpace(buildStdout))
        {
            Console.Out.Write(buildStdout);
        }

        if (!string.IsNullOrWhiteSpace(buildStderr))
        {
            Console.Error.Write(buildStderr);
        }

        if (buildExitCode != 0)
        {
            throw new InvalidOperationException($"Gitleaks oracle capture app build failed with exit code {buildExitCode}.");
        }

        var arguments = new List<string>
        {
            "run",
            "--file",
            captureApp,
            "--no-build",
            "--",
            "-Mode",
            mode,
            "-OutputDirectory",
            outputDirectory,
            "-ReportFormat",
            string.Join(',', reportFormats),
        };

        if (mode.Equals("stdin", StringComparison.Ordinal))
        {
            arguments.Add("-StdinPath");
            arguments.Add(stdinPath);
        }
        else
        {
            arguments.Add("-Source");
            arguments.Add(source);
        }

        AddOptionalParameter(arguments, "Config", config);
        AddOptionalParameter(arguments, "BaselinePath", baselinePath);
        AddOptionalParameter(arguments, "ReportTemplate", reportTemplate);
        AddOptionalParameter(arguments, "GitleaksPath", gitleaksPath);
        AddOptionalParameter(arguments, "WorkingDirectory", workingDirectory);
        AddOptionalParameter(arguments, "LogOptions", logOptions);
        AddOptionalParameter(arguments, "Platform", platform);
        AddOptionalArrayParameter(arguments, "AdditionalArguments", additionalArguments);
        AddOptionalSwitch(arguments, "Staged", staged);
        AddOptionalSwitch(arguments, "PreCommit", preCommit);
        AddOptionalSwitch(arguments, "FollowSymlinks", followSymlinks);
        AddOptionalSwitch(arguments, "FailOnFindings", failOnFindings);
        AddOptionalSwitch(arguments, "AllowMissingClone", allowMissingClone);

        (int exitCode, string stdout, string stderr) = ScriptSupport.RunProcess("dotnet", arguments, repositoryRoot);
        if (!string.IsNullOrWhiteSpace(stdout))
        {
            Console.Out.Write(stdout);
        }

        if (!string.IsNullOrWhiteSpace(stderr))
        {
            Console.Error.Write(stderr);
        }

        if (exitCode != 0)
        {
            throw new InvalidOperationException($"Gitleaks oracle capture failed with exit code {exitCode}.");
        }
    }

    /// <summary>
    /// Resolves the Picket executable used for compatibility capture.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="picketPath">The optional explicit executable path.</param>
    /// <returns>The resolved executable path.</returns>
    private static string ResolvePicketExecutable(string repositoryRoot, string picketPath)
    {
        if (!string.IsNullOrWhiteSpace(picketPath))
        {
            return ScriptSupport.ResolveCommandPath(picketPath, "Picket executable");
        }

        string? configuredPath = Environment.GetEnvironmentVariable("PICKET_BIN");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return ScriptSupport.ResolveCommandPath(configuredPath, "Picket executable from PICKET_BIN");
        }

        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string runtimeIdentifier = RuntimeInformation.RuntimeIdentifier;
        string[] candidatePaths =
        [
            Path.Combine(repositoryRoot, "src", "Picket.Cli", "bin", "Release", "net10.0", runtimeIdentifier, executableName),
            Path.Combine(repositoryRoot, "src", "Picket.Cli", "bin", "Debug", "net10.0", runtimeIdentifier, executableName),
        ];

        foreach (string candidatePath in candidatePaths)
        {
            if (File.Exists(candidatePath))
            {
                return Path.GetFullPath(candidatePath);
            }
        }

        throw new FileNotFoundException("Could not find built Picket executable. Run dotnet build -c Release, set PICKET_BIN, or pass -PicketPath.");
    }

    /// <summary>
    /// Gets the file extension for a report format.
    /// </summary>
    /// <param name="format">The report format.</param>
    /// <returns>The report file extension.</returns>
    private static string GetReportExtension(string format)
    {
        return format.Equals("template", StringComparison.Ordinal) ? "txt" : format;
    }

    /// <summary>
    /// Finds the captured Gitleaks result for a report format.
    /// </summary>
    /// <param name="metadata">The Gitleaks metadata object.</param>
    /// <param name="format">The report format.</param>
    /// <returns>The matching result object.</returns>
    private static JsonObject FindResultByFormat(JsonObject metadata, string format)
    {
        foreach (JsonNode? result in ScriptSupport.GetArray(metadata, "Results"))
        {
            if (ScriptSupport.GetString(result, "Format").Equals(format, StringComparison.Ordinal))
            {
                return result as JsonObject ?? throw new InvalidDataException($"Gitleaks result for '{format}' is not an object.");
            }
        }

        throw new InvalidDataException($"Gitleaks metadata does not contain result for format '{format}'.");
    }

    /// <summary>
    /// Creates Picket command arguments for one compatibility report capture.
    /// </summary>
    /// <param name="mode">The Picket compatibility mode.</param>
    /// <param name="format">The report format.</param>
    /// <param name="reportPath">The report output path.</param>
    /// <param name="source">The source argument.</param>
    /// <param name="config">The config path argument.</param>
    /// <param name="baselinePath">The baseline path argument.</param>
    /// <param name="reportTemplate">The report template argument.</param>
    /// <param name="logOptions">The git log options.</param>
    /// <param name="platform">The git platform value.</param>
    /// <param name="additionalArguments">Additional arguments appended verbatim.</param>
    /// <param name="staged">Whether staged mode is enabled.</param>
    /// <param name="preCommit">Whether pre-commit mode is enabled.</param>
    /// <param name="followSymlinks">Whether directory scans follow symlinks.</param>
    /// <returns>The Picket command arguments.</returns>
    private static List<string> NewPicketArguments(
        string mode,
        string format,
        string reportPath,
        string source,
        string config,
        string baselinePath,
        string reportTemplate,
        string logOptions,
        string platform,
        string[] additionalArguments,
        bool staged,
        bool preCommit,
        bool followSymlinks)
    {
        var arguments = new List<string>
        {
            mode,
        };

        switch (mode)
        {
            case "dir":
                arguments.Add(source);
                if (followSymlinks)
                {
                    arguments.Add("--follow-symlinks");
                }

                break;
            case "git":
                arguments.Add(source);
                if (!string.IsNullOrWhiteSpace(logOptions))
                {
                    arguments.Add("--log-opts");
                    arguments.Add(logOptions);
                }

                if (!string.IsNullOrWhiteSpace(platform))
                {
                    arguments.Add("--platform");
                    arguments.Add(platform);
                }

                if (staged)
                {
                    arguments.Add("--staged");
                }

                if (preCommit)
                {
                    arguments.Add("--pre-commit");
                }

                break;
        }

        if (!string.IsNullOrWhiteSpace(config))
        {
            arguments.Add("--config");
            arguments.Add(config);
        }

        if (!string.IsNullOrWhiteSpace(baselinePath))
        {
            arguments.Add("--baseline-path");
            arguments.Add(baselinePath);
        }

        arguments.Add("--report-format");
        arguments.Add(format);
        arguments.Add("--report-path");
        arguments.Add(reportPath);
        arguments.Add("--no-banner");
        arguments.Add("--no-color");

        if (!string.IsNullOrWhiteSpace(reportTemplate))
        {
            arguments.Add("--report-template");
            arguments.Add(reportTemplate);
        }

        arguments.AddRange(additionalArguments);
        return arguments;
    }

    /// <summary>
    /// Adds a string option when it has a value.
    /// </summary>
    /// <param name="arguments">The argument list.</param>
    /// <param name="name">The option name.</param>
    /// <param name="value">The option value.</param>
    private static void AddOptionalParameter(List<string> arguments, string name, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        arguments.Add(string.Concat("-", name));
        arguments.Add(value);
    }

    /// <summary>
    /// Adds an array option when it has values.
    /// </summary>
    /// <param name="arguments">The argument list.</param>
    /// <param name="name">The option name.</param>
    /// <param name="values">The option values.</param>
    private static void AddOptionalArrayParameter(List<string> arguments, string name, string[] values)
    {
        if (values.Length == 0)
        {
            return;
        }

        arguments.Add(string.Concat("-", name));
        arguments.AddRange(values);
    }

    /// <summary>
    /// Adds a switch option when it is enabled.
    /// </summary>
    /// <param name="arguments">The argument list.</param>
    /// <param name="name">The option name.</param>
    /// <param name="enabled">Whether the switch is enabled.</param>
    private static void AddOptionalSwitch(List<string> arguments, string name, bool enabled)
    {
        if (enabled)
        {
            arguments.Add(string.Concat("-", name));
        }
    }
}
