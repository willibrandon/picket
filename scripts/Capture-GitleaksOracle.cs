#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text.Json.Nodes;

try
{
    return CaptureGitleaksOracleApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Captures pinned Gitleaks oracle reports and metadata.
/// </summary>
internal static class CaptureGitleaksOracleApp
{
    /// <summary>
    /// Runs the Gitleaks oracle capture app.
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
                "StdinPath",
                "WorkingDirectory",
                "LogOptions",
                "Platform",
            ],
            ["ReportFormat", "AdditionalArguments"],
            ["Staged", "PreCommit", "FollowSymlinks", "FailOnFindings", "AllowMissingClone"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string mode = ScriptSupport.GetString(values, "Mode", "dir");
        string source = ScriptSupport.GetString(values, "Source", ".");
        string[] reportFormats = ScriptSupport.GetStringArray(values, "ReportFormat", ["json"]);
        string config = ScriptSupport.GetString(values, "Config");
        string baselinePath = ScriptSupport.GetString(values, "BaselinePath");
        string reportTemplate = ScriptSupport.GetString(values, "ReportTemplate");
        string outputDirectory = ScriptSupport.GetString(values, "OutputDirectory", Path.Combine(repositoryRoot, "artifacts", "oracles", "gitleaks"));
        string gitleaksPath = ScriptSupport.GetString(values, "GitleaksPath");
        string stdinPath = ScriptSupport.GetString(values, "StdinPath");
        string workingDirectory = ScriptSupport.GetString(values, "WorkingDirectory");
        string logOptions = ScriptSupport.GetString(values, "LogOptions");
        string platform = ScriptSupport.GetString(values, "Platform");
        string[] additionalArguments = ScriptSupport.GetStringArray(values, "AdditionalArguments", splitCommas: false);
        bool staged = ScriptSupport.GetSwitch(switches, "Staged");
        bool preCommit = ScriptSupport.GetSwitch(switches, "PreCommit");
        bool followSymlinks = ScriptSupport.GetSwitch(switches, "FollowSymlinks");
        bool failOnFindings = ScriptSupport.GetSwitch(switches, "FailOnFindings");
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

        string gitleaksExecutable = ResolveGitleaksExecutable(gitleaksPath);
        JsonObject gitleaksClone = GetGitleaksCloneMetadata(repositoryRoot, allowMissingClone);
        string gitleaksVersion = GetGitleaksVersion(gitleaksExecutable);
        string resolvedWorkingDirectory = ScriptSupport.ResolveWorkingDirectory(workingDirectory);
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
        Directory.CreateDirectory(outputDirectory);
        string resolvedOutputDirectory = Path.GetFullPath(outputDirectory);
        var results = new JsonArray();

        foreach (string format in reportFormats.Distinct(StringComparer.Ordinal))
        {
            string extension = GetReportExtension(format);
            string baseName = $"gitleaks-{mode}.{extension}";
            string reportPath = Path.Combine(resolvedOutputDirectory, baseName);
            string stdoutPath = Path.Combine(resolvedOutputDirectory, $"{baseName}.stdout.txt");
            string stderrPath = Path.Combine(resolvedOutputDirectory, $"{baseName}.stderr.txt");
            List<string> processArguments = NewGitleaksArguments(
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
                gitleaksExecutable,
                processArguments,
                resolvedWorkingDirectory,
                resolvedStdinPath);

            ScriptSupport.WriteTextFile(stdoutPath, stdout);
            ScriptSupport.WriteTextFile(stderrPath, stderr);
            if (exitCode > 1 || (failOnFindings && exitCode != 0))
            {
                throw new InvalidOperationException($"Gitleaks exited with code {exitCode} for format '{format}'. See '{stderrPath}'.");
            }

            ScriptSupport.AddNode(results, new JsonObject
            {
                ["Format"] = format,
                ["ExitCode"] = exitCode,
                ["Arguments"] = ScriptSupport.ToJsonArray(processArguments),
                ["ReportPath"] = reportPath,
                ["StdoutPath"] = stdoutPath,
                ["StderrPath"] = stderrPath,
            });
        }

        string metadataPath = Path.Combine(resolvedOutputDirectory, "metadata.json");
        var metadata = new JsonObject
        {
            ["Tool"] = "gitleaks",
            ["ToolVersion"] = gitleaksVersion,
            ["Binary"] = gitleaksExecutable,
            ["Clone"] = gitleaksClone,
            ["Mode"] = mode,
            ["WorkingDirectory"] = resolvedWorkingDirectory,
            ["Source"] = resolvedSource,
            ["StdinPath"] = resolvedStdinPath,
            ["Config"] = resolvedConfig,
            ["BaselinePath"] = resolvedBaselinePath,
            ["ReportTemplate"] = resolvedReportTemplate,
            ["AdditionalArguments"] = ScriptSupport.ToJsonArray(additionalArguments),
            ["CapturedUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["Results"] = results,
        };
        ScriptSupport.WriteJsonFile(metadataPath, metadata);
        Console.Out.WriteLine($"Captured Gitleaks oracle reports in '{resolvedOutputDirectory}'.");
        return 0;
    }

    /// <summary>
    /// Resolves the Gitleaks executable.
    /// </summary>
    /// <param name="gitleaksPath">The optional explicit executable path.</param>
    /// <returns>The resolved executable path.</returns>
    private static string ResolveGitleaksExecutable(string gitleaksPath)
    {
        if (!string.IsNullOrWhiteSpace(gitleaksPath))
        {
            return ScriptSupport.ResolveCommandPath(gitleaksPath, "Gitleaks executable");
        }

        string? configuredPath = Environment.GetEnvironmentVariable("PICKET_GITLEAKS_BIN");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return ScriptSupport.ResolveCommandPath(configuredPath, "Gitleaks executable from PICKET_GITLEAKS_BIN");
        }

        return ScriptSupport.ResolveCommandPath("gitleaks", "Gitleaks executable");
    }

    /// <summary>
    /// Captures Gitleaks clone metadata.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="allowMissingClone">Whether missing clone metadata should be represented instead of failing.</param>
    /// <returns>The clone metadata object.</returns>
    private static JsonObject GetGitleaksCloneMetadata(string repositoryRoot, bool allowMissingClone)
    {
        string clonePath = ScriptSupport.ResolveReferencePath(repositoryRoot, "PICKET_GITLEAKS_REPO", "gitleaks");
        if (!Directory.Exists(clonePath))
        {
            if (allowMissingClone)
            {
                return new JsonObject
                {
                    ["Path"] = clonePath,
                    ["Version"] = "missing",
                    ["Commit"] = "missing",
                    ["Remote"] = "missing",
                };
            }

            throw new DirectoryNotFoundException(
                $"Gitleaks clone was not found at '{clonePath}'. Set PICKET_GITLEAKS_REPO or clone it as sibling 'gitleaks'.");
        }

        return new JsonObject
        {
            ["Path"] = Path.GetFullPath(clonePath),
            ["Version"] = ScriptSupport.RunGit(clonePath, "describe", "--tags", "--always", "--dirty"),
            ["Commit"] = ScriptSupport.RunGit(clonePath, "rev-parse", "HEAD"),
            ["Remote"] = ScriptSupport.RunGit(clonePath, "remote", "get-url", "origin"),
        };
    }

    /// <summary>
    /// Reads the Gitleaks executable version string.
    /// </summary>
    /// <param name="executablePath">The resolved executable path.</param>
    /// <returns>The version string, or <c>unknown</c> when the command fails.</returns>
    private static string GetGitleaksVersion(string executablePath)
    {
        (int exitCode, string stdout, _) = ScriptSupport.RunProcess(executablePath, ["version"], Directory.GetCurrentDirectory());
        return exitCode == 0 ? stdout.Trim() : "unknown";
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
    /// Creates Gitleaks command arguments for one report capture.
    /// </summary>
    /// <param name="mode">The Gitleaks mode.</param>
    /// <param name="format">The report format.</param>
    /// <param name="reportPath">The report output path.</param>
    /// <param name="source">The source argument.</param>
    /// <param name="config">The config path argument.</param>
    /// <param name="baselinePath">The baseline path argument.</param>
    /// <param name="reportTemplate">The report template path argument.</param>
    /// <param name="logOptions">The git log options.</param>
    /// <param name="platform">The git platform value.</param>
    /// <param name="additionalArguments">Additional arguments appended verbatim.</param>
    /// <param name="staged">Whether staged mode is enabled.</param>
    /// <param name="preCommit">Whether pre-commit mode is enabled.</param>
    /// <param name="followSymlinks">Whether directory scans follow symlinks.</param>
    /// <returns>The Gitleaks command arguments.</returns>
    private static List<string> NewGitleaksArguments(
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
}
