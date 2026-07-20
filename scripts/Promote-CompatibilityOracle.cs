#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

try
{
    return PromoteCompatibilityOracleApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Promotes a reviewed compatibility oracle capture into normalized committed fixtures.
/// </summary>
internal static partial class PromoteCompatibilityOracleApp
{
    /// <summary>
    /// Runs the compatibility oracle promotion app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            ["CaptureDirectory", "Name", "OutputRoot", "RedactionMapPath"],
            [],
            ["AllowUnredacted", "Force"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string captureDirectory = ScriptSupport.GetString(
            values,
            "CaptureDirectory",
            Path.Combine(repositoryRoot, "artifacts", "oracles", "compatibility"));
        string name = ScriptSupport.GetString(values, "Name");
        string outputRoot = ScriptSupport.GetString(values, "OutputRoot", Path.Combine(repositoryRoot, "tests", "fixtures", "oracles"));
        string redactionMapPath = ScriptSupport.GetString(values, "RedactionMapPath");
        bool allowUnredacted = ScriptSupport.GetSwitch(switches, "AllowUnredacted");
        bool force = ScriptSupport.GetSwitch(switches, "Force");

        if (!IsValidFixtureName(name))
        {
            throw new ArgumentException("Name must match ^[A-Za-z0-9][A-Za-z0-9._-]*$.");
        }

        if (string.IsNullOrWhiteSpace(redactionMapPath) && !allowUnredacted)
        {
            throw new ArgumentException("Refusing to promote oracle captures without -RedactionMapPath or -AllowUnredacted. Use -AllowUnredacted only for synthetic no-secret captures.");
        }

        string resolvedCaptureDirectory = ScriptSupport.ResolveExistingDirectory(captureDirectory, "capture directory");
        string comparisonPath = Path.Combine(resolvedCaptureDirectory, "comparison.json");
        if (!File.Exists(comparisonPath))
        {
            throw new FileNotFoundException($"Capture directory '{resolvedCaptureDirectory}' does not contain comparison.json.");
        }

        string resolvedRedactionMapPath = ScriptSupport.ResolveOptionalFile(redactionMapPath, "redaction map");
        List<(string Secret, string Placeholder)> redactions = LoadRedactionMap(resolvedRedactionMapPath);
        JsonObject comparison = ScriptSupport.ReadJsonObject(comparisonPath);
        List<(string Original, string Replacement)> pathReplacements = NewPathReplacements(repositoryRoot, comparison, resolvedCaptureDirectory);

        Directory.CreateDirectory(outputRoot);
        string resolvedOutputRoot = Path.GetFullPath(outputRoot);
        string destination = Path.Combine(resolvedOutputRoot, name);
        if (Directory.Exists(destination) && !force)
        {
            throw new InvalidOperationException($"Destination '{destination}' already exists. Pass -Force to overwrite it.");
        }

        if (Directory.Exists(destination))
        {
            Directory.Delete(destination, recursive: true);
        }

        Directory.CreateDirectory(destination);
        JsonArray promotedFiles = PromoteFiles(comparison, destination, redactions, pathReplacements, out JsonArray promotedComparisons);
        JsonObject gitleaksMetadata = ScriptSupport.ReadJsonObject(ScriptSupport.GetString(comparison, "GitleaksMetadataPath"));
        JsonObject? clone = gitleaksMetadata["Clone"] as JsonObject;
        var manifest = new JsonObject
        {
            ["Schema"] = "picket.oracle.v1",
            ["Name"] = name,
            ["Mode"] = ScriptSupport.GetString(comparison, "Mode"),
            ["Formats"] = CreateFormatsArray(ScriptSupport.GetArray(comparison, "Comparisons")),
            ["Upstream"] = new JsonObject
            {
                ["Tool"] = "gitleaks",
                ["Version"] = ScriptSupport.GetString(gitleaksMetadata, "ToolVersion"),
                ["CloneVersion"] = ScriptSupport.GetString(clone, "Version"),
                ["Commit"] = ScriptSupport.GetString(clone, "Commit"),
                ["Remote"] = ScriptSupport.GetString(clone, "Remote"),
            },
            ["Redaction"] = new JsonObject
            {
                ["MapRequired"] = !allowUnredacted,
                ["EntryCount"] = redactions.Count,
            },
            ["Files"] = promotedFiles,
            ["Comparisons"] = promotedComparisons,
        };

        string manifestPath = Path.Combine(destination, "manifest.json");
        ScriptSupport.WriteJsonFile(manifestPath, manifest);
        AssertNoUnsafePromotedContent(destination, redactions, pathReplacements);
        Console.Out.WriteLine($"Promoted normalized compatibility oracle '{name}' to '{destination}'.");
        return 0;
    }

    /// <summary>
    /// Validates a fixture directory name.
    /// </summary>
    /// <param name="name">The requested fixture name.</param>
    /// <returns><see langword="true"/> when the name is portable and safe.</returns>
    private static bool IsValidFixtureName(string name)
    {
        return FixtureNamePattern().IsMatch(name);
    }

    /// <summary>
    /// Loads the redaction map sorted by secret length.
    /// </summary>
    /// <param name="path">The optional redaction map path.</param>
    /// <returns>The sorted redaction entries.</returns>
    private static List<(string Secret, string Placeholder)> LoadRedactionMap(string path)
    {
        var entries = new List<(string Secret, string Placeholder)>();
        if (string.IsNullOrWhiteSpace(path))
        {
            return entries;
        }

        JsonObject redactionMap = ScriptSupport.ReadJsonObject(path);
        foreach ((string secret, JsonNode? placeholderNode) in redactionMap)
        {
            string placeholder = placeholderNode?.GetValue<string>() ?? string.Empty;
            if (string.IsNullOrEmpty(secret))
            {
                throw new InvalidDataException($"Redaction map '{path}' contains an empty secret key.");
            }

            if (string.IsNullOrWhiteSpace(placeholder))
            {
                throw new InvalidDataException($"Redaction map '{path}' contains an empty placeholder for '{secret}'.");
            }

            entries.Add((secret, placeholder));
        }

        entries.Sort(static (left, right) => right.Secret.Length.CompareTo(left.Secret.Length));
        return entries;
    }

    /// <summary>
    /// Creates path replacement entries for local-machine-specific capture paths.
    /// </summary>
    /// <param name="repositoryRoot">The repository root path.</param>
    /// <param name="comparison">The compatibility comparison metadata.</param>
    /// <param name="resolvedCaptureDirectory">The resolved capture directory.</param>
    /// <returns>The sorted replacement entries.</returns>
    private static List<(string Original, string Replacement)> NewPathReplacements(
        string repositoryRoot,
        JsonObject comparison,
        string resolvedCaptureDirectory)
    {
        var replacements = new List<(string Original, string Replacement)>();
        AddPathReplacement(replacements, repositoryRoot, "<repo>");
        AddPathReplacement(replacements, resolvedCaptureDirectory, "<capture>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "WorkingDirectory"), "<working-directory>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "Source"), "<source>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "StdinPath"), "<stdin>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "Config"), "<config>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "BaselinePath"), "<baseline>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "ReportTemplate"), "<report-template>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "GitleaksMetadataPath"), "<gitleaks-metadata>");
        AddPathReplacement(replacements, ScriptSupport.GetString(comparison, "PicketBinary"), "<picket-binary>");
        replacements.Sort(static (left, right) => right.Original.Length.CompareTo(left.Original.Length));
        return replacements;
    }

    /// <summary>
    /// Adds a path replacement and its normalized slash variant.
    /// </summary>
    /// <param name="replacements">The replacement list to update.</param>
    /// <param name="path">The original path.</param>
    /// <param name="placeholder">The placeholder value.</param>
    private static void AddPathReplacement(List<(string Original, string Replacement)> replacements, string path, string placeholder)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        replacements.Add((path, placeholder));
        string normalized = ScriptSupport.NormalizePathSeparators(path);
        if (!normalized.Equals(path, StringComparison.Ordinal))
        {
            replacements.Add((normalized, placeholder));
        }
    }

    /// <summary>
    /// Promotes every comparison file into the destination fixture directory.
    /// </summary>
    /// <param name="comparison">The compatibility comparison metadata.</param>
    /// <param name="destination">The destination fixture directory.</param>
    /// <param name="redactions">The redaction entries.</param>
    /// <param name="pathReplacements">The path replacement entries.</param>
    /// <param name="promotedComparisons">The promoted comparison manifest entries.</param>
    /// <returns>The promoted file manifest entries.</returns>
    private static JsonArray PromoteFiles(
        JsonObject comparison,
        string destination,
        List<(string Secret, string Placeholder)> redactions,
        List<(string Original, string Replacement)> pathReplacements,
        out JsonArray promotedComparisons)
    {
        var promotedFiles = new JsonArray();
        promotedComparisons = [];
        foreach (JsonNode? captureComparison in ScriptSupport.GetArray(comparison, "Comparisons"))
        {
            string format = ScriptSupport.GetString(captureComparison, "Format");
            (string Kind, string SourcePath, string FileName)[] targets =
            [
                ("gitleaks-report", ScriptSupport.GetString(captureComparison, "GitleaksReportPath"), $"gitleaks.{format}"),
                ("picket-report", ScriptSupport.GetString(captureComparison, "PicketReportPath"), $"picket.{format}"),
                ("gitleaks-stdout", ScriptSupport.GetString(captureComparison, "GitleaksStdoutPath"), $"gitleaks.{format}.stdout.txt"),
                ("picket-stdout", ScriptSupport.GetString(captureComparison, "PicketStdoutPath"), $"picket.{format}.stdout.txt"),
                ("gitleaks-stderr", ScriptSupport.GetString(captureComparison, "GitleaksStderrPath"), $"gitleaks.{format}.stderr.txt"),
                ("picket-stderr", ScriptSupport.GetString(captureComparison, "PicketStderrPath"), $"picket.{format}.stderr.txt"),
            ];

            foreach ((string kind, string sourcePath, string fileName) in targets)
            {
                string destinationPath = Path.Combine(destination, fileName);
                WriteNormalizedFile(sourcePath, destinationPath, redactions, pathReplacements);
                ScriptSupport.AddNode(promotedFiles, new JsonObject
                {
                    ["Kind"] = kind,
                    ["Format"] = format,
                    ["Path"] = NewRelativePath(destination, destinationPath),
                    ["Sha256"] = ScriptSupport.GetFileSha256(destinationPath),
                });
            }

            ScriptSupport.AddNode(promotedComparisons, new JsonObject
            {
                ["Format"] = format,
                ["ExitCodeEqual"] = captureComparison?["ExitCodeEqual"]?.GetValue<bool>() ?? false,
                ["ReportBytesEqual"] = captureComparison?["ReportBytesEqual"]?.GetValue<bool>() ?? false,
                ["StdoutBytesEqual"] = captureComparison?["StdoutBytesEqual"]?.GetValue<bool>() ?? false,
                ["StderrBytesEqual"] = captureComparison?["StderrBytesEqual"]?.GetValue<bool>() ?? false,
                ["GitleaksExitCode"] = ScriptSupport.GetInt(captureComparison, "GitleaksExitCode"),
                ["PicketExitCode"] = ScriptSupport.GetInt(captureComparison, "PicketExitCode"),
            });
        }

        return promotedFiles;
    }

    /// <summary>
    /// Normalizes volatile capture content.
    /// </summary>
    /// <param name="content">The source content.</param>
    /// <param name="redactions">The redaction entries.</param>
    /// <param name="pathReplacements">The path replacement entries.</param>
    /// <returns>The normalized content.</returns>
    private static string NormalizeContent(
        string content,
        List<(string Secret, string Placeholder)> redactions,
        List<(string Original, string Replacement)> pathReplacements)
    {
        string normalized = content.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\r", "\n", StringComparison.Ordinal);
        normalized = ClockPrefixPattern().Replace(normalized, "<time> ");
        normalized = ScanDurationPattern().Replace(normalized, "$1<duration>");

        foreach ((string original, string replacement) in pathReplacements)
        {
            if (!string.IsNullOrEmpty(original))
            {
                normalized = normalized.Replace(original, replacement, StringComparison.Ordinal);
            }
        }

        foreach ((string secret, string placeholder) in redactions)
        {
            normalized = normalized.Replace(secret, placeholder, StringComparison.Ordinal);
        }

        return normalized;
    }

    /// <summary>
    /// Writes one normalized capture file into the fixture destination.
    /// </summary>
    /// <param name="sourcePath">The source capture file path.</param>
    /// <param name="destinationPath">The normalized destination file path.</param>
    /// <param name="redactions">The redaction entries.</param>
    /// <param name="pathReplacements">The path replacement entries.</param>
    private static void WriteNormalizedFile(
        string sourcePath,
        string destinationPath,
        List<(string Secret, string Placeholder)> redactions,
        List<(string Original, string Replacement)> pathReplacements)
    {
        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException($"Expected capture file '{sourcePath}' does not exist.");
        }

        string normalized = NormalizeContent(ScriptSupport.ReadTextFile(sourcePath), redactions, pathReplacements);
        ScriptSupport.WriteTextFile(destinationPath, normalized);
    }

    /// <summary>
    /// Validates that promoted files do not contain unsafe local paths or redaction keys.
    /// </summary>
    /// <param name="directoryPath">The promoted fixture directory.</param>
    /// <param name="redactions">The redaction entries.</param>
    /// <param name="pathReplacements">The path replacement entries.</param>
    private static void AssertNoUnsafePromotedContent(
        string directoryPath,
        List<(string Secret, string Placeholder)> redactions,
        List<(string Original, string Replacement)> pathReplacements)
    {
        foreach (string file in Directory.EnumerateFiles(directoryPath, "*", SearchOption.AllDirectories))
        {
            string content = ScriptSupport.ReadTextFile(file);
            if (WindowsAbsolutePathPattern().IsMatch(content))
            {
                throw new InvalidDataException($"Promoted file '{file}' still contains a Windows absolute path.");
            }

            foreach ((string original, _) in pathReplacements)
            {
                if (!string.IsNullOrWhiteSpace(original) && content.Contains(original, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"Promoted file '{file}' still contains '{original}'.");
                }
            }

            foreach ((string secret, _) in redactions)
            {
                if (content.Contains(secret, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"Promoted file '{file}' still contains an unredacted redaction-map key.");
                }
            }
        }
    }

    /// <summary>
    /// Creates a slash-normalized relative path.
    /// </summary>
    /// <param name="basePath">The base directory.</param>
    /// <param name="path">The target path.</param>
    /// <returns>The relative path.</returns>
    private static string NewRelativePath(string basePath, string path)
    {
        return Path.GetRelativePath(Path.GetFullPath(basePath), Path.GetFullPath(path)).Replace('\\', '/');
    }

    /// <summary>
    /// Creates the manifest format array from comparison entries.
    /// </summary>
    /// <param name="comparisons">The comparison entries.</param>
    /// <returns>The manifest format array.</returns>
    private static JsonArray CreateFormatsArray(JsonArray comparisons)
    {
        var formats = new JsonArray();
        foreach (JsonNode? comparison in comparisons)
        {
            ScriptSupport.AddString(formats, ScriptSupport.GetString(comparison, "Format"));
        }

        return formats;
    }

    /// <summary>
    /// Creates the generated fixture-name validation expression.
    /// </summary>
    /// <returns>The generated regular expression.</returns>
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex FixtureNamePattern();

    /// <summary>
    /// Creates the generated Windows absolute-path detection expression.
    /// </summary>
    /// <returns>The generated regular expression.</returns>
    [GeneratedRegex("(^|[\\s`\"'\\[\\{\\(,])([A-Za-z]:[\\\\/])", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsAbsolutePathPattern();

    /// <summary>
    /// Creates the generated clock-prefix normalization expression.
    /// </summary>
    /// <returns>The generated regular expression.</returns>
    [GeneratedRegex("(?m)^\\d{1,2}:\\d{2}(?:AM|PM)\\s+", RegexOptions.CultureInvariant)]
    private static partial Regex ClockPrefixPattern();

    /// <summary>
    /// Creates the generated scan-duration normalization expression.
    /// </summary>
    /// <returns>The generated regular expression.</returns>
    [GeneratedRegex("(?m)( scanned ~[0-9.,]+ [A-Za-z]+ \\([0-9.,]+ [A-Za-z]+\\) in )\\S+", RegexOptions.CultureInvariant)]
    private static partial Regex ScanDurationPattern();
}
