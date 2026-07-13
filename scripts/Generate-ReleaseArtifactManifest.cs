#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

try
{
    return GenerateReleaseArtifactManifestApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException
    or DirectoryNotFoundException
    or FileNotFoundException
    or InvalidDataException
    or IOException
    or OverflowException
    or UnauthorizedAccessException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Generates a deterministic size and hash manifest for final release payload assets.
/// </summary>
internal static partial class GenerateReleaseArtifactManifestApp
{
    /// <summary>
    /// Release artifact manifest schema identifier.
    /// </summary>
    private const string ManifestSchema = "picket.release-artifacts.v1";

    /// <summary>
    /// Release tag expression accepted by the release artifact manifest.
    /// </summary>
    private const string ReleaseTagExpression =
        "^v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$";

    /// <summary>
    /// Runs the release artifact manifest generator.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, _) = ScriptSupport.ParseArguments(
            args,
            ["Directory", "OutputPath", "ReleaseTag"],
            [],
            []);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string directory = ScriptSupport.ResolveExistingPath(
            ScriptSupport.GetString(values, "Directory", Path.Combine(repositoryRoot, "dist")),
            "release artifact directory",
            Directory.GetCurrentDirectory());
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Release artifact directory '{directory}' does not exist.");
        }

        string releaseTag = ScriptSupport.GetString(
            values,
            "ReleaseTag",
            Environment.GetEnvironmentVariable("RELEASE_TAG") ?? string.Empty).Trim();
        if (!ReleaseTagPattern().IsMatch(releaseTag))
        {
            throw new ArgumentException("ReleaseTag must be a vMAJOR.MINOR.PATCH tag with an optional SemVer prerelease suffix.");
        }

        string outputPath = Path.GetFullPath(
            ScriptSupport.GetString(values, "OutputPath", Path.Combine(directory, "release-artifacts.json")),
            Directory.GetCurrentDirectory());
        RequireContainedOutputPath(directory, outputPath);

        StringComparison pathComparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        FileInfo[] assets =
        [
            .. new DirectoryInfo(directory)
                .EnumerateFiles("*", SearchOption.TopDirectoryOnly)
                .Where(file => !file.FullName.Equals(outputPath, pathComparison))
                .Where(file => !file.Name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
                .Where(file => !file.Name.Equals("checksums.txt", StringComparison.OrdinalIgnoreCase))
                .OrderBy(file => file.Name, StringComparer.Ordinal),
        ];
        if (assets.Length == 0)
        {
            throw new InvalidDataException($"Release artifact directory '{directory}' does not contain payload assets.");
        }

        var entries = new JsonArray();
        long totalBytes = 0;
        foreach (FileInfo asset in assets)
        {
            if ((asset.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidDataException($"Release asset '{asset.Name}' must not be a symbolic link or reparse point.");
            }

            totalBytes = checked(totalBytes + asset.Length);
            ScriptSupport.AddNode(entries, new JsonObject
            {
                ["Name"] = asset.Name,
                ["Bytes"] = asset.Length,
                ["Sha256"] = ScriptSupport.GetFileSha256(asset.FullName),
            });
        }

        var manifest = new JsonObject
        {
            ["Schema"] = ManifestSchema,
            ["ReleaseTag"] = releaseTag,
            ["AssetCount"] = assets.Length,
            ["TotalBytes"] = totalBytes,
            ["Assets"] = entries,
        };
        ScriptSupport.WriteJsonFile(outputPath, manifest);

        Console.WriteLine($"release artifact manifest written: {outputPath}");
        Console.WriteLine($"assets: {assets.Length}");
        Console.WriteLine($"bytes: {totalBytes}");
        return 0;
    }

    /// <summary>
    /// Requires the generated manifest path to stay inside the release artifact directory.
    /// </summary>
    /// <param name="directory">The release artifact directory.</param>
    /// <param name="outputPath">The requested output path.</param>
    private static void RequireContainedOutputPath(string directory, string outputPath)
    {
        string relativePath = Path.GetRelativePath(directory, outputPath);
        if (relativePath.Length == 0
            || relativePath.Equals("..", StringComparison.Ordinal)
            || relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathRooted(relativePath))
        {
            throw new ArgumentException($"OutputPath '{outputPath}' must name a file inside '{directory}'.");
        }
    }

    /// <summary>
    /// Matches release tags accepted by the release artifact manifest.
    /// </summary>
    /// <returns>The generated release tag regular expression.</returns>
    [GeneratedRegex(ReleaseTagExpression, RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseTagPattern();
}
