#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Text;

try
{
    return CaptureUpstreamPinsApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidOperationException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Captures local reference repository pins into the upstream documentation table.
/// </summary>
internal static class CaptureUpstreamPinsApp
{
    /// <summary>
    /// Runs the upstream pin capture app.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            ["OutputPath"],
            [],
            ["Update", "AllowMissing"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string outputPath = ScriptSupport.GetString(values, "OutputPath", Path.Combine(repositoryRoot, "docs", "UPSTREAM.md"));
        (string Name, string EnvironmentVariable, string SiblingName)[] references =
        [
            ("Gitleaks", "PICKET_GITLEAKS_REPO", "gitleaks"),
            ("Scout", "PICKET_SCOUT_REPO", "scout"),
            ("TruffleHog", "PICKET_TRUFFLEHOG_REPO", "trufflehog"),
            ("Nosey Parker", "PICKET_NOSEYPARKER_REPO", "noseyparker"),
            ("Kingfisher", "PICKET_KINGFISHER_REPO", "kingfisher"),
            (".NET Runtime", "PICKET_DOTNET_RUNTIME_REPO", "runtime"),
        ];

        string table = CreatePinsTable(repositoryRoot, references, ScriptSupport.GetSwitch(switches, "AllowMissing"));
        if (!ScriptSupport.GetSwitch(switches, "Update"))
        {
            Console.Out.WriteLine(table);
            return 0;
        }

        const string StartMarker = "<!-- upstream-pins:start -->";
        const string EndMarker = "<!-- upstream-pins:end -->";

        string content = ScriptSupport.ReadTextFile(outputPath);
        int startIndex = content.IndexOf(StartMarker, StringComparison.Ordinal);
        int endIndex = content.IndexOf(EndMarker, StringComparison.Ordinal);
        if (startIndex < 0 || endIndex < 0 || endIndex <= startIndex)
        {
            throw new InvalidOperationException($"Could not find upstream pins markers in '{outputPath}'.");
        }

        string replacement = string.Concat(StartMarker, "\n", table, "\n", EndMarker);
        string updatedContent = string.Concat(
            content[..startIndex],
            replacement,
            content[(endIndex + EndMarker.Length)..]);
        ScriptSupport.WriteTextFile(Path.GetFullPath(outputPath), updatedContent);
        return 0;
    }

    /// <summary>
    /// Creates the Markdown pins table.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="references">The reference clone descriptors.</param>
    /// <param name="allowMissing">Whether missing clones should be represented instead of failing.</param>
    /// <returns>The Markdown pins table.</returns>
    private static string CreatePinsTable(
        string repositoryRoot,
        (string Name, string EnvironmentVariable, string SiblingName)[] references,
        bool allowMissing)
    {
        var builder = new StringBuilder();
        builder.AppendLine("| Project | Version | Commit | Remote |");
        builder.AppendLine("|---|---:|---|---|");

        foreach ((string name, string environmentVariable, string siblingName) in references)
        {
            (string Name, string Version, string Commit, string Remote) pin = GetReferencePin(
                repositoryRoot,
                name,
                environmentVariable,
                siblingName,
                allowMissing);
            builder.Append("| ")
                .Append(EscapeMarkdownCell(pin.Name))
                .Append(" | `")
                .Append(EscapeMarkdownCell(pin.Version))
                .Append("` | `")
                .Append(EscapeMarkdownCell(pin.Commit))
                .Append("` | `")
                .Append(EscapeMarkdownCell(pin.Remote))
                .AppendLine("` |");
        }

        return builder.ToString().TrimEnd();
    }

    /// <summary>
    /// Captures the version, commit, and remote URL for one reference clone.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="name">The display name.</param>
    /// <param name="environmentVariable">The environment variable used to override the path.</param>
    /// <param name="siblingName">The default sibling clone name.</param>
    /// <param name="allowMissing">Whether missing clones should be represented instead of failing.</param>
    /// <returns>The reference pin data.</returns>
    private static (string Name, string Version, string Commit, string Remote) GetReferencePin(
        string repositoryRoot,
        string name,
        string environmentVariable,
        string siblingName,
        bool allowMissing)
    {
        string path = ScriptSupport.ResolveReferencePath(repositoryRoot, environmentVariable, siblingName);
        if (!Directory.Exists(path))
        {
            if (allowMissing)
            {
                return (name, "missing", "missing", "missing");
            }

            throw new DirectoryNotFoundException(
                $"Reference clone '{name}' was not found at '{path}'. Set {environmentVariable} or clone it as sibling '{siblingName}'.");
        }

        return (
            name,
            ScriptSupport.RunGit(path, "describe", "--tags", "--always", "--dirty"),
            ScriptSupport.RunGit(path, "rev-parse", "HEAD"),
            ScriptSupport.RunGit(path, "remote", "get-url", "origin"));
    }

    /// <summary>
    /// Escapes Markdown table cell metacharacters.
    /// </summary>
    /// <param name="value">The cell value.</param>
    /// <returns>The escaped value.</returns>
    private static string EscapeMarkdownCell(string value)
    {
        return value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("|", "\\|", StringComparison.Ordinal);
    }
}
