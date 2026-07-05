using System.Text;

namespace Picket.Docs;

internal sealed class DocumentationGenerator(string repositoryRoot)
{
    private readonly string _repositoryRoot = repositoryRoot;
    private readonly string _docsRoot = Path.Combine(repositoryRoot, "docs");
    private readonly string _siteDocsRoot = Path.Combine(repositoryRoot, "docs-site", "src", "content", "docs");

    internal static string FindRepositoryRoot(string startDirectory)
    {
        string? directory = Path.GetFullPath(startDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory, "Picket.slnx"))
                && Directory.Exists(Path.Combine(directory, "docs")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new DirectoryNotFoundException("Could not find the Picket repository root.");
    }

    internal void Generate()
    {
        string generatedRoot = Path.Combine(_siteDocsRoot, "generated");
        string referenceRoot = Path.Combine(_siteDocsRoot, "reference");
        RecreateDirectory(generatedRoot);
        RecreateDirectory(referenceRoot);

        GenerateProjectDocumentation(generatedRoot);
        GenerateCliReference(referenceRoot);
        GenerateActionReference(referenceRoot);
    }

    private void GenerateProjectDocumentation(string outputRoot)
    {
        foreach (string sourcePath in Directory.EnumerateFiles(_docsRoot, "*.md").Order(StringComparer.OrdinalIgnoreCase))
        {
            string fileName = Path.GetFileNameWithoutExtension(sourcePath);
            string title = CreateTitle(fileName);
            string content = File.ReadAllText(sourcePath);
            content = RemoveFirstHeading(content);

            WriteMarkdown(
                Path.Combine(outputRoot, string.Concat(Slugify(fileName), ".md")),
                title,
                $"Generated from docs/{Path.GetFileName(sourcePath)}.",
                content);
        }
    }

    private void GenerateCliReference(string outputRoot)
    {
        string helpSource = File.ReadAllText(Path.Combine(_repositoryRoot, "src", "Picket.Cli", "Program.Help.cs"));
        var usageLines = new List<string>();
        foreach (string line in helpSource.Split('\n'))
        {
            string? literal = TryReadConsoleLiteral(line);
            if (literal is not null && literal.StartsWith("  picket ", StringComparison.Ordinal))
            {
                usageLines.Add(literal.Trim());
            }
        }

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from the CLI help source so the published command reference stays aligned with the executable.");
        builder.AppendLine();
        builder.AppendLine("## Usage");
        builder.AppendLine();
        builder.AppendLine("```text");
        foreach (string usageLine in usageLines.Distinct(StringComparer.Ordinal))
        {
            builder.AppendLine(usageLine);
        }

        builder.AppendLine("```");

        WriteMarkdown(
            Path.Combine(outputRoot, "cli.md"),
            "CLI Reference",
            "Generated command reference for the Picket CLI.",
            builder.ToString());
    }

    private void GenerateActionReference(string outputRoot)
    {
        string[] lines = File.ReadAllLines(Path.Combine(_repositoryRoot, "action.yml"));
        List<Dictionary<string, string>> inputs = ReadActionSection(lines, "inputs");
        List<Dictionary<string, string>> outputs = ReadActionSection(lines, "outputs");

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from `action.yml`.");
        builder.AppendLine();
        AppendActionTable(builder, "Inputs", inputs);
        AppendActionTable(builder, "Outputs", outputs);

        WriteMarkdown(
            Path.Combine(outputRoot, "github-action.md"),
            "GitHub Action Reference",
            "Generated input and output reference for the Picket GitHub Action.",
            builder.ToString());
    }

    private static List<Dictionary<string, string>> ReadActionSection(string[] lines, string sectionName)
    {
        var items = new List<Dictionary<string, string>>();
        Dictionary<string, string>? current = null;
        bool inSection = false;
        string sectionHeader = string.Concat(sectionName, ":");

        foreach (string rawLine in lines)
        {
            string line = rawLine.TrimEnd();
            if (!inSection)
            {
                inSection = line.Equals(sectionHeader, StringComparison.Ordinal);
                continue;
            }

            if (line.Length != 0 && !line.StartsWith(' '))
            {
                break;
            }

            if (line.StartsWith("  ", StringComparison.Ordinal) && !line.StartsWith("    ", StringComparison.Ordinal))
            {
                string name = line.Trim().TrimEnd(':');
                current = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["name"] = name,
                };
                items.Add(current);
                continue;
            }

            if (current is null || !line.StartsWith("    ", StringComparison.Ordinal))
            {
                continue;
            }

            string trimmed = line.Trim();
            int separatorIndex = trimmed.IndexOf(':', StringComparison.Ordinal);
            if (separatorIndex <= 0)
            {
                continue;
            }

            string propertyName = trimmed[..separatorIndex];
            string propertyValue = Unquote(trimmed[(separatorIndex + 1)..].Trim());
            current[propertyName] = propertyValue;
        }

        return items;
    }

    private static void AppendActionTable(StringBuilder builder, string title, List<Dictionary<string, string>> items)
    {
        builder.AppendLine($"## {title}");
        builder.AppendLine();
        builder.AppendLine("| Name | Description | Required | Default or Value |");
        builder.AppendLine("|---|---|---:|---|");
        foreach (Dictionary<string, string> item in items)
        {
            string name = item["name"];
            string description = item.GetValueOrDefault("description", string.Empty);
            string required = item.GetValueOrDefault("required", string.Empty);
            string defaultValue = item.GetValueOrDefault("default", item.GetValueOrDefault("value", string.Empty));
            builder.Append("| `");
            builder.Append(EscapeTable(name));
            builder.Append("` | ");
            builder.Append(EscapeTable(description));
            builder.Append(" | ");
            builder.Append(EscapeTable(required));
            builder.Append(" | `");
            builder.Append(EscapeTable(defaultValue));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static string? TryReadConsoleLiteral(string line)
    {
        const string Marker = "Console.Out.WriteLine(\"";
        int start = line.IndexOf(Marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += Marker.Length;
        int end = line.LastIndexOf("\");", StringComparison.Ordinal);
        if (end <= start)
        {
            return null;
        }

        return line[start..end]
            .Replace("\\\"", "\"", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal);
    }

    private static void WriteMarkdown(string path, string title, string description, string content)
    {
        var builder = new StringBuilder();
        builder.AppendLine("---");
        builder.Append("title: ");
        builder.AppendLine(EscapeFrontMatter(title));
        builder.Append("description: ");
        builder.AppendLine(EscapeFrontMatter(description));
        builder.AppendLine("editUrl: false");
        builder.AppendLine("---");
        builder.AppendLine();
        builder.AppendLine("<!-- This file is generated by tools/Picket.Docs. -->");
        builder.AppendLine();
        builder.Append(content.Trim());
        builder.AppendLine();

        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new InvalidOperationException("Generated path has no directory."));
        File.WriteAllText(path, NormalizeLineEndings(builder.ToString()), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    private static void RecreateDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }

        Directory.CreateDirectory(path);
    }

    private static string RemoveFirstHeading(string content)
    {
        string[] lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        int firstContentLine = 0;
        while (firstContentLine < lines.Length && lines[firstContentLine].Length == 0)
        {
            firstContentLine++;
        }

        if (firstContentLine < lines.Length && lines[firstContentLine].StartsWith("# ", StringComparison.Ordinal))
        {
            return string.Join('\n', lines.Skip(firstContentLine + 1));
        }

        return content;
    }

    private static string CreateTitle(string fileName)
    {
        return string.Join(' ', fileName.Split('-', '_').Select(Capitalize));
    }

    private static string Capitalize(string value)
    {
        return value.Length == 0 ? value : string.Concat(char.ToUpperInvariant(value[0]), value[1..]);
    }

    private static string Slugify(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
                continue;
            }

            if (c is '-' or '_' or ' ')
            {
                builder.Append('-');
            }
        }

        return builder.ToString().Trim('-');
    }

    private static string Unquote(string value)
    {
        return value.Length >= 2 && value[0] == '"' && value[^1] == '"' ? value[1..^1] : value;
    }

    private static string EscapeFrontMatter(string value)
    {
        return string.Concat('"', value.Replace("\"", "\\\"", StringComparison.Ordinal), '"');
    }

    private static string EscapeTable(string value)
    {
        return value.Replace("|", "\\|", StringComparison.Ordinal);
    }

    private static string NormalizeLineEndings(string value)
    {
        return value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\r", "\n", StringComparison.Ordinal);
    }
}
