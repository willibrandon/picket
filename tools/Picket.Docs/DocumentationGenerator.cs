using System.Diagnostics;
using System.Text;
using System.Xml.Linq;

namespace Picket.Docs;

internal sealed class DocumentationGenerator(string repositoryRoot)
{
    private readonly string _repositoryRoot = repositoryRoot;
    private readonly string _docsRoot = Path.Combine(repositoryRoot, "docs");
    private readonly string _siteDocsRoot = Path.Combine(repositoryRoot, "docs-site", "src", "content", "docs");
    private readonly string[] _publicPackageIds = ["Picket.Rules", "Picket.Engine", "Picket.Report"];

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
        string apiRoot = Path.Combine(_siteDocsRoot, "api");
        RecreateDirectory(generatedRoot);
        RecreateDirectory(referenceRoot);
        RecreateDirectory(apiRoot);

        GenerateProjectDocumentation(generatedRoot);
        GenerateCliReference(referenceRoot);
        GenerateActionReference(referenceRoot);
        GenerateApiReference(apiRoot);
    }

    internal string GetGeneratedDocumentationStatus()
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo("git")
        {
            WorkingDirectory = _repositoryRoot,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        process.StartInfo.ArgumentList.Add("status");
        process.StartInfo.ArgumentList.Add("--porcelain");
        process.StartInfo.ArgumentList.Add("--");
        process.StartInfo.ArgumentList.Add("docs-site/src/content/docs/api");
        process.StartInfo.ArgumentList.Add("docs-site/src/content/docs/generated");
        process.StartInfo.ArgumentList.Add("docs-site/src/content/docs/reference");

        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"git status failed with exit code {process.ExitCode}: {error.Trim()}");
        }

        return NormalizeLineEndings(output).Trim();
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

    private void GenerateApiReference(string outputRoot)
    {
        foreach (string packageId in _publicPackageIds)
        {
            string xmlPath = Path.Combine(_repositoryRoot, "src", packageId, "bin", "Release", "net10.0", string.Concat(packageId, ".xml"));
            if (!File.Exists(xmlPath))
            {
                throw new FileNotFoundException(
                    $"Missing XML documentation for {packageId}. Run `dotnet build src/{packageId}/{packageId}.csproj --configuration Release --framework net10.0` first.",
                    xmlPath);
            }

            XDocument document = XDocument.Load(xmlPath);
            List<XElement> members = [.. document.Descendants("member")];
            List<XElement> types = [.. members
                .Where(member => GetMemberId(member).StartsWith("T:", StringComparison.Ordinal))
                .OrderBy(member => GetMemberId(member), StringComparer.Ordinal)];

            var builder = new StringBuilder();
            builder.Append("Generated from XML documentation for `");
            builder.Append(packageId);
            builder.AppendLine("`.");
            builder.AppendLine();
            builder.AppendLine("## Types");
            builder.AppendLine();
            foreach (XElement type in types)
            {
                string typeName = GetMemberId(type)[2..];
                builder.Append("- `");
                builder.Append(typeName);
                builder.Append("` - ");
                builder.AppendLine(EscapeMarkdownText(ReadSummary(type)));
            }

            foreach (XElement type in types)
            {
                string typeName = GetMemberId(type)[2..];
                List<XElement> typeMembers = [.. members
                    .Where(member => IsTypeMember(GetMemberId(member), typeName))
                    .OrderBy(member => GetMemberKind(GetMemberId(member)), StringComparer.Ordinal)
                    .ThenBy(member => GetMemberDisplayName(GetMemberId(member), typeName), StringComparer.Ordinal)];

                builder.AppendLine();
                builder.Append("## `");
                builder.Append(typeName);
                builder.AppendLine("`");
                builder.AppendLine();
                builder.AppendLine(ReadSummary(type));
                if (typeMembers.Count == 0)
                {
                    continue;
                }

                builder.AppendLine();
                builder.AppendLine("| Kind | Member | Summary |");
                builder.AppendLine("|---|---|---|");
                foreach (XElement member in typeMembers)
                {
                    string memberId = GetMemberId(member);
                    builder.Append("| ");
                    builder.Append(GetMemberKind(memberId));
                    builder.Append(" | `");
                    builder.Append(EscapeTable(GetMemberDisplayName(memberId, typeName)));
                    builder.Append("` | ");
                    builder.Append(EscapeTable(ReadSummary(member)));
                    builder.AppendLine(" |");
                }
            }

            WriteMarkdown(
                Path.Combine(outputRoot, string.Concat(Slugify(packageId), ".md")),
                string.Concat(packageId, " API"),
                string.Concat("Generated API reference for ", packageId, "."),
                builder.ToString());
        }
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

            if (c is '-' or '_' or ' ' or '.')
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
        return EscapeMarkdownText(value).Replace("|", "\\|", StringComparison.Ordinal);
    }

    private static string NormalizeLineEndings(string value)
    {
        return value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\r", "\n", StringComparison.Ordinal);
    }

    private static string GetMemberId(XElement member)
    {
        return member.Attribute("name")?.Value ?? string.Empty;
    }

    private static bool IsTypeMember(string memberId, string typeName)
    {
        if (memberId.StartsWith("T:", StringComparison.Ordinal))
        {
            return false;
        }

        return memberId.Length > 2 && FindMemberTypeName(memberId[2..]).Equals(typeName, StringComparison.Ordinal);
    }

    private static string FindMemberTypeName(string memberName)
    {
        int parameterIndex = memberName.IndexOf('(', StringComparison.Ordinal);
        if (parameterIndex >= 0)
        {
            memberName = memberName[..parameterIndex];
        }

        int separatorIndex = memberName.LastIndexOf('.');
        return separatorIndex <= 0 ? string.Empty : memberName[..separatorIndex];
    }

    private static string GetMemberKind(string memberId)
    {
        if (memberId.Length < 2)
        {
            return "Member";
        }

        return memberId[0] switch
        {
            'F' => "Field",
            'M' => "Method",
            'P' => "Property",
            'T' => "Type",
            _ => "Member",
        };
    }

    private static string GetMemberDisplayName(string memberId, string typeName)
    {
        if (memberId.Length <= 2)
        {
            return memberId;
        }

        string memberName = memberId[2..];
        string parameters = string.Empty;
        int parameterIndex = memberName.IndexOf('(', StringComparison.Ordinal);
        if (parameterIndex >= 0)
        {
            parameters = memberName[parameterIndex..];
            memberName = memberName[..parameterIndex];
        }

        string typePrefix = string.Concat(typeName, ".");
        if (memberName.StartsWith(typePrefix, StringComparison.Ordinal))
        {
            memberName = memberName[typePrefix.Length..];
        }

        if (memberName.Equals("#ctor", StringComparison.Ordinal))
        {
            memberName = GetShortTypeName(typeName);
        }

        return string.Concat(memberName, parameters);
    }

    private static string GetShortTypeName(string typeName)
    {
        int separatorIndex = typeName.LastIndexOf('.');
        return separatorIndex < 0 ? typeName : typeName[(separatorIndex + 1)..];
    }

    private static string ReadSummary(XElement member)
    {
        XElement? summary = member.Element("summary");
        return summary is null ? string.Empty : NormalizeDocumentationText(summary.Value);
    }

    private static string NormalizeDocumentationText(string value)
    {
        var builder = new StringBuilder(value.Length);
        bool previousWasWhiteSpace = true;
        foreach (char c in value)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!previousWasWhiteSpace)
                {
                    builder.Append(' ');
                    previousWasWhiteSpace = true;
                }

                continue;
            }

            builder.Append(c);
            previousWasWhiteSpace = false;
        }

        return builder.ToString().Trim();
    }

    private static string EscapeMarkdownText(string value)
    {
        return NormalizeDocumentationText(value).Replace("`", "\\`", StringComparison.Ordinal);
    }
}
