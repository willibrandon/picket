using System.Diagnostics;
using System.Net;
using System.Text;
using System.Xml.Linq;

namespace Picket.Docs;

internal sealed class DocumentationGenerator(string repositoryRoot)
{
    private readonly string _repositoryRoot = repositoryRoot;
    private readonly string _docsRoot = Path.Combine(repositoryRoot, "docs");
    private readonly string _siteDocsRoot = Path.Combine(repositoryRoot, "docs-site", "src", "content", "docs");
    private readonly string[] _publicPackageIds = ["Picket.Rules", "Picket.Engine", "Picket.Report", "Picket.Security"];

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
        List<List<string>> helpBlocks = ReadCliHelpBlocks(helpSource);
        List<string> rootBlock = helpBlocks.Count == 0 ? [] : helpBlocks[0];
        List<List<string>> commandBlocks = [.. helpBlocks.Skip(1)];
        List<string> rootUsageLines = ReadCliHelpSection(rootBlock, "Usage");
        HashSet<string> rootCommands = ReadCliUsageCommands(rootUsageLines);
        Dictionary<string, string> commandSummaries = ReadCliCommandSummaries(commandBlocks);

        var builder = new StringBuilder();
        builder.AppendLine("<p class=\"cli-reference-lede\">Use Picket commands to scan code, verify and analyze findings, manage rule packs, maintain caches, install hooks, and run Gitleaks-compatible workflows.</p>");
        builder.AppendLine();

        AppendCliCommandOverview(builder, rootCommands, commandSummaries);
        builder.AppendLine("## Command Reference");
        builder.AppendLine();
        Dictionary<string, List<string>> commandBlockByCommand = ReadCliCommandBlocks(commandBlocks);
        foreach (string usageLine in rootUsageLines)
        {
            string command = GetCliUsageCommandName(usageLine);
            if (command.Length == 0)
            {
                continue;
            }

            if (commandBlockByCommand.TryGetValue(command, out List<string>? commandBlock))
            {
                AppendCliHelpBlock(builder, commandBlock);
                continue;
            }

            AppendCliUsageOnlyBlock(builder, command, GetCliFallbackSummary(command), usageLine);
        }

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
                string shortTypeName = GetShortTypeName(typeName);
                builder.Append("- [");
                builder.Append(EscapeMarkdownText(shortTypeName));
                builder.Append("](#");
                builder.Append(Slugify(shortTypeName));
                builder.Append(')');
                string summary = ReadSummary(type);
                if (summary.Length != 0)
                {
                    builder.Append(" - ");
                    builder.Append(EscapeMarkdownText(summary));
                }

                builder.AppendLine();
            }

            foreach (XElement type in types)
            {
                string typeName = GetMemberId(type)[2..];
                List<XElement> typeMembers = [.. members
                    .Where(member => IsTypeMember(GetMemberId(member), typeName))
                    .OrderBy(member => GetApiMemberGroup(GetMemberId(member)), StringComparer.Ordinal)
                    .ThenBy(member => GetMemberSignature(GetMemberId(member), typeName, member), StringComparer.Ordinal)];

                builder.AppendLine();
                builder.Append("## ");
                builder.AppendLine(GetShortTypeName(typeName));
                builder.AppendLine();
                builder.Append('`');
                builder.Append(typeName);
                builder.AppendLine("`");
                string summary = ReadSummary(type);
                if (summary.Length != 0)
                {
                    builder.AppendLine();
                    builder.AppendLine(EscapeMarkdownText(summary));
                }

                if (typeMembers.Count == 0)
                {
                    continue;
                }

                AppendApiMemberGroup(builder, "Constructors", typeMembers, typeName);
                AppendApiMemberGroup(builder, "Methods", typeMembers, typeName);
                AppendApiMemberGroup(builder, "Properties", typeMembers, typeName);
                AppendApiMemberGroup(builder, "Fields", typeMembers, typeName);
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

    private static List<List<string>> ReadCliHelpBlocks(string helpSource)
    {
        var helpBlocks = new List<List<string>>();
        List<string>? currentBlock = null;
        foreach (string line in helpSource.Split('\n'))
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("static void Write", StringComparison.Ordinal)
                && trimmed.Contains("Help(", StringComparison.Ordinal))
            {
                currentBlock = [];
                helpBlocks.Add(currentBlock);
                continue;
            }

            if (currentBlock is null)
            {
                continue;
            }

            string? literal = TryReadConsoleLiteral(line);
            if (literal is not null)
            {
                currentBlock.Add(literal);
                continue;
            }

            if (trimmed.Equals("}", StringComparison.Ordinal))
            {
                currentBlock = null;
            }
        }

        return helpBlocks;
    }

    private static List<string> ReadCliHelpSection(List<string> block, string sectionName)
    {
        var lines = new List<string>();
        bool inSection = false;
        string header = string.Concat(sectionName, ":");
        foreach (string line in block)
        {
            if (!inSection)
            {
                inSection = line.Equals(header, StringComparison.Ordinal);
                continue;
            }

            if (line.Length == 0 || IsCliHelpHeader(line))
            {
                break;
            }

            lines.Add(line.Trim());
        }

        return lines;
    }

    private static Dictionary<string, string> ReadCliCommandSummaries(List<List<string>> commandBlocks)
    {
        var summaries = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (List<string> commandBlock in commandBlocks)
        {
            if (!TryReadCliTitle(commandBlock, out string command, out string summary))
            {
                continue;
            }

            summaries[command] = summary;
        }

        return summaries;
    }

    private static HashSet<string> ReadCliUsageCommands(List<string> usageLines)
    {
        var commands = new HashSet<string>(StringComparer.Ordinal);
        foreach (string usageLine in usageLines)
        {
            string command = GetCliUsageCommandName(usageLine);
            if (command.Length != 0)
            {
                commands.Add(command);
            }
        }

        return commands;
    }

    private static Dictionary<string, List<string>> ReadCliCommandBlocks(List<List<string>> commandBlocks)
    {
        var blocks = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (List<string> commandBlock in commandBlocks)
        {
            if (!TryReadCliTitle(commandBlock, out string command, out _))
            {
                continue;
            }

            blocks[command] = commandBlock;
        }

        return blocks;
    }

    private static void AppendCliCommandOverview(
        StringBuilder builder,
        HashSet<string> availableCommands,
        Dictionary<string, string> commandSummaries)
    {
        builder.AppendLine("## Commands");
        builder.AppendLine();
        builder.AppendLine("Use the grouped index to jump to the workflow you need.");
        builder.AppendLine();
        var renderedCommands = new HashSet<string>(StringComparer.Ordinal);
        builder.AppendLine("<div class=\"cli-command-groups\">");
        AppendCliCommandGroup(
            builder,
            "Scan and triage",
            availableCommands,
            renderedCommands,
            commandSummaries,
            ["picket scan", "picket verify", "picket analyze"]);
        AppendCliCommandGroup(
            builder,
            "Reports and baselines",
            availableCommands,
            renderedCommands,
            commandSummaries,
            ["picket baseline create", "picket view"]);
        AppendCliCommandGroup(
            builder,
            "Rules",
            availableCommands,
            renderedCommands,
            commandSummaries,
            ["picket rules check", "picket rules test"]);
        AppendCliCommandGroup(
            builder,
            "Maintenance",
            availableCommands,
            renderedCommands,
            commandSummaries,
            ["picket cache stats", "picket cache prune", "picket hooks install"]);
        AppendCliCommandGroup(
            builder,
            "Compatibility",
            availableCommands,
            renderedCommands,
            commandSummaries,
            ["picket git", "picket dir", "picket stdin", "picket version"]);

        string[] remainingCommands = [.. availableCommands
            .Where(command => !renderedCommands.Contains(command))
            .Order(StringComparer.Ordinal)];
        AppendCliCommandGroup(
            builder,
            "Other",
            availableCommands,
            renderedCommands,
            commandSummaries,
            remainingCommands);
        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendCliCommandGroup(
        StringBuilder builder,
        string title,
        HashSet<string> availableCommands,
        HashSet<string> renderedCommands,
        Dictionary<string, string> commandSummaries,
        string[] commands)
    {
        string[] groupCommands = [.. commands.Where(availableCommands.Contains)];
        if (groupCommands.Length == 0)
        {
            return;
        }

        builder.AppendLine("  <section class=\"cli-command-group\">");
        builder.Append("    <p class=\"cli-command-group-title\">");
        builder.Append(EscapeHtmlText(title));
        builder.AppendLine("</p>");
        builder.AppendLine("    <ul class=\"cli-command-list\">");
        foreach (string command in groupCommands)
        {
            renderedCommands.Add(command);
            string summary = commandSummaries.GetValueOrDefault(command, GetCliFallbackSummary(command));
            builder.AppendLine("      <li>");
            builder.Append("        <a class=\"cli-command-link\" href=\"#");
            builder.Append(Slugify(command));
            builder.AppendLine("\">");
            builder.Append("          <code>");
            builder.Append(EscapeHtmlText(command));
            builder.AppendLine("</code>");
            if (summary.Length != 0)
            {
                builder.Append("          <span>");
                builder.Append(EscapeHtmlText(summary));
                builder.AppendLine("</span>");
            }

            builder.AppendLine("        </a>");
            builder.AppendLine("      </li>");
        }

        builder.AppendLine("    </ul>");
        builder.AppendLine("  </section>");
    }

    private static void AppendCliHelpBlock(StringBuilder builder, List<string> block)
    {
        if (!TryReadCliTitle(block, out string command, out string summary))
        {
            return;
        }

        builder.Append("### ");
        builder.AppendLine(EscapeMarkdownText(command));
        builder.AppendLine();
        builder.AppendLine("<div class=\"cli-command-detail\">");
        if (summary.Length != 0)
        {
            builder.Append("  <p class=\"cli-command-summary\">");
            builder.Append(EscapeHtmlText(summary));
            builder.AppendLine("</p>");
        }

        for (int i = 1; i < block.Count; i++)
        {
            string line = block[i];
            if (!IsCliHelpHeader(line))
            {
                continue;
            }

            string sectionName = line[..^1];
            var sectionLines = new List<string>();
            while (++i < block.Count)
            {
                string sectionLine = block[i];
                if (sectionLine.Length == 0)
                {
                    break;
                }

                if (IsCliHelpHeader(sectionLine))
                {
                    i--;
                    break;
                }

                sectionLines.Add(sectionLine.Trim());
            }

            AppendCliHelpSection(builder, sectionName, sectionLines);
        }

        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendCliUsageOnlyBlock(StringBuilder builder, string command, string summary, string usageLine)
    {
        builder.Append("### ");
        builder.AppendLine(EscapeMarkdownText(command));
        builder.AppendLine();
        builder.AppendLine("<div class=\"cli-command-detail\">");
        if (summary.Length != 0)
        {
            builder.Append("  <p class=\"cli-command-summary\">");
            builder.Append(EscapeHtmlText(summary));
            builder.AppendLine("</p>");
        }

        AppendCliHelpSection(builder, "Usage", [usageLine]);
        builder.AppendLine("</div>");
        builder.AppendLine();
    }

    private static void AppendCliHelpSection(StringBuilder builder, string sectionName, List<string> sectionLines)
    {
        if (sectionLines.Count == 0)
        {
            return;
        }

        if (sectionName.Equals("Usage", StringComparison.Ordinal))
        {
            builder.AppendLine("  <div class=\"cli-usage-list\">");
            for (int i = 0; i < sectionLines.Count; i++)
            {
                builder.AppendLine("    <div class=\"cli-usage-block\">");
                builder.Append("      <p class=\"cli-section-label\">");
                builder.Append(sectionLines.Count == 1 ? "Usage" : string.Concat("Usage ", i + 1));
                builder.AppendLine("</p>");
                builder.Append("      <pre class=\"cli-usage-code\"><code>");
                builder.Append(EscapeHtmlCode(string.Join("\n", FormatCliUsageLine(sectionLines[i]))));
                builder.AppendLine("</code></pre>");
                builder.AppendLine("    </div>");
            }

            builder.AppendLine("  </div>");
            return;
        }

        builder.AppendLine("  <div class=\"cli-info-block\">");
        builder.Append("    <p class=\"cli-section-label\">");
        builder.Append(EscapeHtmlText(sectionName));
        builder.AppendLine("</p>");
        if (sectionLines.Count == 1)
        {
            builder.Append("    <p>");
            builder.Append(EscapeHtmlText(sectionLines[0]));
            builder.AppendLine("</p>");
            builder.AppendLine("  </div>");
            return;
        }

        builder.AppendLine("    <ul>");
        foreach (string sectionLine in sectionLines)
        {
            builder.Append("      <li>");
            builder.Append(EscapeHtmlText(sectionLine));
            builder.AppendLine("</li>");
        }

        builder.AppendLine("    </ul>");
        builder.AppendLine("  </div>");
    }

    private static bool TryReadCliTitle(List<string> block, out string command, out string summary)
    {
        command = string.Empty;
        summary = string.Empty;
        string title = block.FirstOrDefault(line => line.Length != 0) ?? string.Empty;
        if (title.Length == 0)
        {
            return false;
        }

        int separatorIndex = title.IndexOf(" - ", StringComparison.Ordinal);
        if (separatorIndex < 0)
        {
            command = title;
            return true;
        }

        command = title[..separatorIndex];
        summary = FormatCliDescription(title[(separatorIndex + 3)..]);
        return command.Length != 0;
    }

    private static bool IsCliHelpHeader(string line)
    {
        return line.Length > 1
            && line.EndsWith(':')
            && !line.StartsWith(' ');
    }

    private static string GetCliUsageCommandName(string usageLine)
    {
        string[] tokens = usageLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var commandTokens = new List<string>(4);
        foreach (string token in tokens)
        {
            if (token.StartsWith('[') || token.StartsWith('<') || token.StartsWith('-'))
            {
                break;
            }

            commandTokens.Add(token);
        }

        return commandTokens.Count == 0 ? string.Empty : string.Join(' ', commandTokens);
    }

    private static List<string> FormatCliUsageLine(string usageLine)
    {
        const int MaxSingleLineUsageLength = 100;
        if (usageLine.Length <= MaxSingleLineUsageLength)
        {
            return [usageLine];
        }

        string command = GetCliUsageCommandName(usageLine);
        if (command.Length == 0 || command.Length >= usageLine.Length)
        {
            return [usageLine];
        }

        List<string> arguments = SplitCliUsageArguments(usageLine[command.Length..].Trim());
        if (arguments.Count == 0)
        {
            return [usageLine];
        }

        var lines = new List<string>(arguments.Count + 1)
        {
            command,
        };
        foreach (string argument in arguments)
        {
            lines.Add(string.Concat("  ", argument));
        }

        return lines;
    }

    private static List<string> SplitCliUsageArguments(string arguments)
    {
        string[] tokens = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var groups = new List<string>(tokens.Length);
        for (int i = 0; i < tokens.Length; i++)
        {
            string group = tokens[i];
            if (group.StartsWith('[') && !group.Contains(']', StringComparison.Ordinal))
            {
                while (i + 1 < tokens.Length)
                {
                    group = string.Concat(group, " ", tokens[++i]);
                    if (group.Contains(']', StringComparison.Ordinal))
                    {
                        break;
                    }
                }
            }
            else if (IsCliUsageOptionToken(group)
                && i + 1 < tokens.Length
                && IsCliUsageValueToken(tokens[i + 1]))
            {
                group = string.Concat(group, " ", tokens[++i]);
            }

            groups.Add(group);
        }

        return groups;
    }

    private static bool IsCliUsageOptionToken(string token)
    {
        return token.StartsWith('-') && !token.StartsWith("---", StringComparison.Ordinal);
    }

    private static bool IsCliUsageValueToken(string token)
    {
        return token.Length != 0
            && !token.StartsWith('-')
            && !token.StartsWith('[')
            && !token.StartsWith('<');
    }

    private static string GetCliFallbackSummary(string command)
    {
        return command switch
        {
            "picket git" => "Gitleaks-compatible git history scan.",
            "picket dir" => "Gitleaks-compatible directory scan.",
            "picket stdin" => "Gitleaks-compatible stdin scan.",
            "picket version" => "Prints version information.",
            _ => string.Empty,
        };
    }

    private static string FormatCliDescription(string value)
    {
        string trimmed = NormalizeDocumentationText(value).TrimEnd('.');
        return trimmed.Length == 0 ? string.Empty : string.Concat(char.ToUpperInvariant(trimmed[0]), trimmed[1..], ".");
    }

    private static void AppendApiMemberGroup(StringBuilder builder, string title, List<XElement> members, string typeName)
    {
        List<XElement> groupMembers = [.. members.Where(member => GetApiMemberGroup(GetMemberId(member)).Equals(title, StringComparison.Ordinal))];
        if (groupMembers.Count == 0)
        {
            return;
        }

        builder.AppendLine();
        builder.Append("### ");
        builder.AppendLine(title);
        builder.AppendLine();
        foreach (XElement member in groupMembers)
        {
            string signature = GetMemberSignature(GetMemberId(member), typeName, member);
            string summary = ReadSummary(member);
            if (IsCallableApiGroup(title) && signature.Length > 100)
            {
                AppendCallableApiMember(builder, signature, summary);
                continue;
            }

            AppendInlineApiMember(builder, signature, summary);
        }
    }

    private static void AppendInlineApiMember(StringBuilder builder, string signature, string summary)
    {
        builder.Append("- `");
        builder.Append(EscapeMarkdownText(signature));
        builder.Append('`');
        if (summary.Length != 0)
        {
            builder.Append(" - ");
            builder.Append(EscapeMarkdownText(summary));
        }

        builder.AppendLine();
    }

    private static bool IsCallableApiGroup(string title)
    {
        return title is "Constructors" or "Methods";
    }

    private static void AppendCallableApiMember(StringBuilder builder, string signature, string summary)
    {
        builder.Append("#### `");
        builder.Append(EscapeMarkdownText(GetCallableApiHeading(signature)));
        builder.AppendLine("`");
        builder.AppendLine();
        builder.AppendLine("```csharp");
        builder.AppendLine(FormatApiCodeSignature(signature));
        builder.AppendLine("```");
        if (summary.Length != 0)
        {
            builder.AppendLine();
            builder.AppendLine(EscapeMarkdownText(summary));
        }

        builder.AppendLine();
    }

    private static string GetCallableApiHeading(string signature)
    {
        if (signature.Length <= 80)
        {
            return signature;
        }

        int parameterIndex = signature.IndexOf('(', StringComparison.Ordinal);
        return parameterIndex < 0 ? signature : string.Concat(signature[..parameterIndex], "(...)");
    }

    private static string FormatApiCodeSignature(string signature)
    {
        const int MaxSingleLineSignatureLength = 100;
        if (signature.Length <= MaxSingleLineSignatureLength)
        {
            return signature;
        }

        int parameterIndex = signature.IndexOf('(', StringComparison.Ordinal);
        if (parameterIndex < 0 || !signature.EndsWith(')'))
        {
            return signature;
        }

        List<string> parameters = SplitSignatureParameters(signature[(parameterIndex + 1)..^1]);
        if (parameters.Count <= 1)
        {
            return signature;
        }

        var builder = new StringBuilder(signature.Length + (parameters.Count * 6));
        builder.Append(signature[..parameterIndex]);
        builder.AppendLine("(");
        for (int i = 0; i < parameters.Count; i++)
        {
            builder.Append("    ");
            builder.Append(parameters[i]);
            if (i < parameters.Count - 1)
            {
                builder.Append(',');
            }

            builder.AppendLine();
        }

        builder.Append(')');
        return builder.ToString();
    }

    private static List<string> SplitSignatureParameters(string parameters)
    {
        var signatureParameters = new List<string>();
        if (parameters.Length == 0)
        {
            return signatureParameters;
        }

        int start = 0;
        int depth = 0;
        for (int i = 0; i < parameters.Length; i++)
        {
            char c = parameters[i];
            if (c == '<')
            {
                depth++;
                continue;
            }

            if (c == '>' && depth > 0)
            {
                depth--;
                continue;
            }

            if (c == ',' && depth == 0)
            {
                AddParameterType(signatureParameters, parameters[start..i]);
                start = i + 1;
            }
        }

        AddParameterType(signatureParameters, parameters[start..]);
        return signatureParameters;
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

    private static string GetApiMemberGroup(string memberId)
    {
        if (IsConstructorMember(memberId))
        {
            return "Constructors";
        }

        return memberId.Length == 0
            ? "Members"
            : memberId[0] switch
            {
                'F' => "Fields",
                'M' => "Methods",
                'P' => "Properties",
                _ => "Members",
            };
    }

    private static bool IsConstructorMember(string memberId)
    {
        return memberId.StartsWith("M:", StringComparison.Ordinal) && memberId.Contains(".#ctor", StringComparison.Ordinal);
    }

    private static string GetMemberSignature(string memberId, string typeName, XElement member)
    {
        if (memberId.Length <= 2)
        {
            return memberId;
        }

        string memberName = memberId[2..];
        string? parameters = null;
        int parameterIndex = memberName.IndexOf('(', StringComparison.Ordinal);
        if (parameterIndex >= 0)
        {
            parameters = memberName.EndsWith(')') ? memberName[(parameterIndex + 1)..^1] : string.Empty;
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

        memberName = FormatOperatorName(memberName);
        if (memberId[0] != 'M')
        {
            return memberName;
        }

        string parameterList = parameters is null ? string.Empty : FormatParameterList(parameters, member);
        return string.Concat(memberName, "(", parameterList, ")");
    }

    private static string FormatOperatorName(string memberName)
    {
        return memberName switch
        {
            "op_Equality" => "operator ==",
            "op_Inequality" => "operator !=",
            _ => memberName,
        };
    }

    private static string FormatParameterList(string parameters, XElement member)
    {
        List<string> parameterTypes = SplitParameterTypes(parameters);
        List<string> parameterNames = GetParameterNames(member);
        var builder = new StringBuilder(parameters.Length);
        for (int i = 0; i < parameterTypes.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(", ");
            }

            builder.Append(FormatTypeName(parameterTypes[i]));
            if (i < parameterNames.Count)
            {
                builder.Append(' ');
                builder.Append(parameterNames[i]);
            }
        }

        return builder.ToString();
    }

    private static List<string> GetParameterNames(XElement member)
    {
        var parameterNames = new List<string>();
        foreach (XElement parameter in member.Elements("param"))
        {
            string? name = parameter.Attribute("name")?.Value;
            if (!string.IsNullOrWhiteSpace(name))
            {
                parameterNames.Add(name);
            }
        }

        return parameterNames;
    }

    private static List<string> SplitParameterTypes(string parameters)
    {
        var parameterTypes = new List<string>();
        if (parameters.Length == 0)
        {
            return parameterTypes;
        }

        int start = 0;
        int depth = 0;
        for (int i = 0; i < parameters.Length; i++)
        {
            char c = parameters[i];
            if (c == '{')
            {
                depth++;
                continue;
            }

            if (c == '}' && depth > 0)
            {
                depth--;
                continue;
            }

            if (c == ',' && depth == 0)
            {
                AddParameterType(parameterTypes, parameters[start..i]);
                start = i + 1;
            }
        }

        AddParameterType(parameterTypes, parameters[start..]);
        return parameterTypes;
    }

    private static void AddParameterType(List<string> parameterTypes, string parameterType)
    {
        string trimmedParameterType = parameterType.Trim();
        if (trimmedParameterType.Length != 0)
        {
            parameterTypes.Add(trimmedParameterType);
        }
    }

    private static string FormatTypeName(string typeName)
    {
        typeName = typeName.Trim();
        if (typeName.EndsWith("[]", StringComparison.Ordinal))
        {
            return string.Concat(FormatTypeName(typeName[..^2]), "[]");
        }

        int genericIndex = typeName.IndexOf('{', StringComparison.Ordinal);
        if (genericIndex >= 0 && typeName.EndsWith('}'))
        {
            string genericTypeName = typeName[..genericIndex];
            List<string> genericArguments = SplitParameterTypes(typeName[(genericIndex + 1)..^1]);
            if (genericTypeName.Equals("System.Nullable", StringComparison.Ordinal) && genericArguments.Count == 1)
            {
                return string.Concat(FormatTypeName(genericArguments[0]), "?");
            }

            return string.Concat(
                FormatSimpleTypeName(genericTypeName),
                "<",
                string.Join(", ", genericArguments.Select(FormatTypeName)),
                ">");
        }

        return FormatSimpleTypeName(typeName);
    }

    private static string FormatSimpleTypeName(string typeName)
    {
        string simpleTypeName = typeName switch
        {
            "System.Boolean" => "bool",
            "System.Byte" => "byte",
            "System.Char" => "char",
            "System.Decimal" => "decimal",
            "System.Double" => "double",
            "System.Int16" => "short",
            "System.Int32" => "int",
            "System.Int64" => "long",
            "System.Object" => "object",
            "System.SByte" => "sbyte",
            "System.Single" => "float",
            "System.String" => "string",
            "System.UInt16" => "ushort",
            "System.UInt32" => "uint",
            "System.UInt64" => "ulong",
            "System.Void" => "void",
            _ => typeName,
        };

        int arityIndex = simpleTypeName.IndexOf('`', StringComparison.Ordinal);
        if (arityIndex >= 0)
        {
            simpleTypeName = simpleTypeName[..arityIndex];
        }

        return GetShortTypeName(simpleTypeName);
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

    private static string EscapeHtmlText(string value)
    {
        return WebUtility.HtmlEncode(NormalizeDocumentationText(value)) ?? string.Empty;
    }

    private static string EscapeHtmlCode(string value)
    {
        return WebUtility.HtmlEncode(value) ?? string.Empty;
    }
}
