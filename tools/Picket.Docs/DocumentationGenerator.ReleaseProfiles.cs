using System.Text;
using System.Xml.Linq;

namespace Picket.Docs;

internal sealed partial class DocumentationGenerator
{
    private static readonly string[] s_corePublishProperties =
    [
        "PublishAot",
        "SelfContained",
        "PublishSingleFile",
        "InvariantGlobalization",
    ];

    private static readonly string[] s_optimizationProperties =
    [
        "Configuration",
        "OptimizationPreference",
        "StripSymbols",
        "UseSystemResourceKeys",
    ];

    private static readonly string[] s_diagnosticsProperties =
    [
        "DebuggerSupport",
        "EventSourceSupport",
        "MetricsSupport",
        "StackTraceSupport",
        "HttpActivityPropagationSupport",
    ];

    private static readonly string[] s_runtimeFeatureProperties =
    [
        "EnableUnsafeBinaryFormatterSerialization",
        "EnableUnsafeUTF7Encoding",
        "MetadataUpdaterSupport",
        "XmlResolverIsNetworkingEnabledByDefault",
        "Http3Support",
    ];

    private static readonly string[] s_packageMetadataProperties =
    [
        "VersionPrefix",
        "Authors",
        "PackageLicenseExpression",
        "PackageProjectUrl",
        "RepositoryUrl",
        "PackageTags",
        "IncludeSymbols",
        "SymbolPackageFormat",
    ];

    private void GenerateReleaseProfileReference(string outputRoot)
    {
        List<(string Project, string Profile, string RelativePath, Dictionary<string, string> Properties)> profiles = ReadReleaseProfiles();
        List<(string PackageId, string TargetFrameworks, string Description, string Tags, string PackageReferences, string ProjectReferences)> packages = ReadPublicPackageMetadata();
        Dictionary<string, string> packageMetadata = ReadMsBuildProperties(Path.Combine(_repositoryRoot, "Directory.Build.props"));
        List<(string PackageId, string Version)> packageVersions = ReadCentralPackageVersions();
        List<(string Workflow, string Os, string Rid)> workflowRids = ReadWorkflowRuntimeIdentifiers();

        var builder = new StringBuilder();
        builder.AppendLine("This page is generated from publish profiles, packable project files, central package metadata, and release workflow matrices.");
        builder.AppendLine();
        AppendReleaseProfileOverview(builder, profiles);
        AppendReleaseProfileMatrix(builder, profiles);
        AppendGlobalPackageMetadata(builder, packageMetadata);
        AppendPublicPackageMetadata(builder, packages);
        AppendCentralPackageVersions(builder, packageVersions);
        AppendWorkflowRuntimeIdentifierMatrix(builder, workflowRids);

        WriteMarkdown(
            Path.Combine(outputRoot, "release-profiles.md"),
            "Release Profile Reference",
            "Generated release profile and package metadata reference.",
            builder.ToString(),
            tableOfContents: false);
    }

    private List<(string Project, string Profile, string RelativePath, Dictionary<string, string> Properties)> ReadReleaseProfiles()
    {
        string[] profileFiles = [.. Directory
            .EnumerateFiles(Path.Combine(_repositoryRoot, "src"), "*.pubxml", SearchOption.AllDirectories)
            .Order(StringComparer.OrdinalIgnoreCase)];
        var profiles = new List<(string Project, string Profile, string RelativePath, Dictionary<string, string> Properties)>(profileFiles.Length);

        for (int i = 0; i < profileFiles.Length; i++)
        {
            string path = profileFiles[i];
            string project = Path.GetFileName(Directory.GetParent(path)?.Parent?.Parent?.FullName ?? string.Empty);
            profiles.Add((
                project,
                Path.GetFileNameWithoutExtension(path),
                NormalizePath(Path.GetRelativePath(_repositoryRoot, path)),
                ReadMsBuildProperties(path)));
        }

        return [.. profiles
            .OrderBy(static profile => profile.Profile, StringComparer.Ordinal)
            .ThenBy(static profile => profile.Project, StringComparer.Ordinal)];
    }

    private List<(string PackageId, string TargetFrameworks, string Description, string Tags, string PackageReferences, string ProjectReferences)> ReadPublicPackageMetadata()
    {
        string[] projectFiles = [.. Directory
            .EnumerateFiles(Path.Combine(_repositoryRoot, "src"), "*.csproj", SearchOption.AllDirectories)
            .Order(StringComparer.OrdinalIgnoreCase)];
        var packages = new List<(string PackageId, string TargetFrameworks, string Description, string Tags, string PackageReferences, string ProjectReferences)>();

        for (int i = 0; i < projectFiles.Length; i++)
        {
            string path = projectFiles[i];
            XDocument document = XDocument.Load(path);
            Dictionary<string, string> properties = ReadMsBuildProperties(document);
            if (!properties.TryGetValue("IsPackable", out string? isPackable)
                || !isPackable.Equals("true", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            packages.Add((
                properties.GetValueOrDefault("PackageId", Path.GetFileNameWithoutExtension(path)),
                properties.GetValueOrDefault("TargetFrameworks", properties.GetValueOrDefault("TargetFramework", string.Empty)),
                properties.GetValueOrDefault("Description", string.Empty),
                properties.GetValueOrDefault("PackageTags", string.Empty),
                FormatProjectItems(document, "PackageReference", "Include"),
                FormatProjectItems(document, "ProjectReference", "Include")));
        }

        return [.. packages.OrderBy(static package => package.PackageId, StringComparer.Ordinal)];
    }

    private static Dictionary<string, string> ReadMsBuildProperties(string path)
    {
        return ReadMsBuildProperties(XDocument.Load(path));
    }

    private static Dictionary<string, string> ReadMsBuildProperties(XDocument document)
    {
        var properties = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (XElement element in document.Descendants().Where(static element => element.Parent?.Name.LocalName == "PropertyGroup"))
        {
            properties[element.Name.LocalName] = NormalizeDocumentationText(element.Value);
        }

        return properties;
    }

    private List<(string PackageId, string Version)> ReadCentralPackageVersions()
    {
        XDocument document = XDocument.Load(Path.Combine(_repositoryRoot, "Directory.Packages.props"));
        return [.. document
            .Descendants()
            .Where(static element => element.Name.LocalName == "PackageVersion")
            .Select(static element => (
                PackageId: element.Attribute("Include")?.Value ?? string.Empty,
                Version: element.Attribute("Version")?.Value ?? string.Empty))
            .Where(static package => package.PackageId.Length != 0)
            .OrderBy(static package => package.PackageId, StringComparer.Ordinal)];
    }

    private List<(string Workflow, string Os, string Rid)> ReadWorkflowRuntimeIdentifiers()
    {
        var entries = new List<(string Workflow, string Os, string Rid)>();
        entries.AddRange(ReadWorkflowRuntimeIdentifiers(".github/workflows/ci.yml", "CI"));
        entries.AddRange(ReadWorkflowRuntimeIdentifiers(".github/workflows/release.yml", "Release"));
        return [.. entries
            .Distinct()
            .OrderBy(static entry => entry.Workflow, StringComparer.Ordinal)
            .ThenBy(static entry => entry.Rid, StringComparer.Ordinal)];
    }

    private List<(string Workflow, string Os, string Rid)> ReadWorkflowRuntimeIdentifiers(string relativePath, string workflowName)
    {
        string[] lines = File.ReadAllLines(Path.Combine(_repositoryRoot, relativePath));
        var entries = new List<(string Workflow, string Os, string Rid)>();
        string currentOs = string.Empty;
        for (int i = 0; i < lines.Length; i++)
        {
            string trimmed = lines[i].Trim();
            if (trimmed.StartsWith("- os:", StringComparison.Ordinal))
            {
                currentOs = trimmed["- os:".Length..].Trim();
                continue;
            }

            if (currentOs.Length != 0 && trimmed.StartsWith("rid:", StringComparison.Ordinal))
            {
                string rid = trimmed["rid:".Length..].Trim();
                entries.Add((workflowName, currentOs, rid));
                currentOs = string.Empty;
            }
        }

        return entries;
    }

    private static void AppendReleaseProfileOverview(
        StringBuilder builder,
        List<(string Project, string Profile, string RelativePath, Dictionary<string, string> Properties)> profiles)
    {
        builder.AppendLine("## Profile Overview");
        builder.AppendLine();
        builder.AppendLine("| Profile | Project | Purpose | Publish profile path |");
        builder.AppendLine("|---|---|---|---|");
        foreach ((string project, string profile, string relativePath, Dictionary<string, string> _) in profiles)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(profile));
            builder.Append("` | `");
            builder.Append(EscapeTable(project));
            builder.Append("` | ");
            builder.Append(EscapeTable(GetReleaseProfilePurpose(profile)));
            builder.Append(" | `");
            builder.Append(EscapeTable(relativePath));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static string GetReleaseProfilePurpose(string profile)
    {
        return profile switch
        {
            "release-speed" => "Default public Native AOT binary profile.",
            "release-minsize" => "Smallest supported Native AOT binary profile.",
            "release-diagnostics" => "Support binary profile with richer diagnostics enabled.",
            _ => "Release publish profile.",
        };
    }

    private static void AppendReleaseProfileMatrix(
        StringBuilder builder,
        List<(string Project, string Profile, string RelativePath, Dictionary<string, string> Properties)> profiles)
    {
        builder.AppendLine("## Publish Profile Properties");
        builder.AppendLine();
        builder.AppendLine("| Profile | Project | Core publish | Optimization | Diagnostics | Runtime feature switches |");
        builder.AppendLine("|---|---|---|---|---|---|");
        foreach ((string project, string profile, string _, Dictionary<string, string> properties) in profiles)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(profile));
            builder.Append("` | `");
            builder.Append(EscapeTable(project));
            builder.Append("` |");
            AppendPropertyGroupCell(builder, properties, s_corePublishProperties);
            AppendPropertyGroupCell(builder, properties, s_optimizationProperties);
            AppendPropertyGroupCell(builder, properties, s_diagnosticsProperties);
            AppendPropertyGroupCell(builder, properties, s_runtimeFeatureProperties);
            builder.AppendLine();
        }

        builder.AppendLine();
    }

    private static void AppendPropertyGroupCell(StringBuilder builder, Dictionary<string, string> properties, string[] propertyNames)
    {
        builder.Append(' ');
        builder.Append(EscapeTable(FormatPropertyGroup(properties, propertyNames)));
        builder.Append(" |");
    }

    private static string FormatPropertyGroup(Dictionary<string, string> properties, string[] propertyNames)
    {
        string[] values = [.. propertyNames.Select(property => string.Concat(property, "=", properties.GetValueOrDefault(property, "-")))];
        return string.Join(", ", values);
    }

    private static void AppendGlobalPackageMetadata(StringBuilder builder, Dictionary<string, string> packageMetadata)
    {
        builder.AppendLine("## Global Package Metadata");
        builder.AppendLine();
        builder.AppendLine("| Property | Value |");
        builder.AppendLine("|---|---|");
        for (int i = 0; i < s_packageMetadataProperties.Length; i++)
        {
            string property = s_packageMetadataProperties[i];
            builder.Append("| `");
            builder.Append(EscapeTable(property));
            builder.Append("` | `");
            builder.Append(EscapeTable(packageMetadata.GetValueOrDefault(property, string.Empty)));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendPublicPackageMetadata(
        StringBuilder builder,
        List<(string PackageId, string TargetFrameworks, string Description, string Tags, string PackageReferences, string ProjectReferences)> packages)
    {
        builder.AppendLine("## Public NuGet Packages");
        builder.AppendLine();
        builder.AppendLine("| Package | Target frameworks | Description | Package references | Project references |");
        builder.AppendLine("|---|---|---|---|---|");
        foreach ((string packageId, string targetFrameworks, string description, string _, string packageReferences, string projectReferences) in packages)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(packageId));
            builder.Append("` | `");
            builder.Append(EscapeTable(targetFrameworks));
            builder.Append("` | ");
            builder.Append(EscapeTable(description));
            builder.Append(" | ");
            builder.Append(EscapeTable(packageReferences));
            builder.Append(" | ");
            builder.Append(EscapeTable(projectReferences));
            builder.AppendLine(" |");
        }

        builder.AppendLine();
    }

    private static void AppendCentralPackageVersions(StringBuilder builder, List<(string PackageId, string Version)> packageVersions)
    {
        builder.AppendLine("## Central Package Versions");
        builder.AppendLine();
        builder.AppendLine("| Package | Version |");
        builder.AppendLine("|---|---|");
        foreach ((string packageId, string version) in packageVersions)
        {
            builder.Append("| `");
            builder.Append(EscapeTable(packageId));
            builder.Append("` | `");
            builder.Append(EscapeTable(version));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static void AppendWorkflowRuntimeIdentifierMatrix(StringBuilder builder, List<(string Workflow, string Os, string Rid)> workflowRids)
    {
        builder.AppendLine("## Workflow Runtime Identifiers");
        builder.AppendLine();
        builder.AppendLine("| Workflow | Runner | RID |");
        builder.AppendLine("|---|---|---|");
        foreach ((string workflow, string os, string rid) in workflowRids)
        {
            builder.Append("| ");
            builder.Append(EscapeTable(workflow));
            builder.Append(" | `");
            builder.Append(EscapeTable(os));
            builder.Append("` | `");
            builder.Append(EscapeTable(rid));
            builder.AppendLine("` |");
        }

        builder.AppendLine();
    }

    private static string FormatProjectItems(XDocument document, string itemName, string attributeName)
    {
        string[] values = [.. document
            .Descendants()
            .Where(element => element.Name.LocalName.Equals(itemName, StringComparison.Ordinal))
            .Select(element => element.Attribute(attributeName)?.Value ?? string.Empty)
            .Where(static value => value.Length != 0)
            .Select(static value => NormalizeProjectReferenceName(value))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)];

        return FormatValueList(values);
    }

    private static string NormalizeProjectReferenceName(string value)
    {
        if (!value.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        string normalized = value.Replace('\\', '/');
        int separatorIndex = normalized.LastIndexOf('/');
        string fileName = separatorIndex < 0 ? normalized : normalized[(separatorIndex + 1)..];
        return Path.GetFileNameWithoutExtension(fileName);
    }

    private static string NormalizePath(string value)
    {
        return value.Replace('\\', '/');
    }
}
