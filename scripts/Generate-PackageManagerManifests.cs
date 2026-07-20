#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Globalization;
using System.Text;

try
{
    return GeneratePackageManagerManifestsApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or DirectoryNotFoundException or FileNotFoundException or InvalidDataException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Generates package-manager manifests from release archive checksums.
/// </summary>
internal static class GeneratePackageManagerManifestsApp
{
    /// <summary>
    /// The current WinGet manifest schema version used for generated manifests.
    /// </summary>
    private const string WingetManifestVersion = "1.12.0";

    /// <summary>
    /// Release binary archive descriptors used by package-manager manifests.
    /// </summary>
    private static readonly (string Rid, string FileExtension)[] s_releaseArchives =
    [
        ("linux-x64", "tar.gz"),
        ("linux-arm64", "tar.gz"),
        ("osx-x64", "tar.gz"),
        ("osx-arm64", "tar.gz"),
        ("win-x64", "zip"),
        ("win-arm64", "zip"),
    ];

    /// <summary>
    /// Runs the manifest generator.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, HashSet<string> switches) = ScriptSupport.ParseArguments(
            args,
            ["ReleaseTag", "ChecksumsPath", "OutputDirectory", "Repository", "PackageIdentifier", "PackageName", "Publisher", "PublisherUrl"],
            [],
            ["Clean"]);

        string repositoryRoot = ScriptSupport.FindRepositoryRoot();
        string releaseTag = RequireReleaseTag(ScriptSupport.GetString(values, "ReleaseTag", Environment.GetEnvironmentVariable("RELEASE_TAG") ?? string.Empty));
        string version = GetVersion(releaseTag);
        string repository = RequireRepository(ScriptSupport.GetString(values, "Repository", "willibrandon/picket"));
        string checksumsPath = Path.GetFullPath(ScriptSupport.GetString(values, "ChecksumsPath", Path.Combine(repositoryRoot, "dist", "checksums.txt")));
        string outputDirectory = Path.GetFullPath(ScriptSupport.GetString(values, "OutputDirectory", Path.Combine(repositoryRoot, "artifacts", "package-managers")));
        string packageIdentifier = RequireNonEmpty(ScriptSupport.GetString(values, "PackageIdentifier", "Willibrandon.Picket"), "PackageIdentifier");
        string packageName = RequireNonEmpty(ScriptSupport.GetString(values, "PackageName", "Picket"), "PackageName");
        string publisher = RequireNonEmpty(ScriptSupport.GetString(values, "Publisher", "Brandon Williams"), "Publisher");
        string publisherUrl = RequireNonEmpty(ScriptSupport.GetString(values, "PublisherUrl", "https://github.com/willibrandon"), "PublisherUrl");

        Dictionary<string, string> checksums = ReadChecksums(checksumsPath);
        Dictionary<string, string> archiveHashes = CreateArchiveHashMap(releaseTag, checksums);

        if (ScriptSupport.GetSwitch(switches, "Clean") && Directory.Exists(outputDirectory))
        {
            Directory.Delete(outputDirectory, recursive: true);
        }

        Directory.CreateDirectory(outputDirectory);
        List<string> files =
        [
            WriteHomebrewFormula(outputDirectory, repository, releaseTag, version, archiveHashes),
            WriteScoopManifest(outputDirectory, repository, releaseTag, version, archiveHashes),
        ];
        files.AddRange(WriteWingetManifests(outputDirectory, repository, releaseTag, version, packageIdentifier, packageName, publisher, publisherUrl, archiveHashes));

        foreach (string file in files)
        {
            Console.Out.WriteLine(Path.GetRelativePath(outputDirectory, file).Replace(Path.DirectorySeparatorChar, '/'));
        }

        return 0;
    }

    /// <summary>
    /// Requires a release tag to be present.
    /// </summary>
    /// <param name="releaseTag">The release tag value.</param>
    /// <returns>The trimmed release tag.</returns>
    private static string RequireReleaseTag(string releaseTag)
    {
        releaseTag = releaseTag.Trim();
        if (releaseTag.Length == 0)
        {
            throw new ArgumentException("ReleaseTag is required.");
        }

        return releaseTag;
    }

    /// <summary>
    /// Converts a release tag into a package version.
    /// </summary>
    /// <param name="releaseTag">The release tag.</param>
    /// <returns>The package version.</returns>
    private static string GetVersion(string releaseTag)
    {
        string version = releaseTag.StartsWith('v') || releaseTag.StartsWith('V') ? releaseTag[1..] : releaseTag;
        if (!IsSemVerLike(version))
        {
            throw new ArgumentException($"Release tag '{releaseTag}' does not contain a valid SemVer package version.");
        }

        return version;
    }

    /// <summary>
    /// Checks whether a version value is SemVer-shaped enough for release metadata.
    /// </summary>
    /// <param name="version">The version value.</param>
    /// <returns><see langword="true"/> when the value is accepted.</returns>
    private static bool IsSemVerLike(string version)
    {
        string[] versionParts = version.Split('-', 2);
        string[] numericParts = versionParts[0].Split('.');
        if (numericParts.Length != 3)
        {
            return false;
        }

        foreach (string numericPart in numericParts)
        {
            if (numericPart.Length == 0 || !int.TryParse(numericPart, NumberStyles.None, CultureInfo.InvariantCulture, out _))
            {
                return false;
            }
        }

        if (versionParts.Length == 1)
        {
            return true;
        }

        foreach (char ch in versionParts[1])
        {
            if (!char.IsAsciiLetterOrDigit(ch) && ch is not '-' and not '.')
            {
                return false;
            }
        }

        return versionParts[1].Length != 0;
    }

    /// <summary>
    /// Requires a non-empty option value.
    /// </summary>
    /// <param name="value">The option value.</param>
    /// <param name="name">The option name.</param>
    /// <returns>The trimmed value.</returns>
    private static string RequireNonEmpty(string value, string name)
    {
        value = value.Trim();
        if (value.Length == 0)
        {
            throw new ArgumentException($"{name} is required.");
        }

        return value;
    }

    /// <summary>
    /// Validates and returns the owner/name repository value.
    /// </summary>
    /// <param name="repository">The repository value.</param>
    /// <returns>The validated repository value.</returns>
    private static string RequireRepository(string repository)
    {
        repository = RequireNonEmpty(repository, "Repository");
        string[] parts = repository.Split('/');
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0)
        {
            throw new ArgumentException("Repository must use owner/name form.");
        }

        return repository;
    }

    /// <summary>
    /// Reads a checksums file into a filename-to-hash map.
    /// </summary>
    /// <param name="checksumsPath">The checksums file path.</param>
    /// <returns>The checksum map.</returns>
    private static Dictionary<string, string> ReadChecksums(string checksumsPath)
    {
        if (!File.Exists(checksumsPath))
        {
            throw new FileNotFoundException($"Checksums file was not found: {checksumsPath}", checksumsPath);
        }

        var checksums = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in File.ReadLines(checksumsPath))
        {
            if (line.Trim().Length == 0)
            {
                continue;
            }

            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || !IsSha256(parts[0]))
            {
                throw new InvalidDataException($"Invalid checksum line: {line}");
            }

            checksums[parts[1]] = parts[0].ToLowerInvariant();
        }

        return checksums;
    }

    /// <summary>
    /// Checks whether a value is a lowercase-or-uppercase SHA-256 digest.
    /// </summary>
    /// <param name="value">The candidate digest.</param>
    /// <returns><see langword="true"/> when the value is a digest.</returns>
    private static bool IsSha256(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }

        foreach (char ch in value)
        {
            if (!Uri.IsHexDigit(ch))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Creates a release archive checksum map keyed by RID.
    /// </summary>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="checksums">The file checksum map.</param>
    /// <returns>The RID checksum map.</returns>
    private static Dictionary<string, string> CreateArchiveHashMap(string releaseTag, Dictionary<string, string> checksums)
    {
        var archiveHashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach ((string rid, string extension) in s_releaseArchives)
        {
            string fileName = CreateArchiveName(releaseTag, rid, extension);
            if (!checksums.TryGetValue(fileName, out string? hash))
            {
                throw new InvalidDataException($"Checksum for '{fileName}' is missing.");
            }

            archiveHashes.Add(rid, hash);
        }

        return archiveHashes;
    }

    /// <summary>
    /// Creates a release archive filename.
    /// </summary>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="rid">The runtime identifier.</param>
    /// <param name="extension">The archive extension.</param>
    /// <returns>The archive filename.</returns>
    private static string CreateArchiveName(string releaseTag, string rid, string extension)
    {
        return $"picket-{releaseTag}-{rid}.{extension}";
    }

    /// <summary>
    /// Creates a release archive download URL.
    /// </summary>
    /// <param name="repository">The owner/name repository.</param>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="rid">The runtime identifier.</param>
    /// <param name="extension">The archive extension.</param>
    /// <returns>The archive URL.</returns>
    private static string CreateArchiveUrl(string repository, string releaseTag, string rid, string extension)
    {
        return $"https://github.com/{repository}/releases/download/{releaseTag}/{CreateArchiveName(releaseTag, rid, extension)}";
    }

    /// <summary>
    /// Writes the Homebrew formula.
    /// </summary>
    /// <param name="outputDirectory">The output directory.</param>
    /// <param name="repository">The owner/name repository.</param>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="version">The package version.</param>
    /// <param name="archiveHashes">The archive hashes keyed by RID.</param>
    /// <returns>The written file path.</returns>
    private static string WriteHomebrewFormula(
        string outputDirectory,
        string repository,
        string releaseTag,
        string version,
        Dictionary<string, string> archiveHashes)
    {
        string formulaDirectory = Path.Combine(outputDirectory, "homebrew");
        Directory.CreateDirectory(formulaDirectory);
        string formulaPath = Path.Combine(formulaDirectory, "picket.rb");
        var formula = new StringBuilder();
        formula.AppendLine("class Picket < Formula");
        formula.AppendLine("  desc \"Native AOT secrets scanner with Gitleaks-compatible and Picket-native modes\"");
        formula.AppendLine($"  homepage \"https://github.com/{repository}\"");
        formula.AppendLine($"  version \"{version}\"");
        formula.AppendLine("  license \"MIT\"");
        formula.AppendLine();
        formula.AppendLine("  on_macos do");
        formula.AppendLine("    if Hardware::CPU.arm?");
        formula.AppendLine($"      url \"{CreateArchiveUrl(repository, releaseTag, "osx-arm64", "tar.gz")}\"");
        formula.AppendLine($"      sha256 \"{archiveHashes["osx-arm64"]}\"");
        formula.AppendLine("    else");
        formula.AppendLine($"      url \"{CreateArchiveUrl(repository, releaseTag, "osx-x64", "tar.gz")}\"");
        formula.AppendLine($"      sha256 \"{archiveHashes["osx-x64"]}\"");
        formula.AppendLine("    end");
        formula.AppendLine("  end");
        formula.AppendLine();
        formula.AppendLine("  on_linux do");
        formula.AppendLine("    if Hardware::CPU.arm?");
        formula.AppendLine($"      url \"{CreateArchiveUrl(repository, releaseTag, "linux-arm64", "tar.gz")}\"");
        formula.AppendLine($"      sha256 \"{archiveHashes["linux-arm64"]}\"");
        formula.AppendLine("    else");
        formula.AppendLine($"      url \"{CreateArchiveUrl(repository, releaseTag, "linux-x64", "tar.gz")}\"");
        formula.AppendLine($"      sha256 \"{archiveHashes["linux-x64"]}\"");
        formula.AppendLine("    end");
        formula.AppendLine("  end");
        formula.AppendLine();
        formula.AppendLine("  def install");
        formula.AppendLine("    libexec.install Dir[\"*\"]");
        formula.AppendLine("    bin.write_exec_script libexec/\"picket\"");
        formula.AppendLine("    bin.write_exec_script libexec/\"picket-tui\"");
        formula.AppendLine("  end");
        formula.AppendLine();
        formula.AppendLine("  test do");
        formula.AppendLine("    system \"#{bin}/picket\", \"version\"");
        formula.AppendLine("    system \"#{bin}/picket-tui\", \"--help\"");
        formula.AppendLine("  end");
        formula.AppendLine("end");
        ScriptSupport.WriteTextFile(formulaPath, formula.ToString().TrimEnd());
        return formulaPath;
    }

    /// <summary>
    /// Writes the Scoop manifest.
    /// </summary>
    /// <param name="outputDirectory">The output directory.</param>
    /// <param name="repository">The owner/name repository.</param>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="version">The package version.</param>
    /// <param name="archiveHashes">The archive hashes keyed by RID.</param>
    /// <returns>The written file path.</returns>
    private static string WriteScoopManifest(
        string outputDirectory,
        string repository,
        string releaseTag,
        string version,
        Dictionary<string, string> archiveHashes)
    {
        string scoopDirectory = Path.Combine(outputDirectory, "scoop");
        Directory.CreateDirectory(scoopDirectory);
        string manifestPath = Path.Combine(scoopDirectory, "picket.json");
        var json = new StringBuilder();
        json.AppendLine("{");
        AppendJsonProperty(json, 2, "version", version, trailingComma: true);
        AppendJsonProperty(json, 2, "description", "Native AOT secrets scanner with Gitleaks-compatible and Picket-native modes.", trailingComma: true);
        AppendJsonProperty(json, 2, "homepage", $"https://github.com/{repository}", trailingComma: true);
        AppendJsonProperty(json, 2, "license", "MIT", trailingComma: true);
        json.AppendLine("  \"architecture\": {");
        json.AppendLine("    \"64bit\": {");
        AppendJsonProperty(json, 6, "url", CreateArchiveUrl(repository, releaseTag, "win-x64", "zip"), trailingComma: true);
        AppendJsonProperty(json, 6, "hash", archiveHashes["win-x64"], trailingComma: false);
        json.AppendLine("    },");
        json.AppendLine("    \"arm64\": {");
        AppendJsonProperty(json, 6, "url", CreateArchiveUrl(repository, releaseTag, "win-arm64", "zip"), trailingComma: true);
        AppendJsonProperty(json, 6, "hash", archiveHashes["win-arm64"], trailingComma: false);
        json.AppendLine("    }");
        json.AppendLine("  },");
        json.AppendLine("  \"bin\": [");
        json.AppendLine("    [\"picket.exe\", \"picket\"],");
        json.AppendLine("    [\"picket-tui.exe\", \"picket-tui\"]");
        json.AppendLine("  ],");
        json.AppendLine("  \"checkver\": {");
        AppendJsonProperty(json, 4, "github", $"https://github.com/{repository}", trailingComma: false);
        json.AppendLine("  },");
        json.AppendLine("  \"autoupdate\": {");
        json.AppendLine("    \"architecture\": {");
        json.AppendLine("      \"64bit\": {");
        AppendJsonProperty(json, 8, "url", $"https://github.com/{repository}/releases/download/v$version/picket-v$version-win-x64.zip", trailingComma: false);
        json.AppendLine("      },");
        json.AppendLine("      \"arm64\": {");
        AppendJsonProperty(json, 8, "url", $"https://github.com/{repository}/releases/download/v$version/picket-v$version-win-arm64.zip", trailingComma: false);
        json.AppendLine("      }");
        json.AppendLine("    }");
        json.AppendLine("  }");
        json.AppendLine("}");
        ScriptSupport.WriteTextFile(manifestPath, json.ToString().TrimEnd());
        return manifestPath;
    }

    /// <summary>
    /// Appends a JSON string property.
    /// </summary>
    /// <param name="builder">The destination builder.</param>
    /// <param name="indent">The indentation width.</param>
    /// <param name="name">The property name.</param>
    /// <param name="value">The property value.</param>
    /// <param name="trailingComma">Whether a trailing comma should be appended.</param>
    private static void AppendJsonProperty(StringBuilder builder, int indent, string name, string value, bool trailingComma)
    {
        builder.Append(' ', indent);
        AppendJsonString(builder, name);
        builder.Append(": ");
        AppendJsonString(builder, value);
        if (trailingComma)
        {
            builder.Append(',');
        }

        builder.AppendLine();
    }

    /// <summary>
    /// Appends a JSON string literal.
    /// </summary>
    /// <param name="builder">The destination builder.</param>
    /// <param name="value">The string value.</param>
    private static void AppendJsonString(StringBuilder builder, string value)
    {
        builder.Append('"');
        foreach (char ch in value)
        {
            switch (ch)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (ch < 0x20)
                    {
                        builder.Append("\\u");
                        builder.Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(ch);
                    }

                    break;
            }
        }

        builder.Append('"');
    }

    /// <summary>
    /// Writes the WinGet multiple-file manifest set.
    /// </summary>
    /// <param name="outputDirectory">The output directory.</param>
    /// <param name="repository">The owner/name repository.</param>
    /// <param name="releaseTag">The release tag.</param>
    /// <param name="version">The package version.</param>
    /// <param name="packageIdentifier">The WinGet package identifier.</param>
    /// <param name="packageName">The package display name.</param>
    /// <param name="publisher">The publisher display name.</param>
    /// <param name="publisherUrl">The publisher URL.</param>
    /// <param name="archiveHashes">The archive hashes keyed by RID.</param>
    /// <returns>The written file paths.</returns>
    private static List<string> WriteWingetManifests(
        string outputDirectory,
        string repository,
        string releaseTag,
        string version,
        string packageIdentifier,
        string packageName,
        string publisher,
        string publisherUrl,
        Dictionary<string, string> archiveHashes)
    {
        string manifestDirectory = Path.Combine(outputDirectory, "winget", packageIdentifier, version);
        Directory.CreateDirectory(manifestDirectory);
        string versionPath = Path.Combine(manifestDirectory, $"{packageIdentifier}.yaml");
        string localePath = Path.Combine(manifestDirectory, $"{packageIdentifier}.locale.en-US.yaml");
        string installerPath = Path.Combine(manifestDirectory, $"{packageIdentifier}.installer.yaml");

        ScriptSupport.WriteTextFile(
            versionPath,
            $$"""
            PackageIdentifier: {{packageIdentifier}}
            PackageVersion: {{version}}
            DefaultLocale: en-US
            ManifestType: version
            ManifestVersion: {{WingetManifestVersion}}
            """);
        ScriptSupport.WriteTextFile(
            localePath,
            $$"""
            PackageIdentifier: {{packageIdentifier}}
            PackageVersion: {{version}}
            PackageLocale: en-US
            Publisher: {{publisher}}
            PublisherUrl: {{publisherUrl}}
            PackageName: {{packageName}}
            PackageUrl: https://github.com/{{repository}}
            License: MIT
            LicenseUrl: https://github.com/{{repository}}/blob/main/LICENSE
            ShortDescription: Native AOT secrets scanner with Gitleaks-compatible and Picket-native modes.
            Tags:
            - secrets
            - secret-scanning
            - security
            - cli
            - dotnet
            ManifestType: defaultLocale
            ManifestVersion: {{WingetManifestVersion}}
            """);
        ScriptSupport.WriteTextFile(
            installerPath,
            $$"""
            PackageIdentifier: {{packageIdentifier}}
            PackageVersion: {{version}}
            MinimumOSVersion: 10.0.17763.0
            InstallerType: zip
            NestedInstallerType: portable
            Commands:
            - picket
            - picket-tui
            Installers:
            - Architecture: x64
              InstallerUrl: {{CreateArchiveUrl(repository, releaseTag, "win-x64", "zip")}}
              InstallerSha256: {{archiveHashes["win-x64"]}}
              NestedInstallerFiles:
              - RelativeFilePath: picket.exe
                PortableCommandAlias: picket
              - RelativeFilePath: picket-tui.exe
                PortableCommandAlias: picket-tui
            - Architecture: arm64
              InstallerUrl: {{CreateArchiveUrl(repository, releaseTag, "win-arm64", "zip")}}
              InstallerSha256: {{archiveHashes["win-arm64"]}}
              NestedInstallerFiles:
              - RelativeFilePath: picket.exe
                PortableCommandAlias: picket
              - RelativeFilePath: picket-tui.exe
                PortableCommandAlias: picket-tui
            ManifestType: installer
            ManifestVersion: {{WingetManifestVersion}}
            """);

        return [versionPath, localePath, installerPath];
    }
}
