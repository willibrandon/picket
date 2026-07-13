#!/usr/bin/env -S dotnet --
#:property TargetFramework=net10.0
#:property PackAsTool=false
#:include ScriptSupport.cs

using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

try
{
    return ValidateMarketplaceReleaseApp.Run(args);
}
catch (Exception ex) when (ex is ArgumentException or InvalidDataException or IOException or JsonException or UnauthorizedAccessException or XmlException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

/// <summary>
/// Validates an Azure DevOps Marketplace release package and its checksum.
/// </summary>
internal static class ValidateMarketplaceReleaseApp
{
    /// <summary>
    /// Maximum accepted VSIX entry count.
    /// </summary>
    private const int MaxEntryCount = 1_024;

    /// <summary>
    /// Maximum accepted aggregate uncompressed VSIX size.
    /// </summary>
    private const long MaxUncompressedBytes = 100_000_000;

    /// <summary>
    /// Maximum accepted metadata document size.
    /// </summary>
    private const int MaxMetadataBytes = 1_000_000;

    /// <summary>
    /// Files that every publishable Picket VSIX must contain.
    /// </summary>
    private static readonly string[] s_requiredEntries =
    [
        "CHANGELOG.md",
        "COMPATIBILITY.md",
        "LICENSE",
        "PRIVACY.md",
        "README.md",
        "extension.vsixmanifest",
        "images/extension-icon.png",
        "tasks/PicketScanV1/icon.png",
        "tasks/PicketScanV1/index.js",
        "tasks/PicketScanV1/task.json",
    ];

    /// <summary>
    /// Runs Marketplace release validation.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    internal static int Run(string[] args)
    {
        (Dictionary<string, List<string>> values, _) = ScriptSupport.ParseArguments(
            args,
            ["ReleaseTag", "VsixPath", "ChecksumPath"],
            [],
            []);

        string releaseTag = RequireValue(
            ScriptSupport.GetString(values, "ReleaseTag", Environment.GetEnvironmentVariable("RELEASE_TAG") ?? string.Empty),
            "ReleaseTag");
        string version = ParseStableVersion(releaseTag);
        string vsixPath = RequireFile(ScriptSupport.GetString(values, "VsixPath"), "VsixPath");
        string checksumPath = RequireFile(ScriptSupport.GetString(values, "ChecksumPath", string.Concat(vsixPath, ".sha256")), "ChecksumPath");

        ValidateChecksum(vsixPath, checksumPath);
        (string extensionVersion, string taskVersion) = ValidateVsix(vsixPath, version);

        Console.Out.WriteLine($"release tag: {releaseTag}");
        Console.Out.WriteLine($"extension: willibrandon.picket {extensionVersion}");
        Console.Out.WriteLine($"task: PicketScan@{taskVersion}");
        Console.Out.WriteLine($"sha256: {ScriptSupport.GetFileSha256(vsixPath)}");
        return 0;
    }

    /// <summary>
    /// Parses a stable release tag and returns its semantic version.
    /// </summary>
    /// <param name="releaseTag">The release tag.</param>
    /// <returns>The version without its leading <c>v</c>.</returns>
    private static string ParseStableVersion(string releaseTag)
    {
        if (!releaseTag.StartsWith('v'))
        {
            throw new InvalidDataException($"Release tag '{releaseTag}' must start with 'v'.");
        }

        string version = releaseTag[1..];
        string[] components = version.Split('.');
        if (components.Length != 3)
        {
            throw new InvalidDataException($"Release tag '{releaseTag}' must be a stable vMAJOR.MINOR.PATCH tag.");
        }

        for (int i = 0; i < components.Length; i++)
        {
            if (!int.TryParse(components[i], NumberStyles.None, CultureInfo.InvariantCulture, out int value)
                || value.ToString(CultureInfo.InvariantCulture) != components[i])
            {
                throw new InvalidDataException($"Release tag '{releaseTag}' must use canonical non-negative numeric components.");
            }
        }

        return version;
    }

    /// <summary>
    /// Validates the checksum sidecar against the named VSIX.
    /// </summary>
    /// <param name="vsixPath">The VSIX path.</param>
    /// <param name="checksumPath">The checksum sidecar path.</param>
    private static void ValidateChecksum(string vsixPath, string checksumPath)
    {
        string[] lines = [.. File.ReadLines(checksumPath).Where(line => !string.IsNullOrWhiteSpace(line))];
        if (lines.Length != 1)
        {
            throw new InvalidDataException($"Checksum file '{checksumPath}' must contain exactly one non-empty line.");
        }

        string line = lines[0].Trim();
        int separatorIndex = line.IndexOfAny(' ', '\t');
        if (separatorIndex <= 0)
        {
            throw new InvalidDataException($"Checksum file '{checksumPath}' does not use the '<sha256>  <file>' format.");
        }

        string expectedHash = line[..separatorIndex];
        if (expectedHash.Length != 64 || expectedHash.Any(c => !char.IsAsciiHexDigit(c)))
        {
            throw new InvalidDataException($"Checksum file '{checksumPath}' does not contain a SHA-256 hash.");
        }

        string expectedFileName = line[(separatorIndex + 1)..].TrimStart();
        if (expectedFileName.StartsWith('*'))
        {
            expectedFileName = expectedFileName[1..];
        }

        string actualFileName = Path.GetFileName(vsixPath);
        if (!expectedFileName.Equals(actualFileName, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"Checksum file names '{expectedFileName}', but the VSIX is '{actualFileName}'.");
        }

        string actualHash = ScriptSupport.GetFileSha256(vsixPath);
        if (!expectedHash.Equals(actualHash, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException($"Checksum verification failed for '{actualFileName}'.");
        }
    }

    /// <summary>
    /// Validates VSIX structure and metadata.
    /// </summary>
    /// <param name="vsixPath">The VSIX path.</param>
    /// <param name="expectedVersion">The expected extension version.</param>
    /// <returns>The extension and task versions.</returns>
    private static (string ExtensionVersion, string TaskVersion) ValidateVsix(string vsixPath, string expectedVersion)
    {
        using ZipArchive archive = ZipFile.OpenRead(vsixPath);
        if (archive.Entries.Count > MaxEntryCount)
        {
            throw new InvalidDataException($"VSIX '{vsixPath}' contains more than {MaxEntryCount} entries.");
        }

        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
        long totalBytes = 0;
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            if (entry.FullName.Contains('\\', StringComparison.Ordinal)
                || entry.FullName.StartsWith('/')
                || entry.FullName.Split('/').Contains("..", StringComparer.Ordinal))
            {
                throw new InvalidDataException($"VSIX entry '{entry.FullName}' is not a safe package path.");
            }

            if (!entries.TryAdd(entry.FullName, entry))
            {
                throw new InvalidDataException($"VSIX contains duplicate entry '{entry.FullName}'.");
            }

            if (entry.Length > MaxUncompressedBytes - totalBytes)
            {
                throw new InvalidDataException($"VSIX exceeds the {MaxUncompressedBytes} byte uncompressed limit.");
            }

            totalBytes += entry.Length;
        }

        foreach (string requiredEntry in s_requiredEntries)
        {
            if (!entries.ContainsKey(requiredEntry))
            {
                throw new InvalidDataException($"VSIX is missing required entry '{requiredEntry}'.");
            }
        }

        string extensionVersion = ValidateExtensionManifest(entries["extension.vsixmanifest"], expectedVersion);
        string taskVersion = ValidateTaskMetadata(entries["tasks/PicketScanV1/task.json"]);
        ValidatePng(entries["images/extension-icon.png"], 128, 128);
        ValidatePng(entries["tasks/PicketScanV1/icon.png"], 32, 32);
        return (extensionVersion, taskVersion);
    }

    /// <summary>
    /// Validates the generated VSIX identity.
    /// </summary>
    /// <param name="entry">The extension manifest entry.</param>
    /// <param name="expectedVersion">The expected extension version.</param>
    /// <returns>The extension version.</returns>
    private static string ValidateExtensionManifest(ZipArchiveEntry entry, string expectedVersion)
    {
        using Stream stream = OpenBoundedEntry(entry);
        XDocument manifest = XDocument.Load(stream, LoadOptions.None);
        XElement[] identities = [.. manifest.Descendants().Where(element => element.Name.LocalName.Equals("Identity", StringComparison.Ordinal))];
        if (identities.Length != 1)
        {
            throw new InvalidDataException("VSIX extension manifest must contain exactly one Identity element.");
        }

        XElement identity = identities[0];
        string id = identity.Attribute("Id")?.Value ?? string.Empty;
        string publisher = identity.Attribute("Publisher")?.Value ?? string.Empty;
        string version = identity.Attribute("Version")?.Value ?? string.Empty;

        if (!id.Equals("picket", StringComparison.Ordinal)
            || !publisher.Equals("willibrandon", StringComparison.Ordinal)
            || !version.Equals(expectedVersion, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"VSIX identity is '{publisher}.{id} {version}', expected 'willibrandon.picket {expectedVersion}'.");
        }

        return version;
    }

    /// <summary>
    /// Validates packaged Azure Pipelines task metadata.
    /// </summary>
    /// <param name="entry">The task metadata entry.</param>
    /// <returns>The task major, minor, and patch version.</returns>
    private static string ValidateTaskMetadata(ZipArchiveEntry entry)
    {
        using Stream stream = OpenBoundedEntry(entry);
        using JsonDocument document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 64 });
        JsonElement root = document.RootElement;
        if (!root.TryGetProperty("name", out JsonElement name)
            || !string.Equals(name.GetString(), "PicketScan", StringComparison.Ordinal))
        {
            throw new InvalidDataException("VSIX task metadata does not describe PicketScan.");
        }

        if (!root.TryGetProperty("version", out JsonElement version)
            || !version.TryGetProperty("Major", out JsonElement majorElement)
            || !majorElement.TryGetInt32(out int major)
            || !version.TryGetProperty("Minor", out JsonElement minorElement)
            || !minorElement.TryGetInt32(out int minor)
            || !version.TryGetProperty("Patch", out JsonElement patchElement)
            || !patchElement.TryGetInt32(out int patch)
            || major != 1
            || minor < 0
            || patch < 0)
        {
            throw new InvalidDataException("VSIX task version is not in the supported PicketScan@1 line.");
        }

        return $"{major}.{minor}.{patch}";
    }

    /// <summary>
    /// Validates a packaged PNG's dimensions.
    /// </summary>
    /// <param name="entry">The PNG entry.</param>
    /// <param name="expectedWidth">The expected width.</param>
    /// <param name="expectedHeight">The expected height.</param>
    private static void ValidatePng(ZipArchiveEntry entry, int expectedWidth, int expectedHeight)
    {
        Span<byte> header = stackalloc byte[24];
        using Stream stream = entry.Open();
        stream.ReadExactly(header);
        ReadOnlySpan<byte> pngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
        int width = BinaryPrimitives.ReadInt32BigEndian(header[16..20]);
        int height = BinaryPrimitives.ReadInt32BigEndian(header[20..24]);
        if (!header[..pngSignature.Length].SequenceEqual(pngSignature)
            || !header[12..16].SequenceEqual("IHDR"u8)
            || width != expectedWidth
            || height != expectedHeight)
        {
            throw new InvalidDataException($"VSIX entry '{entry.FullName}' must be a {expectedWidth}-by-{expectedHeight} PNG.");
        }
    }

    /// <summary>
    /// Opens a metadata entry after applying its size limit.
    /// </summary>
    /// <param name="entry">The metadata entry.</param>
    /// <returns>The entry stream.</returns>
    private static Stream OpenBoundedEntry(ZipArchiveEntry entry)
    {
        if (entry.Length > MaxMetadataBytes)
        {
            throw new InvalidDataException($"VSIX metadata entry '{entry.FullName}' exceeds {MaxMetadataBytes} bytes.");
        }

        return entry.Open();
    }

    /// <summary>
    /// Requires a non-empty option value.
    /// </summary>
    /// <param name="value">The option value.</param>
    /// <param name="name">The option name.</param>
    /// <returns>The trimmed value.</returns>
    private static string RequireValue(string value, string name)
    {
        value = value.Trim();
        if (value.Length == 0)
        {
            throw new ArgumentException($"{name} is required.");
        }

        return value;
    }

    /// <summary>
    /// Requires a file option to identify an existing file.
    /// </summary>
    /// <param name="value">The option value.</param>
    /// <param name="name">The option name.</param>
    /// <returns>The absolute file path.</returns>
    private static string RequireFile(string value, string name)
    {
        string path = Path.GetFullPath(RequireValue(value, name));
        return File.Exists(path) ? path : throw new FileNotFoundException($"{name} file '{path}' does not exist.", path);
    }
}
