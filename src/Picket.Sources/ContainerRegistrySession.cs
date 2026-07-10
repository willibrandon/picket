namespace Picket.Sources;

/// <summary>
/// Holds per-enumeration registry state so a source client remains safe for concurrent callers.
/// </summary>
internal sealed class ContainerRegistrySession(ContainerRegistrySourceOptions options)
{
    internal ContainerRegistrySourceOptions Options { get; } = options;

    internal string BearerToken { get; set; } = options.CredentialKind == ContainerRegistryCredentialKind.BearerToken
        ? options.Credential
        : string.Empty;

    internal long DownloadedBytes { get; set; }

    internal int ExtractedEntryCount { get; set; }

    internal long ExtractedByteCount { get; set; }

    internal string BaseDisplayPath { get; set; } = string.Empty;

    internal Dictionary<string, byte[]> BlobContent { get; } = new(StringComparer.OrdinalIgnoreCase);

    internal HashSet<string> ExpandedLayerDigests { get; } = new(StringComparer.OrdinalIgnoreCase);

    internal HashSet<string> ManifestDigests { get; } = new(StringComparer.OrdinalIgnoreCase);

    internal HashSet<string> ReportedRegistryWarnings { get; } = new(StringComparer.Ordinal);

    internal HashSet<string> SourceDisplayPaths { get; } = new(StringComparer.Ordinal);

    internal List<SourceFile> Files { get; } = [];
}
