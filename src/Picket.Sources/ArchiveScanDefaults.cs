namespace Picket.Sources;

/// <summary>
/// Defines the default safety limits used when archive traversal is enabled.
/// </summary>
public static class ArchiveScanDefaults
{
    /// <summary>
    /// The default nested archive traversal depth.
    /// </summary>
    public const int DefaultMaxDepth = 1;

    /// <summary>
    /// The default maximum number of archive entries to enumerate.
    /// </summary>
    public const int DefaultMaxEntries = 4096;

    /// <summary>
    /// The default maximum number of decompressed archive bytes to enumerate.
    /// </summary>
    public const long DefaultMaxBytes = 512_000_000;

    /// <summary>
    /// The default maximum archive expansion ratio.
    /// </summary>
    public const int DefaultMaxCompressionRatio = 1000;
}
