namespace Picket.Store;

/// <summary>
/// Describes how native scan-cache entries are addressed for a blob.
/// </summary>
public enum ScanCacheAddressMode
{
    /// <summary>
    /// Address entries by source content, logical path, and scanner key.
    /// </summary>
    Path,

    /// <summary>
    /// Address entries by source content, file extension, and scanner key.
    /// </summary>
    FileExtension,

    /// <summary>
    /// Address entries only by source content and scanner key.
    /// </summary>
    Content,
}
