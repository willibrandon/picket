namespace Picket.Store;

/// <summary>
/// Describes how finding evidence is stored in native scan-cache entries.
/// </summary>
public enum ScanCacheStorageMode
{
    /// <summary>
    /// Store secret and match hashes without raw match, secret, or line text.
    /// </summary>
    SecretHashOnly,

    /// <summary>
    /// Store raw match, secret, and line text so cached reports can replay scan output exactly.
    /// </summary>
    Raw,
}
