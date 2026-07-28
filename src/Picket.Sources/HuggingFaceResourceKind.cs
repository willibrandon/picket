namespace Picket.Sources;

/// <summary>
/// Identifies a Hugging Face resource that can be scanned.
/// </summary>
public enum HuggingFaceResourceKind
{
    /// <summary>
    /// A model repository.
    /// </summary>
    Model,

    /// <summary>
    /// A dataset repository.
    /// </summary>
    Dataset,

    /// <summary>
    /// A Space repository.
    /// </summary>
    Space,

    /// <summary>
    /// A storage bucket.
    /// </summary>
    Bucket,
}
