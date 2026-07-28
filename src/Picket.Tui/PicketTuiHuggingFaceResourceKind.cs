namespace Picket.Tui;

/// <summary>
/// Identifies the Hugging Face resource selected in the terminal UI.
/// </summary>
internal enum PicketTuiHuggingFaceResourceKind
{
    /// <summary>
    /// Scan a model repository.
    /// </summary>
    Model = 0,

    /// <summary>
    /// Scan a dataset repository.
    /// </summary>
    Dataset = 1,

    /// <summary>
    /// Scan a Space repository.
    /// </summary>
    Space = 2,

    /// <summary>
    /// Scan a storage bucket.
    /// </summary>
    Bucket = 3,
}
