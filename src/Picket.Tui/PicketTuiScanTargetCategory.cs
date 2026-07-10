namespace Picket.Tui;

/// <summary>
/// Identifies the target family selected in the terminal scan workspace.
/// </summary>
internal enum PicketTuiScanTargetCategory
{
    /// <summary>
    /// Local filesystem scans.
    /// </summary>
    Local,

    /// <summary>
    /// Source host scans.
    /// </summary>
    SourceHost,

    /// <summary>
    /// Object storage scans.
    /// </summary>
    ObjectStore,

    /// <summary>
    /// Container image archive scans.
    /// </summary>
    Archive,
}
