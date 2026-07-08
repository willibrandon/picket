namespace Picket.Tui;

/// <summary>
/// Identifies the active option group in the scan workspace.
/// </summary>
internal enum PicketTuiScanSection
{
    /// <summary>
    /// Target and source-host selector fields.
    /// </summary>
    Target,

    /// <summary>
    /// Report, format, profile, config, and verification fields.
    /// </summary>
    Output,

    /// <summary>
    /// Ignore and validation-result filter fields.
    /// </summary>
    Rules,

    /// <summary>
    /// Target, archive, and timeout limit fields.
    /// </summary>
    Limits,
}
