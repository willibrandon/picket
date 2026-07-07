namespace Picket.Tui;

/// <summary>
/// Identifies a scanner-console view.
/// </summary>
internal enum PicketTuiView
{
    /// <summary>
    /// Summary dashboard view.
    /// </summary>
    Dashboard,

    /// <summary>
    /// Native scan workspace view.
    /// </summary>
    Scan,

    /// <summary>
    /// Findings table and detail view.
    /// </summary>
    Findings,

    /// <summary>
    /// Rule frequency view.
    /// </summary>
    Rules,

    /// <summary>
    /// File frequency view.
    /// </summary>
    Files,

    /// <summary>
    /// Session diagnostics view.
    /// </summary>
    Logs,
}
