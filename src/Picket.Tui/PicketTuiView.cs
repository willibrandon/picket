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
    /// Accessibility contract view.
    /// </summary>
    Accessibility,

    /// <summary>
    /// Session diagnostics view.
    /// </summary>
    Logs,
}
