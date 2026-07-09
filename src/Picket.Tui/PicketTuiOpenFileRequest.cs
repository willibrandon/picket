namespace Picket.Tui;

/// <summary>
/// Describes a local file-open request that should run after the full-screen terminal has stopped.
/// </summary>
/// <param name="Path">The local file path to open.</param>
/// <param name="Line">The optional one-based line number.</param>
/// <param name="Column">The optional one-based column number.</param>
/// <param name="ReturnFocusTarget">The control that should regain focus when the TUI resumes.</param>
internal readonly record struct PicketTuiOpenFileRequest(
    string Path,
    int? Line,
    int? Column,
    PicketTuiFocusTarget ReturnFocusTarget);
