namespace Picket.Tui;

/// <summary>
/// Describes a local file-open request that should run after the full-screen terminal has stopped.
/// </summary>
/// <param name="Path">The local file path to open.</param>
/// <param name="Line">The optional one-based line number.</param>
internal readonly record struct PicketTuiOpenFileRequest(string Path, int? Line);
