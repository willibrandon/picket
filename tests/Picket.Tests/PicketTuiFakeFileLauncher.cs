using Picket.Tui;

namespace Picket.Tests;

/// <summary>
/// Captures file-open requests from the TUI without launching an external process.
/// </summary>
internal sealed class PicketTuiFakeFileLauncher : IPicketTuiFileLauncher
{
    /// <summary>
    /// Gets the captured path.
    /// </summary>
    internal string CapturedPath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the captured line number.
    /// </summary>
    internal int? CapturedLine { get; private set; }

    /// <summary>
    /// Gets or sets a value indicating whether the open request succeeds.
    /// </summary>
    internal bool Result { get; set; } = true;

    /// <summary>
    /// Gets or sets the status message returned to the TUI.
    /// </summary>
    internal string Message { get; set; } = "Opened test file";

    /// <inheritdoc />
    public bool TryOpen(string path, int? line, out string message)
    {
        CapturedPath = path;
        CapturedLine = line;
        message = Message;
        return Result;
    }
}
