namespace Picket.Tui;

/// <summary>
/// Opens local files selected from the terminal UI.
/// </summary>
internal interface IPicketTuiFileLauncher
{
    /// <summary>
    /// Attempts to open a local file.
    /// </summary>
    /// <param name="path">The report path to open.</param>
    /// <param name="line">The optional one-based line number.</param>
    /// <param name="column">The optional one-based column number.</param>
    /// <param name="message">The user-facing status message.</param>
    /// <returns><see langword="true" /> when the file was opened.</returns>
    bool TryOpen(string path, int? line, int? column, out string message);
}
