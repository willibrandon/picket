namespace Picket.Tui;

/// <summary>
/// Executes a scan requested by the terminal UI.
/// </summary>
internal interface IPicketTuiScanExecutor
{
    /// <summary>
    /// Runs the scanner with the supplied command arguments.
    /// </summary>
    /// <param name="arguments">The arguments after the `picket` executable name.</param>
    /// <param name="reportPath">The report path the scan command should write.</param>
    /// <param name="output">The live scanner output callback.</param>
    /// <param name="cancellationToken">A token that can cancel the scan process.</param>
    /// <returns>The scanner process result.</returns>
    ValueTask<PicketTuiScanExecutionResult> RunAsync(
        IReadOnlyList<string> arguments,
        string reportPath,
        Action<PicketTuiScanOutputEvent> output,
        CancellationToken cancellationToken);
}
