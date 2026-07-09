using Hex1b;
using Picket.Report;

namespace Picket.Tui;

/// <summary>
/// Runs the full-screen Picket report triage console.
/// </summary>
internal static class PicketTuiRunner
{
    /// <summary>
    /// Runs the full-screen report triage console.
    /// </summary>
    /// <param name="reportPath">The report path to load.</param>
    /// <param name="cancellationToken">A token used to cancel the console.</param>
    /// <returns>The process-style exit code.</returns>
    internal static async Task<int> RunAsync(string reportPath, CancellationToken cancellationToken = default)
    {
        PicketTuiState state = LoadState(reportPath);
        return await RunTerminalLoopAsync(state, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the full-screen scan workspace.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the console.</param>
    /// <returns>The process-style exit code.</returns>
    internal static async Task<int> RunScanWorkspaceAsync(CancellationToken cancellationToken = default)
    {
        PicketTuiState state = CreateScanWorkspaceState();
        state.SetView(PicketTuiView.Scan);
        return await RunTerminalLoopAsync(state, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Loads report state for the terminal UI.
    /// </summary>
    /// <param name="reportPath">The report path to load.</param>
    /// <returns>The initialized TUI state.</returns>
    internal static PicketTuiState LoadState(string reportPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);

        ReportSummary summary = ReportSummaryReader.Read(reportPath);
        return new PicketTuiState(new PicketTuiReport(
            Path.GetFullPath(reportPath),
            summary,
            DateTimeOffset.UtcNow));
    }

    private static PicketTuiState CreateScanWorkspaceState()
    {
        var state = new PicketTuiState(new PicketTuiReport(
            "picket-tui-scan",
            new ReportSummary("picket-jsonl", []),
            DateTimeOffset.UtcNow));
        state.TryLoadPreviousScanReport();
        state.SetView(PicketTuiView.Scan);
        return state;
    }

    private static Hex1bTerminal CreateTerminal(PicketTuiState state)
    {
        return Hex1bTerminal.CreateBuilder()
            .WithHex1bApp(
                options =>
                {
                    options.EnableMouse = true;
                    options.Theme = PicketTuiPalette.CreateTheme();
                },
                app => ctx => PicketTuiApp.Build(ctx, state, app))
            .Build();
    }

    private static async Task<int> RunTerminalLoopAsync(PicketTuiState state, CancellationToken cancellationToken)
    {
        while (true)
        {
            int exitCode;
            await using (Hex1bTerminal terminal = CreateTerminal(state))
            {
                exitCode = await terminal.RunAsync(cancellationToken).ConfigureAwait(false);
            }

            if (!state.TryOpenPendingFile())
            {
                return exitCode;
            }
        }
    }
}
