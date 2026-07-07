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
        await using Hex1bTerminal terminal = Hex1bTerminal.CreateBuilder()
            .WithHex1bApp(
                options =>
                {
                    options.EnableMouse = true;
                    options.Theme = PicketTuiAccessibilityPalette.CreateTheme();
                },
                ctx => PicketTuiApp.Build(ctx, state))
            .Build();

        return await terminal.RunAsync(cancellationToken).ConfigureAwait(false);
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
}
