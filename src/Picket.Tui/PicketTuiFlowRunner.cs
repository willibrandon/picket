using Hex1b;
using Hex1b.Flow;
using Hex1b.Input;
using Hex1b.Widgets;

namespace Picket.Tui;

/// <summary>
/// Runs the report triage workflow as inline Hex1b Flow steps.
/// </summary>
internal static class PicketTuiFlowRunner
{
    private const int ReportPathStepHeight = 4;
    private const int ReviewStepHeight = 8;
    private static readonly string[] s_reviewActions =
    [
        "Open full-screen scanner console",
        "Keep summary in scrollback",
    ];

    /// <summary>
    /// Runs the inline report triage flow.
    /// </summary>
    /// <param name="reportPath">The optional report path. When omitted, the flow prompts for it.</param>
    /// <param name="cancellationToken">A token used to cancel the flow.</param>
    /// <returns>The process-style exit code.</returns>
    internal static async Task<int> RunAsync(string? reportPath, CancellationToken cancellationToken = default)
    {
        int? cursorRow = TryGetCursorRow();
        bool flowCanceled = false;
        int flowExitCode = 0;
        string selectedReportPath = reportPath ?? string.Empty;

        await using Hex1bTerminal terminal = Hex1bTerminal.CreateBuilder()
            .WithScrollback()
            .WithHex1bFlow(async flow =>
            {
                if (selectedReportPath.Length == 0)
                {
                    bool reportPathSubmitted = false;
                    FlowStep pathStep = flow.Step(ctx => ctx.VStack(v => [
                        v.Text("Report path"),
                        v.TextBox(selectedReportPath)
                            .OnTextChanged(e => selectedReportPath = e.NewText)
                            .OnSubmit(e =>
                            {
                                reportPathSubmitted = true;
                                selectedReportPath = e.Text;
                                ctx.Step.Complete(y => y.Text(CreateReportPathPromptResult(selectedReportPath)));
                            })
                            .FillWidth(),
                    ]).ExitFlowOnCtrlC(() => flowCanceled = true, ctx), options => options.MaxHeight = ReportPathStepHeight);

                    await pathStep.WaitForCompletionAsync(flow.CancellationToken).ConfigureAwait(false);
                    if (flowCanceled)
                    {
                        flowExitCode = 130;
                        await flow.ShowAsync(ctx => ctx.Text("Canceled.")).ConfigureAwait(false);
                        return;
                    }

                    if (!reportPathSubmitted)
                    {
                        flowExitCode = 130;
                        await flow.ShowAsync(ctx => ctx.Text("Canceled.")).ConfigureAwait(false);
                        return;
                    }
                }

                if (string.IsNullOrWhiteSpace(selectedReportPath))
                {
                    flowExitCode = 126;
                    await flow.ShowAsync(ctx => ctx.Text("Report path is required.")).ConfigureAwait(false);
                    return;
                }

                PicketTuiState state = PicketTuiRunner.LoadState(selectedReportPath);
                await flow.ShowAsync(ctx => ctx.Border(b => [
                    b.Text("Picket scan report"),
                    b.Separator(),
                    b.Text(state.GetSummaryLine()),
                    b.Text(string.Concat("Report: ", state.Report.Path)).Ellipsis(),
                ]).Title("Summary")).ConfigureAwait(false);

                int selectedAction = 1;
                FlowStep reviewStep = flow.Step(ctx => ctx.VStack(v => [
                    v.Text("Next step"),
                    v.List(s_reviewActions)
                        .OnFocusChanged(e => selectedAction = e.FocusedIndex)
                        .OnItemActivated(e =>
                        {
                            selectedAction = e.ActivatedIndex;
                            ctx.Step.Complete(y => y.Text(e.ActivatedText));
                        })
                        .FixedHeight(3),
                    v.Text("Every action is keyboard reachable; color is never the only signal.").Wrap(),
                ]).ExitFlowOnCtrlC(() => flowCanceled = true, ctx), options => options.MaxHeight = ReviewStepHeight);

                await reviewStep.WaitForCompletionAsync(flow.CancellationToken).ConfigureAwait(false);
                if (flowCanceled)
                {
                    flowExitCode = 130;
                    await flow.ShowAsync(ctx => ctx.Text("Canceled.")).ConfigureAwait(false);
                    return;
                }

                if (selectedAction == 0)
                {
                    await flow.FullScreenStepAsync((_, options) =>
                    {
                        options.EnableMouse = true;
                        options.Theme = PicketTuiPalette.CreateTheme();
                        return ctx => PicketTuiApp.Build(ctx, state);
                    }).ConfigureAwait(false);
                }

                await flow.ShowAsync(ctx => ctx.Text(string.Concat("Done: ", state.GetSummaryLine()))).ConfigureAwait(false);
            }, options =>
            {
                options.EnableMouse = true;
                options.InitialCursorRow = cursorRow;
                options.Theme = PicketTuiPalette.CreateTheme();
                options.UseSoftWrapTombstones = true;
            })
            .Build();

        int terminalExitCode = await terminal.RunAsync(cancellationToken).ConfigureAwait(false);
        return terminalExitCode == 0 ? flowExitCode : terminalExitCode;
    }

    private static string CreateReportPathPromptResult(string reportPath)
    {
        return string.IsNullOrWhiteSpace(reportPath)
            ? "Report path is required."
            : string.Concat("Report: ", reportPath);
    }

    private static TWidget ExitFlowOnCtrlC<TWidget>(this TWidget widget, Action cancel, FlowStepContext ctx)
        where TWidget : Hex1bWidget
    {
        return widget.InputBindings(bindings =>
        {
            bindings.Ctrl().Key(Hex1bKey.C).Action(_ =>
            {
                cancel();
                ctx.Step.Complete();
            }, "Cancel");
        });
    }

    private static int? TryGetCursorRow()
    {
        try
        {
            return Console.GetCursorPosition().Top;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            return null;
        }
    }
}
