using Hex1b;
using Hex1b.Automation;
using Hex1b.Input;
using Hex1b.Theming;
using Picket.Report;
using Picket.Tui;

namespace Picket.Tests;

/// <summary>
/// Tests the interactive report triage console state and accessibility contract.
/// </summary>
[TestClass]
public sealed class PicketTuiTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that the TUI state filters rows and keeps focused findings addressable by key.
    /// </summary>
    [TestMethod]
    public void StateFiltersRowsAndTracksFocusedFinding()
    {
        PicketTuiState state = CreateState();

        Assert.HasCount(3, state.VisibleRows);
        Assert.AreEqual("github-token", state.FocusedFinding?.RuleId);

        state.SetSearchText("infra");

        Assert.HasCount(1, state.VisibleRows);
        Assert.AreEqual("aws-key", state.VisibleRows[0].RuleId);

        state.FocusFinding(state.VisibleRows[0].Key);

        Assert.AreEqual("infra/main.tf", state.FocusedFinding?.Path);

        state.ClearSearch();

        Assert.HasCount(3, state.VisibleRows);
    }

    /// <summary>
    /// Verifies that the top rule and file summaries sort by finding count, then by key.
    /// </summary>
    [TestMethod]
    public void StateBuildsDeterministicTopLists()
    {
        PicketTuiState state = CreateState();

        List<KeyValuePair<string, int>> rules = state.GetTopRules(2);
        List<KeyValuePair<string, int>> files = state.GetTopFiles(2);

        Assert.HasCount(2, rules);
        Assert.HasCount(2, files);
        Assert.AreEqual("github-token", rules[0].Key);
        Assert.AreEqual(2, rules[0].Value);
        Assert.AreEqual("src/auth.cs", files[0].Key);
        Assert.AreEqual(2, files[0].Value);
    }

    /// <summary>
    /// Verifies that the scanner-console palette satisfies the terminal-adapted WCAG contrast thresholds.
    /// </summary>
    [TestMethod]
    public void AccessibilityPaletteMeetsContrastThresholds()
    {
        AssertTextContrast(PicketTuiAccessibilityPalette.Foreground, PicketTuiAccessibilityPalette.Background);
        AssertTextContrast(PicketTuiAccessibilityPalette.Foreground, PicketTuiAccessibilityPalette.PanelBackground);
        AssertTextContrast(PicketTuiAccessibilityPalette.MutedForeground, PicketTuiAccessibilityPalette.Background);
        AssertTextContrast(PicketTuiAccessibilityPalette.ErrorForeground, PicketTuiAccessibilityPalette.Background);
        AssertTextContrast(PicketTuiAccessibilityPalette.WarningForeground, PicketTuiAccessibilityPalette.Background);
        AssertTextContrast(PicketTuiAccessibilityPalette.FocusForeground, PicketTuiAccessibilityPalette.FocusBackground);
        AssertUiContrast(PicketTuiAccessibilityPalette.Border, PicketTuiAccessibilityPalette.Background);
        AssertUiContrast(PicketTuiAccessibilityPalette.FocusBackground, PicketTuiAccessibilityPalette.Background);
    }

    /// <summary>
    /// Verifies that the full-screen scanner console renders through Hex1b and exits through its keyboard binding.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersDashboardAndExits()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Dashboard"), TimeSpan.FromSeconds(5), "dashboard to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string screenText = snapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("Picket", screenText);
        Assert.Contains("Dashboard", screenText);
        Assert.Contains("Top rules", screenText);
        Assert.Contains("github-token", screenText);
        Assert.Contains("src/auth.cs", screenText);
    }

    /// <summary>
    /// Verifies that the scanner console remains useful in a narrow terminal and exposes the accessibility view through Hex1b input.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleHandlesNarrowTerminalAndKeyboardNavigation()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 80, height: 24);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Dashboard"), TimeSpan.FromSeconds(5), "dashboard to render")
            .Key(Hex1bKey.F1)
            .WaitUntil(s => s.ContainsText("Accessibility Contract"), TimeSpan.FromSeconds(5), "accessibility view to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string screenText = snapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("Accessibility Contract", screenText);
        Assert.Contains("WCAG 2.2 AA", screenText);
        Assert.Contains("Keyboard", screenText);
        Assert.Contains("F1", screenText);
    }

    private static PicketTuiState CreateState()
    {
        var summary = new ReportSummary(
            "picket-json",
            [
                new ReportFindingSummary("github-token", "src/auth.cs", 12, "fp-auth-1"),
                new ReportFindingSummary("github-token", "src/auth.cs", 18, "fp-auth-2"),
                new ReportFindingSummary("aws-key", "infra/main.tf", 4, "fp-infra-1"),
            ]);

        return new PicketTuiState(new PicketTuiReport("report.json", summary, DateTimeOffset.UnixEpoch));
    }

    private static Hex1bTerminal CreateHeadlessTerminal(PicketTuiState state, int width, int height)
    {
        return Hex1bTerminal.CreateBuilder()
            .WithHex1bApp(
                options =>
                {
                    options.EnableMouse = true;
                    options.Theme = PicketTuiAccessibilityPalette.CreateTheme();
                },
                ctx => PicketTuiApp.Build(ctx, state))
            .WithHeadless()
            .WithDimensions(width, height)
            .Build();
    }

    private static void AssertTextContrast(Hex1bColor foreground, Hex1bColor background)
    {
        double ratio = PicketTuiAccessibilityPalette.ContrastRatio(foreground, background);
        Assert.IsGreaterThanOrEqualTo(PicketTuiAccessibilityPalette.TextContrastMinimum, ratio);
    }

    private static void AssertUiContrast(Hex1bColor foreground, Hex1bColor background)
    {
        double ratio = PicketTuiAccessibilityPalette.ContrastRatio(foreground, background);
        Assert.IsGreaterThanOrEqualTo(PicketTuiAccessibilityPalette.UiContrastMinimum, ratio);
    }
}
