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
