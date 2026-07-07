using Hex1b;
using Hex1b.Input;
using Hex1b.Layout;
using Hex1b.Widgets;
using System.Globalization;

namespace Picket.Tui;

/// <summary>
/// Builds the full-screen scanner-console widget tree for Picket report triage.
/// </summary>
internal static class PicketTuiApp
{
    private const int DetailLimit = 180;
    private const int TopListLimit = 8;

    /// <summary>
    /// Builds the root widget for the scanner console.
    /// </summary>
    /// <param name="ctx">The Hex1b root context.</param>
    /// <param name="state">The mutable TUI state for the current report.</param>
    /// <returns>The root Hex1b widget.</returns>
    internal static Hex1bWidget Build(RootContext ctx, PicketTuiState state)
    {
        return ctx.ThemePanel(
            PicketTuiAccessibilityPalette.Apply,
            ctx.VStack(main => [
                BuildMenu(main, state),
                main.HSplitter(
                    left => [BuildNavigation(left, state)],
                    right => [BuildMainArea(right, state)],
                    leftWidth: 24).Fill(),
                BuildInfoBar(main, state)
            ]).InputBindings(bindings =>
            {
                bindings.Ctrl().Key(Hex1bKey.Q).Action(context => context.RequestStop(), "Quit");
                bindings.Key(Hex1bKey.Escape).Action(_ => state.ClearSearch(), "Clear filter");
                bindings.Key(Hex1bKey.F1).Action(_ => state.SetView(PicketTuiView.Accessibility), "Accessibility");
            }));
    }

    private static MenuBarWidget BuildMenu<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.MenuBar(m => [
            m.Menu("File", m => [
                m.MenuItem("Quit").OnActivated(e => e.Context.RequestStop())
            ]),
            m.Menu("View", m => [
                m.MenuItem("Dashboard").OnActivated(_ => state.SetView(PicketTuiView.Dashboard)),
                m.MenuItem("Findings").OnActivated(_ => state.SetView(PicketTuiView.Findings)),
                m.MenuItem("Rules").OnActivated(_ => state.SetView(PicketTuiView.Rules)),
                m.MenuItem("Files").OnActivated(_ => state.SetView(PicketTuiView.Files)),
                m.MenuItem("Accessibility").OnActivated(_ => state.SetView(PicketTuiView.Accessibility)),
                m.MenuItem("Logs").OnActivated(_ => state.SetView(PicketTuiView.Logs))
            ]),
            m.Menu("Filter", m => [
                m.MenuItem("Clear").OnActivated(_ => state.ClearSearch())
            ])
        ]);
    }

    private static BorderWidget BuildNavigation<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        string[] labels = [.. PicketTuiState.NavigationItems.Select(PicketTuiState.GetViewLabel)];
        return ctx.Border(b => [
            b.Text("Picket"),
            b.Text(state.GetSummaryLine()).Wrap(),
            b.Separator(),
            b.List(labels)
                .OnFocusChanged(e => state.SetViewByIndex(e.FocusedIndex))
                .OnItemActivated(e => state.SetViewByIndex(e.ActivatedIndex))
                .FocusedIndex(state.CurrentNavigationIndex)
                .FixedHeight(labels.Length),
            b.Text("").Fill(),
            b.Separator(),
            b.Text(string.Concat("Report: ", TrimMiddle(Path.GetFileName(state.Report.Path), 18))).Ellipsis()
        ]).Title("Scanner").Fill();
    }

    private static SplitterWidget BuildMainArea<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VSplitter(
            top => [BuildCurrentView(top, state)],
            bottom => BuildBottomPanel(bottom, state),
            topHeight: 22).Fill();
    }

    private static Hex1bWidget BuildCurrentView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return state.CurrentView switch
        {
            PicketTuiView.Dashboard => BuildDashboard(ctx, state),
            PicketTuiView.Findings => BuildFindingsView(ctx, state),
            PicketTuiView.Rules => BuildRulesView(ctx, state),
            PicketTuiView.Files => BuildFilesView(ctx, state),
            PicketTuiView.Accessibility => BuildAccessibilityView(ctx),
            PicketTuiView.Logs => BuildLogsView(ctx, state),
            _ => ctx.Text("Unknown view")
        };
    }

    private static BorderWidget BuildDashboard<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Border(b => [
            b.HStack(h => [
                h.Border(c => [
                    c.Text(state.Report.Summary.FindingCount.ToString(CultureInfo.InvariantCulture)),
                    c.Text("Findings")
                ]).Title("Total").FillWidth(),
                h.Border(c => [
                    c.Text(state.Report.Summary.FileCount.ToString(CultureInfo.InvariantCulture)),
                    c.Text("Files")
                ]).Title("Affected").FillWidth(),
                h.Border(c => [
                    c.Text(state.Report.Summary.Format),
                    c.Text("Format")
                ]).Title("Report").FillWidth()
            ]).FixedHeight(5),
            b.Separator(),
            b.HSplitter(
                left => BuildCountList(left, "Top rules", state.GetTopRules(TopListLimit)),
                right => BuildCountList(right, "Top files", state.GetTopFiles(TopListLimit)),
                leftWidth: 44).Fill()
        ]).Title("Dashboard").Fill();
    }

    private static SplitterWidget BuildFindingsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.HSplitter(
            left => [
                left.Border(b => [
                    b.HStack(h => [
                        h.Text("Filter: "),
                        h.TextBox(state.SearchText)
                            .OnTextChanged(e => state.SetSearchText(e.NewText))
                            .FillWidth()
                    ]).FixedHeight(1),
                    BuildFindingsTable(b, state)
                ]).Title("Findings").Fill()
            ],
            right => [
                right.Border(b => BuildFindingDetails(b, state.FocusedFinding))
                    .Title("Focused Finding")
                    .Fill()
            ],
            leftWidth: 82).Fill();
    }

    private static TableWidget<PicketTuiFindingRow> BuildFindingsTable<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Table(state.FindingDataSource)
            .RowKey(row => row.Key)
            .Header(h => [
                h.Cell("#").Width(SizeHint.Fixed(6)).Align(Alignment.Right),
                h.Cell("Rule").Width(SizeHint.Fixed(28)),
                h.Cell("Location").Width(SizeHint.Fill),
                h.Cell("Fingerprint").Width(SizeHint.Fixed(24))
            ])
            .Row((r, row, _) => [
                r.Cell(row.Index.ToString(CultureInfo.InvariantCulture)),
                r.Cell(TrimMiddle(row.RuleId, 26)),
                r.Cell(TrimMiddle(row.Location, 72)),
                r.Cell(TrimMiddle(row.Fingerprint, 22))
            ])
            .Empty(empty => empty.Text("No findings match the current filter."))
            .Focus(state.FocusedFindingKey)
            .OnFocusChanged(state.FocusFinding)
            .Compact()
            .Fill();
    }

    private static Hex1bWidget[] BuildFindingDetails<TParent>(WidgetContext<TParent> ctx, PicketTuiFindingRow? row)
        where TParent : Hex1bWidget
    {
        if (row is null)
        {
            return [
                ctx.Text("No finding selected."),
                ctx.Text(""),
                ctx.Text("The TUI summary does not load raw secret fields.")
            ];
        }

        return [
            ctx.Text(string.Concat("Rule: ", row.RuleId)).Wrap(),
            ctx.Text(string.Concat("Path: ", TrimEnd(row.Path, DetailLimit))).Wrap(),
            ctx.Text(string.Concat("Line: ", row.Line)),
            ctx.Text(string.Concat("Location: ", TrimEnd(row.Location, DetailLimit))).Wrap(),
            ctx.Text(""),
            ctx.Text("Fingerprint"),
            ctx.Text(TrimEnd(row.Fingerprint, DetailLimit)).Wrap(),
            ctx.Text(""),
            ctx.Text("Raw secret, match, and line evidence are intentionally not loaded in this report summary view.").Wrap()
        ];
    }

    private static BorderWidget BuildRulesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Border(b => BuildCountList(b, "Rules by finding count", state.GetTopRules(24))).Title("Rules").Fill();
    }

    private static BorderWidget BuildFilesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Border(b => BuildCountList(b, "Files by finding count", state.GetTopFiles(24))).Title("Files").Fill();
    }

    private static BorderWidget BuildAccessibilityView<TParent>(WidgetContext<TParent> ctx)
        where TParent : Hex1bWidget
    {
        return ctx.Border(b => [
            b.Text("Accessibility Contract"),
            b.Separator(),
            b.Text("Baseline: WCAG 2.2 AA principles adapted to terminal UI.").Wrap(),
            b.Text("Keyboard: every action is reachable without a mouse.").Wrap(),
            b.Text("Focus: focused rows and controls use a high-contrast inverse state.").Wrap(),
            b.Text("Color: status is written as text; color is never the only signal.").Wrap(),
            b.Text("Contrast: text pairs target 4.5:1 or better; UI/focus indicators target 3:1 or better.").Wrap(),
            b.Text("Motion: scan progress should have text status alongside spinners.").Wrap()
        ]).Title("Accessibility").Fill();
    }

    private static BorderWidget BuildLogsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Border(b => [
            b.Text("Session"),
            b.Separator(),
            b.Text(string.Concat("Loaded: ", state.Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))),
            b.Text(string.Concat("Report: ", state.Report.Path)).Wrap(),
            b.Text(string.Concat("Status: ", state.StatusMessage)).Wrap(),
            b.Text(string.Concat("Filter: ", state.SearchText.Length == 0 ? "none" : state.SearchText)).Wrap()
        ]).Title("Logs").Fill();
    }

    private static Hex1bWidget[] BuildBottomPanel<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return [
            ctx.Border(b => [
                b.HStack(h => [
                    h.Text(string.Concat("Status: ", state.StatusMessage)).FillWidth(),
                    h.Text(string.Concat("Visible: ", state.VisibleRows.Count.ToString(CultureInfo.InvariantCulture))).FillWidth(),
                    h.Text(string.Concat("Loaded: ", state.Report.LoadedAt.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture)))
                ]),
                b.Text(string.Concat("Report: ", state.Report.Path)).Ellipsis()
            ]).Title("Diagnostics").Fill()
        ];
    }

    private static InfoBarWidget BuildInfoBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.InfoBar(s => [
            s.Section("Tab"),
            s.Section("Focus"),
            s.Section("Arrows/Page"),
            s.Section("Navigate"),
            s.Section("Esc"),
            s.Section("Clear filter"),
            s.Section("F1"),
            s.Section("Accessibility"),
            s.Spacer(),
            s.Section(state.GetSummaryLine()),
            s.Section("Ctrl+Q"),
            s.Section("Quit")
        ]);
    }

    private static Hex1bWidget[] BuildCountList<TParent>(
        WidgetContext<TParent> ctx,
        string title,
        List<KeyValuePair<string, int>> rows)
        where TParent : Hex1bWidget
    {
        var widgets = new List<Hex1bWidget>
        {
            ctx.Text(title),
            ctx.Separator()
        };

        if (rows.Count == 0)
        {
            widgets.Add(ctx.Text("No findings."));
            return [.. widgets];
        }

        for (int i = 0; i < rows.Count; i++)
        {
            KeyValuePair<string, int> row = rows[i];
            widgets.Add(ctx.HStack(h => [
                h.Text(row.Value.ToString(CultureInfo.InvariantCulture)).FixedWidth(6),
                h.Text(TrimMiddle(row.Key, 72)).FillWidth()
            ]));
        }

        return [.. widgets];
    }

    private static string TrimEnd(string value, int limit)
    {
        if (value.Length <= limit)
        {
            return value;
        }

        return string.Concat(value.AsSpan(0, limit - 3), "...");
    }

    private static string TrimMiddle(string value, int limit)
    {
        if (value.Length <= limit)
        {
            return value;
        }

        int prefixLength = (limit - 3) / 2;
        int suffixLength = limit - prefixLength - 3;
        return string.Concat(value.AsSpan(0, prefixLength), "...", value.AsSpan(value.Length - suffixLength, suffixLength));
    }
}
