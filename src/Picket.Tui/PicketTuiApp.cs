using Hex1b;
using Hex1b.Documents;
using Hex1b.Input;
using Hex1b.Layout;
using Hex1b.Nodes;
using Hex1b.Theming;
using Hex1b.Widgets;
using System.Globalization;

namespace Picket.Tui;

/// <summary>
/// Builds the full-screen scanner-console widget tree for Picket report triage.
/// </summary>
internal static class PicketTuiApp
{
    private const int DetailLimit = 180;
    private const int DashboardSummaryHeight = 10;
    private const int FieldLabelWidth = 16;
    private const int FindingDetailsWidth = 42;
    private const int FindingDetailsMaximumWidth = 72;
    private const int FindingDetailsMinimumWidth = 32;
    private const int FindingsSideBySideMinimumWidth = 126;
    private const int OutputPreviewLimit = 7;
    private const int ScanSettingsWidth = 74;
    private const int TopListLimit = 8;
    private static readonly string[] s_booleanOptions = ["Off", "On"];

    /// <summary>
    /// Builds the root widget for the scanner console.
    /// </summary>
    /// <param name="ctx">The Hex1b root context.</param>
    /// <param name="state">The mutable TUI state for the current report.</param>
    /// <returns>The root Hex1b widget.</returns>
    internal static Hex1bWidget Build(RootContext ctx, PicketTuiState state)
    {
        return Build(ctx, state, null);
    }

    /// <summary>
    /// Builds the root widget for the scanner console.
    /// </summary>
    /// <param name="ctx">The Hex1b root context.</param>
    /// <param name="state">The mutable TUI state for the current report.</param>
    /// <param name="app">The owning Hex1b application, when focus should be requested after render.</param>
    /// <returns>The root Hex1b widget.</returns>
    internal static Hex1bWidget Build(RootContext ctx, PicketTuiState state, Hex1bApp? app)
    {
        RequestPendingFocus(state, app);

        Hex1bWidget content = ctx.VStack(main => [
                BuildTitleBar(main, state),
                BuildMainTabs(main, state),
                main.Padding(2, 2, 1, 1, BuildActiveView(main, state).Fill()).Fill(),
                BuildInfoBar(main, state)
            ]).InputBindings(bindings => ConfigureRootBindings(bindings, state));
        Hex1bWidget body = state.IsHelpOpen
            ? ctx.ZStack(z => [
                content,
                BuildHelpOverlay(z, state),
            ]).Fill()
            : content;
        return ctx.ThemePanel(PicketTuiPalette.Apply, body);
    }

    private static void ConfigureRootBindings(
        InputBindingsBuilder bindings,
        PicketTuiState state)
    {
        bindings.Ctrl().Key(Hex1bKey.Q).Global().OverridesCapture().Action(context => context.RequestStop(), "Quit");
        if (state.IsHelpOpen)
        {
            bindings.Key(Hex1bKey.Escape).Global().OverridesCapture().Action(
                context => CloseHelpFromUi(state, context.Invalidate),
                "Close keyboard help");
            bindings.Key(Hex1bKey.F1).Global().OverridesCapture().Action(
                context => CloseHelpFromUi(state, context.Invalidate),
                "Close keyboard help");
            bindings.Key(Hex1bKey.OemQuestion).Global().OverridesCapture().Action(
                context => CloseHelpFromUi(state, context.Invalidate),
                "Close keyboard help");
            return;
        }

        bindings.Key(Hex1bKey.Tab).Global().OverridesCapture().Action(
            context => context.FocusNext(),
            "Next control");
        bindings.Shift().Key(Hex1bKey.Tab).Global().OverridesCapture().Action(
            context => context.FocusPrevious(),
            "Previous control");

        if (state.CurrentView != PicketTuiView.Scan)
        {
            bindings.Key(Hex1bKey.Q).Global().Action(context => context.RequestStop(), "Quit");
        }

        bindings.Ctrl().Key(Hex1bKey.C).Global().OverridesCapture().Action(
            context =>
            {
                if (state.ScanWorkspace.IsRunning)
                {
                    CancelScanFromUi(state, context.Invalidate);
                    return;
                }

                context.RequestStop();
            },
            "Cancel scan or quit");
        bindings.Ctrl().Key(Hex1bKey.R).Global().OverridesCapture().Action(
            context => RunScanFromUi(state, context.Invalidate, context.CancellationToken),
            "Run scan");
        bindings.Key(Hex1bKey.F1).Global().OverridesCapture().Action(
            context => OpenHelpFromUi(state, context.Invalidate),
            "Keyboard help");
        bindings.Key(Hex1bKey.OemQuestion).Action(
            context => OpenHelpFromUi(state, context.Invalidate),
            "Keyboard help");
        if (state.CurrentView == PicketTuiView.Logs)
        {
            bindings.Key(Hex1bKey.Escape).Global().OverridesCapture().Action(
                context => HandleLogsEscape(state, context),
                "Leave search or clear selection");
        }
        else if (state.CurrentView != PicketTuiView.Scan)
        {
            bindings.Key(Hex1bKey.Escape).Action(
                context => ClearSelectionOrFilter(state, context.Invalidate),
                "Clear selection or filter");
        }

        if (state.CurrentView == PicketTuiView.Findings)
        {
            bindings.Key(Hex1bKey.J).Global().Action(context => MoveFindingFromUi(state, context.Invalidate, 1), "Move finding");
            bindings.Key(Hex1bKey.K).Global().Action(context => MoveFindingFromUi(state, context.Invalidate, -1), "Move finding");
            bindings.Key(Hex1bKey.O).Action(context => OpenFocusedFindingFromUi(state, context), "Open file");
        }

        if (state.CurrentView == PicketTuiView.Rules)
        {
            bindings.Key(Hex1bKey.F).Action(context => FilterRuleFromUi(state, context.Invalidate), "Filter findings to rule");
        }

        if (state.CurrentView == PicketTuiView.Files)
        {
            bindings.Key(Hex1bKey.F).Action(context => FilterFileFromUi(state, context.Invalidate), "Filter findings to file");
            bindings.Key(Hex1bKey.O).Action(context => OpenFocusedFileFromUi(state, context), "Open file");
        }

        bindings.Key(Hex1bKey.F5).Global().Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
        ConfigureViewNavigationBindings(bindings, state);
        ConfigureNumberedViewBindings(bindings, state);

        bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");
        state.CaptureHelpBindings(bindings.Bindings);
    }

    private static void ConfigureViewNavigationBindings(InputBindingsBuilder bindings, PicketTuiState state)
    {
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.S).Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.D).Action(_ => state.SetView(PicketTuiView.Dashboard), "Dashboard");
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.F).Action(_ => state.SetView(PicketTuiView.Findings), "Findings");
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.R).Action(_ => state.SetView(PicketTuiView.Rules), "Rules");
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.B).Action(_ => state.SetView(PicketTuiView.Files), "Files");
        bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.L).Action(_ => state.SetView(PicketTuiView.Logs), "Logs");
    }

    private static void ConfigureNumberedViewBindings(InputBindingsBuilder bindings, PicketTuiState state)
    {
        bindings.Key(Hex1bKey.D1).Action(_ => state.SetViewByTabNumber(1), "Dashboard");
        bindings.Key(Hex1bKey.D2).Action(_ => state.SetViewByTabNumber(2), "Scan workspace");
        bindings.Key(Hex1bKey.D3).Action(_ => state.SetViewByTabNumber(3), "Findings");
        bindings.Key(Hex1bKey.D4).Action(_ => state.SetViewByTabNumber(4), "Rules");
        bindings.Key(Hex1bKey.D5).Action(_ => state.SetViewByTabNumber(5), "Files");
        bindings.Key(Hex1bKey.D6).Action(_ => state.SetViewByTabNumber(6), "Logs");
        bindings.Key(Hex1bKey.NumPad1).Action(_ => state.SetViewByTabNumber(1));
        bindings.Key(Hex1bKey.NumPad2).Action(_ => state.SetViewByTabNumber(2));
        bindings.Key(Hex1bKey.NumPad3).Action(_ => state.SetViewByTabNumber(3));
        bindings.Key(Hex1bKey.NumPad4).Action(_ => state.SetViewByTabNumber(4));
        bindings.Key(Hex1bKey.NumPad5).Action(_ => state.SetViewByTabNumber(5));
        bindings.Key(Hex1bKey.NumPad6).Action(_ => state.SetViewByTabNumber(6));
    }

    private static BackdropWidget BuildHelpOverlay<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        string[] lines = state.HelpText.ReplaceLineEndings("\n").Split('\n');
        return ctx.Backdrop(
            ctx.Border(
                ctx.Padding(
                    2,
                    2,
                    0,
                    0,
                    ctx.VStack(v =>
                    {
                        var widgets = new List<Hex1bWidget>(lines.Length);
                        for (int i = 0; i < lines.Length; i++)
                        {
                            widgets.Add(v.Text(lines[i]).FixedHeight(1));
                        }

                        return [.. widgets];
                    }).Fill()).Fill())
                .Title(" Keyboard help ")
                .FixedWidth(68)
                .FixedHeight(lines.Length + 2))
            .Background(PicketTuiPalette.PanelBackground)
            .OnClickAway(state.CloseHelp);
    }

    private static void OpenHelpFromUi(PicketTuiState state, Action invalidate)
    {
        state.OpenHelp();
        invalidate();
    }

    private static void CloseHelpFromUi(PicketTuiState state, Action invalidate)
    {
        state.CloseHelp();
        invalidate();
    }

    private static void RequestPendingFocus(PicketTuiState state, Hex1bApp? app)
    {
        if (app is null)
        {
            return;
        }

        PicketTuiFocusTarget? target = state.ConsumePendingFocusTarget();
        if (target.HasValue)
        {
            app.RequestFocus(node => IsFocusTarget(node, target.GetValueOrDefault()));
        }
    }

    private static bool IsFocusTarget(Hex1bNode node, PicketTuiFocusTarget target)
    {
        return target switch
        {
            PicketTuiFocusTarget.DashboardEditor => node is EditorNode,
            PicketTuiFocusTarget.ScanPrimaryControl => node is ButtonNode,
            PicketTuiFocusTarget.FindingsTable => node is TableNode<PicketTuiFindingRow>,
            PicketTuiFocusTarget.RulesTable or PicketTuiFocusTarget.FilesTable => node is TableNode<KeyValuePair<string, int>>,
            PicketTuiFocusTarget.LogsSearch => node is TextBoxNode,
            _ => false,
        };
    }

    private static HStackWidget BuildTitleBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.InfoBar(bar =>
            [
                bar.Section(" Picket ").Theme(theme => theme
                    .Set(GlobalTheme.ForegroundColor, PicketTuiPalette.Foreground)),
                bar.Divider(" "),
                bar.Section(state.GetCompactSummaryLine()).Theme(theme => theme
                    .Set(GlobalTheme.ForegroundColor, PicketTuiPalette.MutedForeground)),
                bar.Spacer()
            ], invertColors: false).FillWidth(),
            state.CurrentView == PicketTuiView.Scan
                ? h.Text("").FixedWidth(14)
                : BuildRunScanButton(h, state).FixedWidth(14)
        ]).FixedHeight(1);
    }

    private static ThemePanelWidget BuildRunScanButton<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme
                .Set(ButtonTheme.BackgroundColor, PicketTuiPalette.PrimaryActionBackground)
                .Set(ButtonTheme.ForegroundColor, PicketTuiPalette.PrimaryActionForeground)
                .Set(ButtonTheme.FocusedBackgroundColor, PicketTuiPalette.PrimaryActionBackground)
                .Set(ButtonTheme.FocusedForegroundColor, PicketTuiPalette.PrimaryActionForeground)
                .Set(ButtonTheme.HoveredBackgroundColor, PicketTuiPalette.PrimaryActionBackground)
                .Set(ButtonTheme.HoveredForegroundColor, PicketTuiPalette.PrimaryActionForeground),
            ctx.Button(state.ScanWorkspace.IsRunning ? "Cancel" : "Run scan")
                .OnClick(e => ActivateScanButton(state, e.Context.Invalidate, e.CancellationToken)));
    }

    private static TabPanelWidget BuildMainTabs<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.TabPanel(tp =>
        [
            tp.Tab("Dashboard", _ => []).Selected(state.CurrentView == PicketTuiView.Dashboard),
            tp.Tab("Scan", _ => []).Selected(state.CurrentView == PicketTuiView.Scan),
            tp.Tab("Findings", _ => []).Selected(state.CurrentView == PicketTuiView.Findings),
            tp.Tab("Rules", _ => []).Selected(state.CurrentView == PicketTuiView.Rules),
            tp.Tab("Files", _ => []).Selected(state.CurrentView == PicketTuiView.Files),
            tp.Tab("Logs", _ => []).Selected(state.CurrentView == PicketTuiView.Logs),
        ])
        .OnSelectionChanged(e => state.SetViewByIndex(e.SelectedIndex))
        .Full()
        .FixedHeight(3);
    }

    private static Hex1bWidget BuildActiveView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return state.CurrentView switch
        {
            PicketTuiView.Scan => BuildScanWorkspace(ctx, state),
            PicketTuiView.Findings => BuildFindingsView(ctx, state),
            PicketTuiView.Rules => BuildRulesView(ctx, state),
            PicketTuiView.Files => BuildFilesView(ctx, state),
            PicketTuiView.Logs => BuildLogsView(ctx, state),
            _ => BuildDashboard(ctx, state),
        };
    }

    private static VStackWidget BuildDashboard<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildReadOnlyEditor(
                v,
                state,
                state.GetDashboardEditorState(),
                state.DashboardYankProvider,
                state.MetadataDecorationProvider).FixedHeight(DashboardSummaryHeight),
            v.Separator(),
            v.HStack(h => [
                h.VStack(rules => [
                    BuildSectionTitle(rules, "Top rules"),
                    BuildCountTable(
                        rules,
                        state,
                        state.GetTopRules(TopListLimit),
                        "Rule",
                        state.FocusedRuleKey,
                        state.SelectedRuleKey,
                        state.FocusRule,
                        PicketTuiCountTableKind.Rules).Fill()
                ]).FillWidth(),
                h.Separator(),
                h.VStack(files => [
                    BuildSectionTitle(files, "Top files"),
                    BuildCountTable(
                        files,
                        state,
                        state.GetTopFiles(TopListLimit),
                        "File",
                        state.FocusedFileKey,
                        state.SelectedFileKey,
                        state.FocusFile,
                        PicketTuiCountTableKind.Files).Fill()
                ]).FillWidth()
            ]).Fill()
        ]).Fill();
    }

    private static ResponsiveWidget BuildScanWorkspace<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.Responsive(r => [
            r.When((width, _) => width >= 100,
                wide => wide.VStack(v => [
                    BuildScanStatusStrip(v, state, showCommand: false).FixedHeight(4),
                    v.Separator(),
                    v.HSplitter(
                        left => [BuildScanConfigurationPane(left, scan).Fill()],
                        right => [BuildScanCommandPane(right, state)],
                        leftWidth: ScanSettingsWidth).Fill()
                ]).Fill()),
            r.Otherwise(narrow => narrow.VStack(v => [
                BuildScanStatusStrip(v, state, showCommand: true).FixedHeight(6),
                v.Separator(),
                BuildScanConfigurationPane(v, scan).Fill()
            ]).Fill())
        ]).Fill();
    }

    private static VStackWidget BuildScanStatusStrip<TParent>(
        WidgetContext<TParent> ctx,
        PicketTuiState state,
        bool showCommand)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.VStack(v =>
        {
            List<Hex1bWidget> rows =
            [
                v.HStack(h => [
                BuildRunScanButton(h, state).FixedWidth(14),
                h.Text("  "),
                BuildScanStatus(h, scan).FillWidth(),
                BuildStatusText(h, FormatScanExit(scan), PicketTuiPalette.MutedForeground).FixedWidth(10)
                ]).FixedHeight(1),
                BuildBlankLine(v),
            ];

            if (showCommand)
            {
                rows.Add(BuildScanCommandPreview(v, state, wrap: false));
                rows.Add(BuildBlankLine(v));
            }

            rows.Add(v.HStack(h => [
                BuildMetadataLine(h, "Target", FormatScanTargetValue(scan)).FillWidth(),
                h.Text("    "),
                BuildMetadataLine(h, "Report", TrimMiddle(scan.ReportPath, 72)).FillWidth()
            ]).FixedHeight(1));
            rows.Add(v.HStack(h => [
                BuildMetadataLine(h, "Findings", FormatLoadedFindingsLine(state)).FillWidth(),
                h.Text("    "),
                BuildMetadataLine(h, "Timing", PicketTuiScanTimeFormatter.FormatCompact(scan)).FillWidth()
            ]).FixedHeight(1));
            return [.. rows];
        });
    }

    private static Hex1bWidget BuildScanStatus<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return scan.IsRunning
            ? ctx.HStack(h => [
                h.Spinner(SpinnerStyle.Dots),
                h.Text(" "),
                BuildStatusText(h, scan.Status, GetScanStatusColor(scan)).FillWidth(),
            ]).FillWidth()
            : BuildStatusText(ctx, scan.Status, GetScanStatusColor(scan)).FillWidth();
    }

    private static VStackWidget BuildScanCommandPane<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Command"),
            BuildBlankLine(v),
            BuildScanCommandPreview(v, state, wrap: true).FillWidth(),
            BuildWideGap(v),
            .. BuildScanOutput(v, scan)
        ]).Fill();
    }

    private static VStackWidget BuildScanConfigurationPane<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Settings"),
            BuildBlankLine(v),
            v.ToggleSwitch(PicketTuiScanWorkspace.ScanSettingPages, scan.ScanSettingPageIndex)
                .OnSelectionChanged(e => scan.SetScanSettingPageByIndex(e.SelectedIndex))
                .FillWidth(),
            BuildSectionGap(v),
            BuildScanSettingsPage(v, scan).Fill()
        ]).Fill();
    }

    private static VStackWidget BuildScanSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return scan.ScanSettingPageIndex switch
        {
            1 => BuildOutputSettingsPage(ctx, scan),
            2 => BuildValidationSettingsPage(ctx, scan),
            3 => BuildLimitSettingsPage(ctx, scan),
            _ => BuildSourceSettingsPage(ctx, scan),
        };
    }

    private static VStackWidget BuildSourceSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Target"),
            BuildBlankLine(v),
            BuildTargetSelectionRows(v, scan),
            BuildSectionGap(v),
            .. BuildPrimaryTargetFields(v, scan)
        ]);
    }

    private static VStackWidget BuildOutputSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Report"),
            BuildBlankLine(v),
            BuildOutputFields(v, scan),
            BuildSectionGap(v),
            BuildSectionTitle(v, "Paths"),
            BuildBlankLine(v),
            BuildOutputPathFields(v, scan)
        ]);
    }

    private static VStackWidget BuildValidationSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Validation and filters"),
            BuildBlankLine(v),
            BuildFilterFields(v, scan),
            BuildBooleanField(v, "Verify", scan.Verify, scan.SetVerify),
            BuildSectionGap(v),
            BuildStatusText(v, "Live verification only runs when Verify is On.", PicketTuiPalette.MutedForeground),
            BuildSectionGap(v),
            BuildSectionTitle(v, "Rule packs"),
            BuildBlankLine(v),
            BuildBooleanField(v, "Strict", scan.StrictRulePack, scan.SetStrictRulePack),
            BuildBooleanField(v, "Experimental", scan.ExperimentalRulePack, scan.SetExperimentalRulePack)
        ]);
    }

    private static VStackWidget BuildLimitSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            var widgets = new List<Hex1bWidget>
            {
                BuildSectionTitle(v, "Scan and archive limits"),
                BuildBlankLine(v),
                BuildLimitFields(v, scan),
            };

            if (scan.TargetMode == PicketTuiScanTargetMode.AzureDevOps)
            {
                widgets.Add(BuildBlankLine(v));
                widgets.Add(BuildSectionTitle(v, "Azure DevOps transfer limits"));
                widgets.Add(BuildBlankLine(v));
                widgets.Add(BuildTextField(v, "Artifact MB", scan.AzureDevOpsMaxArtifactMegabytes, scan.SetAzureDevOpsMaxArtifactMegabytes));
                widgets.Add(BuildTextField(v, "Log MB", scan.AzureDevOpsMaxLogMegabytes, scan.SetAzureDevOpsMaxLogMegabytes));
                widgets.Add(BuildTextField(v, "Package MB", scan.AzureDevOpsMaxPackageMegabytes, scan.SetAzureDevOpsMaxPackageMegabytes));
            }

            if (scan.TargetMode == PicketTuiScanTargetMode.RegistryImage)
            {
                widgets.Add(BuildBlankLine(v));
                widgets.Add(BuildSectionTitle(v, "Registry transfer limit"));
                widgets.Add(BuildBlankLine(v));
                widgets.Add(BuildTextField(v, "Image MB", scan.RegistryMaxImageMegabytes, scan.SetRegistryMaxImageMegabytes));
            }

            return [.. widgets];
        });
    }

    private static VStackWidget BuildTargetSelectionRows<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            List<Hex1bWidget> rows =
            [
                v.HStack(h => [
                h.Text("Kind").FixedWidth(FieldLabelWidth),
                h.Text("  "),
                h.ToggleSwitch(PicketTuiScanWorkspace.TargetCategoryLabels, scan.TargetCategoryIndex)
                    .OnSelectionChanged(e => scan.SetTargetCategoryByIndex(e.SelectedIndex))
                    .FillWidth()
                ]).FixedHeight(1),
            ];

            if (scan.ActiveTargetModeLabels.Count > 1)
            {
                rows.Add(v.HStack(h => [
                h.Text(scan.TargetCategory == PicketTuiScanTargetCategory.SourceHost ? "Provider" : "Target").FixedWidth(FieldLabelWidth),
                h.Text("  "),
                BuildTargetModeSelector(h, scan)
                ]).FixedHeight(1));
            }

            return [.. rows];
        });
    }

    private static Hex1bWidget BuildTargetModeSelector<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        if (scan.TargetCategory == PicketTuiScanTargetCategory.SourceHost)
        {
            return ctx.Picker(scan.ActiveTargetModeLabels, scan.TargetModeIndex)
                .OnSelectionChanged(e => scan.SetTargetModeByCategoryIndex(e.SelectedIndex))
                .FillWidth();
        }

        return ctx.ToggleSwitch(scan.ActiveTargetModeLabels, scan.TargetModeIndex)
            .OnSelectionChanged(e => scan.SetTargetModeByCategoryIndex(e.SelectedIndex))
            .FillWidth();
    }

    private static ThemePanelWidget BuildSectionTitle<TParent>(WidgetContext<TParent> ctx, string text)
        where TParent : Hex1bWidget
    {
        return BuildStatusText(ctx, text, PicketTuiPalette.InfoForeground);
    }

    private static TextBlockWidget BuildBlankLine<TParent>(WidgetContext<TParent> ctx)
        where TParent : Hex1bWidget
    {
        return ctx.Text("").FixedHeight(1);
    }

    private static TextBlockWidget BuildSectionGap<TParent>(WidgetContext<TParent> ctx)
        where TParent : Hex1bWidget
    {
        return ctx.Text("").FixedHeight(1);
    }

    private static TextBlockWidget BuildWideGap<TParent>(WidgetContext<TParent> ctx)
        where TParent : Hex1bWidget
    {
        return ctx.Text("").FixedHeight(2);
    }

    private static VStackWidget BuildOutputFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildChoiceField(v, "Format", PicketTuiScanWorkspace.ReportFormats, scan.ReportFormatIndex, scan.SetReportFormatByIndex),
            BuildTextField(v, "Redact", scan.RedactionPercent, scan.SetRedactionPercent)
        ]);
    }

    private static VStackWidget BuildOutputPathFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            var fields = new List<Hex1bWidget>
            {
                BuildTextField(v, "Report", scan.ReportPath, scan.SetReportPath),
            };
            if (scan.TargetMode != PicketTuiScanTargetMode.Local)
            {
                fields.Add(BuildTextField(v, "Checkpoint", scan.CheckpointPath, scan.SetCheckpointPath));
                fields.Add(BuildBooleanField(v, "Reset state", scan.ResetCheckpoint, scan.SetResetCheckpoint));
            }

            fields.Add(BuildTextField(v, "Profile", scan.Profile, scan.SetProfile));
            fields.Add(BuildTextField(v, "Config", scan.ConfigPath, scan.SetConfigPath));
            fields.Add(BuildTextField(v, "Ignore", scan.IgnorePath, scan.SetIgnorePath));
            return [.. fields];
        });
    }

    private static VStackWidget BuildFilterFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildBooleanField(v, "No ignore", scan.NoIgnore, scan.SetNoIgnore),
            BuildBooleanField(v, "Only valid", scan.OnlyVerified, scan.SetOnlyVerified),
            BuildChoiceField(v, "Results", PicketTuiScanWorkspace.ResultFilterDisplayLabels, scan.ResultFilterIndex, scan.SetResultFilterByIndex),
            BuildMetadataLine(v, "Result value", scan.ResultFilter)
        ]);
    }

    private static Hex1bWidget[] BuildPrimaryTargetFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return scan.TargetMode switch
        {
            PicketTuiScanTargetMode.GitHub =>
            [
                BuildGitHubSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.AzureDevOps =>
            [
                BuildAzureDevOpsSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.GitLab =>
            [
                BuildGitLabSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.Gitea =>
            [
                BuildGiteaSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.Bitbucket =>
            [
                BuildBitbucketSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.BitbucketDataCenter =>
            [
                BuildBitbucketDataCenterSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.S3 =>
            [
                BuildS3SourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.Gcs =>
            [
                BuildGcsSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.AzureBlob =>
            [
                BuildAzureBlobSourceFields(ctx, scan),
            ],
            PicketTuiScanTargetMode.DockerArchive =>
            [
                BuildTextField(ctx, "Docker archive", scan.DockerArchivePath, scan.SetDockerArchivePath),
            ],
            PicketTuiScanTargetMode.OciArchive =>
            [
                BuildTextField(ctx, "OCI archive", scan.OciArchivePath, scan.SetOciArchivePath),
            ],
            PicketTuiScanTargetMode.RegistryImage =>
            [
                BuildContainerRegistrySourceFields(ctx, scan),
            ],
            _ =>
            [
                BuildTextField(ctx, "Path", scan.LocalPath, scan.SetLocalPath),
            ],
        };
    }

    private static VStackWidget BuildGitHubSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildPickerField(v, "Scope", PicketTuiScanWorkspace.GitHubScopeLabels, scan.GitHubScopeIndex, scan.SetGitHubScopeByIndex),
            v.HStack(h => [
                BuildGitHubPrimaryFields(h, scan).FillWidth(),
                h.Text("      "),
                BuildGitHubOptionFields(h, scan).FillWidth(),
            ]).FillWidth()
        ]).FillWidth();
    }

    private static VStackWidget BuildGitHubPrimaryFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            var widgets = new List<Hex1bWidget>();
            switch (scan.GitHubScope)
            {
                case PicketTuiGitHubScope.Repository:
                    widgets.Add(BuildTextField(v, "Repo owner/name", scan.GitHubRepository, scan.SetGitHubRepository));
                    break;
                case PicketTuiGitHubScope.Organization:
                    widgets.Add(BuildTextField(v, "Organization", scan.GitHubOrganization, scan.SetGitHubOrganization));
                    break;
                case PicketTuiGitHubScope.User:
                    widgets.Add(BuildTextField(v, "User login", scan.GitHubUser, scan.SetGitHubUser));
                    break;
                case PicketTuiGitHubScope.Gist:
                    widgets.Add(BuildTextField(v, "Gist ID", scan.GitHubGist, scan.SetGitHubGist));
                    break;
                case PicketTuiGitHubScope.UserGists:
                    widgets.Add(BuildTextField(v, "User login", scan.GitHubUserGists, scan.SetGitHubUserGists));
                    break;
            }

            if (widgets.Count != 0)
            {
            }

            widgets.Add(BuildTextField(v, "Token env", scan.GitHubTokenEnvironmentVariable, scan.SetGitHubTokenEnvironmentVariable));
            widgets.Add(BuildTextField(v, "Endpoint", scan.GitHubSourceApiEndpoint, scan.SetGitHubSourceApiEndpoint));

            if (scan.GitHubScope is PicketTuiGitHubScope.Repository or PicketTuiGitHubScope.Organization or PicketTuiGitHubScope.User)
            {
                widgets.Add(BuildTextField(v, "Ref", scan.GitHubRef, scan.SetGitHubRef));
            }

            if (scan.GitHubScope == PicketTuiGitHubScope.Repository)
            {
                widgets.Add(BuildTextField(v, "Pull request", scan.GitHubPullRequest, scan.SetGitHubPullRequest));
            }

            return [.. widgets];
        });
    }

    private static VStackWidget BuildGitHubOptionFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            var widgets = new List<Hex1bWidget>();
            if (scan.GitHubScope is PicketTuiGitHubScope.Repository or PicketTuiGitHubScope.Organization or PicketTuiGitHubScope.User)
            {
                widgets.Add(BuildPickerField(v, "Repo type", PicketTuiScanWorkspace.GitHubRepositoryTypes, scan.GitHubRepositoryTypeIndex, scan.SetGitHubRepositoryTypeByIndex));
                widgets.Add(BuildChoiceField(v, "Issue state", PicketTuiScanWorkspace.GitHubIssueStates, scan.GitHubIssueStateIndex, scan.SetGitHubIssueStateByIndex));
                widgets.Add(BuildBooleanField(v, "Issues", scan.IncludeGitHubIssues, scan.SetIncludeGitHubIssues));
                widgets.Add(BuildBooleanField(v, "Releases", scan.IncludeGitHubReleases, scan.SetIncludeGitHubReleases));
                widgets.Add(BuildBooleanField(v, "Actions", scan.IncludeGitHubActionsArtifacts, scan.SetIncludeGitHubActionsArtifacts));
            }

            widgets.Add(BuildBooleanField(v, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints));
            widgets.Add(BuildBooleanField(v, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints));
            return [.. widgets];
        });
    }

    private static HStackWidget BuildAzureDevOpsSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Org", scan.AzureDevOpsOrganization, scan.SetAzureDevOpsOrganization),
                BuildTextField(left, "Endpoint", scan.AzureDevOpsEndpoint, scan.SetAzureDevOpsEndpoint),
                BuildTextField(left, "Token env", scan.AzureDevOpsTokenEnvironmentVariable, scan.SetAzureDevOpsTokenEnvironmentVariable),
                BuildTextField(left, "Project", scan.AzureDevOpsProject, scan.SetAzureDevOpsProject),
                BuildTextField(left, "Repo", scan.AzureDevOpsRepository, scan.SetAzureDevOpsRepository),
                BuildTextField(left, "Branch", scan.AzureDevOpsBranch, scan.SetAzureDevOpsBranch),
                BuildTextField(left, "PR", scan.AzureDevOpsPullRequest, scan.SetAzureDevOpsPullRequest),
                BuildTextField(left, "Feed", scan.AzureDevOpsFeed, scan.SetAzureDevOpsFeed),
                BuildTextField(left, "Package", scan.AzureDevOpsPackage, scan.SetAzureDevOpsPackage),
                BuildTextField(left, "Version", scan.AzureDevOpsPackageVersion, scan.SetAzureDevOpsPackageVersion),
                BuildTextField(left, "Build ID", scan.AzureDevOpsBuildId, scan.SetAzureDevOpsBuildId),
                BuildTextField(left, "Release ID", scan.AzureDevOpsReleaseId, scan.SetAzureDevOpsReleaseId),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Token", PicketTuiScanWorkspace.AzureDevOpsTokenKinds, scan.AzureDevOpsTokenKindIndex, scan.SetAzureDevOpsTokenKindByIndex),
                BuildBooleanField(right, "Wikis", scan.IncludeAzureDevOpsWikis, scan.SetIncludeAzureDevOpsWikis),
                BuildBooleanField(right, "Artifacts", scan.IncludeAzureDevOpsArtifacts, scan.SetIncludeAzureDevOpsArtifacts),
                BuildBooleanField(right, "Logs", scan.IncludeAzureDevOpsLogs, scan.SetIncludeAzureDevOpsLogs),
                BuildBooleanField(right, "Releases", scan.IncludeAzureDevOpsReleaseArtifacts, scan.SetIncludeAzureDevOpsReleaseArtifacts),
                BuildBooleanField(right, "Packages", scan.IncludeAzureDevOpsPackages, scan.SetIncludeAzureDevOpsPackages),
                BuildTextField(right, "Artifact MB", scan.AzureDevOpsMaxArtifactMegabytes, scan.SetAzureDevOpsMaxArtifactMegabytes),
                BuildTextField(right, "Log MB", scan.AzureDevOpsMaxLogMegabytes, scan.SetAzureDevOpsMaxLogMegabytes),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildGitLabSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Project", scan.GitLabProject, scan.SetGitLabProject),
                BuildTextField(left, "Group", scan.GitLabGroup, scan.SetGitLabGroup),
                BuildTextField(left, "Token env", scan.GitLabTokenEnvironmentVariable, scan.SetGitLabTokenEnvironmentVariable),
                BuildTextField(left, "Endpoint", scan.GitLabApiEndpoint, scan.SetGitLabApiEndpoint),
                BuildTextField(left, "Ref", scan.GitLabRef, scan.SetGitLabRef),
                BuildTextField(left, "MR", scan.GitLabMergeRequest, scan.SetGitLabMergeRequest),
                BuildTextField(left, "Pipeline", scan.GitLabPipelineId, scan.SetGitLabPipelineId),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildBooleanField(right, "Subgroups", scan.IncludeGitLabSubgroups, scan.SetIncludeGitLabSubgroups),
                BuildBooleanField(right, "Snippets", scan.IncludeGitLabSnippets, scan.SetIncludeGitLabSnippets),
                BuildBooleanField(right, "Artifacts", scan.IncludeGitLabJobArtifacts, scan.SetIncludeGitLabJobArtifacts),
                BuildBooleanField(right, "Logs", scan.IncludeGitLabJobLogs, scan.SetIncludeGitLabJobLogs),
                BuildBooleanField(right, "Packages", scan.IncludeGitLabPackages, scan.SetIncludeGitLabPackages),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildGiteaSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Repository", scan.GiteaRepository, scan.SetGiteaRepository),
                BuildTextField(left, "Org", scan.GiteaOrganization, scan.SetGiteaOrganization),
                BuildTextField(left, "User", scan.GiteaUser, scan.SetGiteaUser),
                BuildTextField(left, "Token env", scan.GiteaTokenEnvironmentVariable, scan.SetGiteaTokenEnvironmentVariable),
                BuildTextField(left, "Endpoint", scan.GiteaApiEndpoint, scan.SetGiteaApiEndpoint),
                BuildTextField(left, "Ref", scan.GiteaRef, scan.SetGiteaRef),
                BuildTextField(left, "PR", scan.GiteaPullRequest, scan.SetGiteaPullRequest),
                BuildTextField(left, "Actions run", scan.GiteaActionsRunId, scan.SetGiteaActionsRunId),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Issue state", PicketTuiScanWorkspace.GiteaIssueStates, scan.GiteaIssueStateIndex, scan.SetGiteaIssueStateByIndex),
                BuildBooleanField(right, "Issues", scan.IncludeGiteaIssues, scan.SetIncludeGiteaIssues),
                BuildBooleanField(right, "Releases", scan.IncludeGiteaReleases, scan.SetIncludeGiteaReleases),
                BuildBooleanField(right, "Actions", scan.IncludeGiteaActionsArtifacts, scan.SetIncludeGiteaActionsArtifacts),
                BuildTextField(right, "Package owner", scan.GiteaGenericPackageOwner, scan.SetGiteaGenericPackageOwner),
                BuildTextField(right, "Package name", scan.GiteaGenericPackageName, scan.SetGiteaGenericPackageName),
                BuildTextField(right, "Package version", scan.GiteaGenericPackageVersion, scan.SetGiteaGenericPackageVersion),
                BuildTextField(right, "Package file", scan.GiteaGenericPackageFile, scan.SetGiteaGenericPackageFile),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildBitbucketSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Repository", scan.BitbucketRepository, scan.SetBitbucketRepository),
                BuildTextField(left, "Workspace", scan.BitbucketWorkspace, scan.SetBitbucketWorkspace),
                BuildTextField(left, "Project", scan.BitbucketProject, scan.SetBitbucketProject),
                BuildTextField(left, "Token env", scan.BitbucketTokenEnvironmentVariable, scan.SetBitbucketTokenEnvironmentVariable),
                BuildTextField(left, "Username env", scan.BitbucketUsernameEnvironmentVariable, scan.SetBitbucketUsernameEnvironmentVariable),
                BuildTextField(left, "Endpoint", scan.BitbucketApiEndpoint, scan.SetBitbucketApiEndpoint),
                BuildTextField(left, "Ref", scan.BitbucketRef, scan.SetBitbucketRef),
                BuildTextField(left, "PR", scan.BitbucketPullRequest, scan.SetBitbucketPullRequest),
                BuildTextField(left, "Pipeline", scan.BitbucketPipelineId, scan.SetBitbucketPipelineId),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Token", PicketTuiScanWorkspace.BitbucketTokenKinds, scan.BitbucketTokenKindIndex, scan.SetBitbucketTokenKindByIndex),
                BuildBooleanField(right, "Downloads", scan.IncludeBitbucketDownloads, scan.SetIncludeBitbucketDownloads),
                BuildBooleanField(right, "Pipeline logs", scan.IncludeBitbucketPipelineLogs, scan.SetIncludeBitbucketPipelineLogs),
                BuildBooleanField(right, "Snippets", scan.IncludeBitbucketSnippets, scan.SetIncludeBitbucketSnippets),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildBitbucketDataCenterSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "API endpoint", scan.BitbucketDataCenterApiEndpoint, scan.SetBitbucketDataCenterApiEndpoint),
                BuildTextField(left, "Project key", scan.BitbucketDataCenterProject, scan.SetBitbucketDataCenterProject),
                BuildTextField(left, "Repository", scan.BitbucketDataCenterRepository, scan.SetBitbucketDataCenterRepository),
                BuildTextField(left, "Ref", scan.BitbucketDataCenterRef, scan.SetBitbucketDataCenterRef),
                BuildTextField(left, "Pull request", scan.BitbucketDataCenterPullRequest, scan.SetBitbucketDataCenterPullRequest),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildTextField(right, "Token env", scan.BitbucketDataCenterTokenEnvironmentVariable, scan.SetBitbucketDataCenterTokenEnvironmentVariable),
                BuildTextField(right, "Username env", scan.BitbucketDataCenterUsernameEnvironmentVariable, scan.SetBitbucketDataCenterUsernameEnvironmentVariable),
                BuildChoiceField(right, "Token", PicketTuiScanWorkspace.BitbucketDataCenterTokenKinds, scan.BitbucketDataCenterTokenKindIndex, scan.SetBitbucketDataCenterTokenKindByIndex),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildS3SourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Bucket", scan.S3Bucket, scan.SetS3Bucket),
                BuildTextField(left, "Region", scan.S3Region, scan.SetS3Region),
                BuildTextField(left, "Endpoint", scan.S3Endpoint, scan.SetS3Endpoint),
                BuildTextField(left, "Prefix", scan.S3Prefix, scan.SetS3Prefix),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildTextField(right, "Access env", scan.S3AccessKeyIdEnvironmentVariable, scan.SetS3AccessKeyIdEnvironmentVariable),
                BuildTextField(right, "Secret env", scan.S3SecretAccessKeyEnvironmentVariable, scan.SetS3SecretAccessKeyEnvironmentVariable),
                BuildTextField(right, "Session env", scan.S3SessionTokenEnvironmentVariable, scan.SetS3SessionTokenEnvironmentVariable),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildGcsSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Bucket", scan.GcsBucket, scan.SetGcsBucket),
                BuildTextField(left, "Endpoint", scan.GcsEndpoint, scan.SetGcsEndpoint),
                BuildTextField(left, "Prefix", scan.GcsPrefix, scan.SetGcsPrefix),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildTextField(right, "Token env", scan.GcsTokenEnvironmentVariable, scan.SetGcsTokenEnvironmentVariable),
                BuildTextField(right, "Billing project", scan.GcsUserProject, scan.SetGcsUserProject),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildAzureBlobSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Endpoint", scan.AzureBlobEndpoint, scan.SetAzureBlobEndpoint),
                BuildTextField(left, "Container", scan.AzureBlobContainer, scan.SetAzureBlobContainer),
                BuildTextField(left, "Prefix", scan.AzureBlobPrefix, scan.SetAzureBlobPrefix),
                BuildTextField(left, "Token env", scan.AzureBlobTokenEnvironmentVariable, scan.SetAzureBlobTokenEnvironmentVariable),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Token", PicketTuiScanWorkspace.AzureBlobTokenKinds, scan.AzureBlobTokenKindIndex, scan.SetAzureBlobTokenKindByIndex),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildContainerRegistrySourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Image", scan.RegistryImage, scan.SetRegistryImage),
                BuildTextField(left, "Endpoint", scan.RegistryEndpoint, scan.SetRegistryEndpoint),
                BuildTextField(left, "Auth endpoint", scan.RegistryAuthenticationEndpoint, scan.SetRegistryAuthenticationEndpoint),
                BuildTextField(left, "Platform", scan.RegistryPlatform, scan.SetRegistryPlatform),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildTextField(right, "Token env", scan.RegistryTokenEnvironmentVariable, scan.SetRegistryTokenEnvironmentVariable),
                BuildTextField(right, "Username env", scan.RegistryUsernameEnvironmentVariable, scan.SetRegistryUsernameEnvironmentVariable),
                BuildTextField(right, "Password env", scan.RegistryPasswordEnvironmentVariable, scan.SetRegistryPasswordEnvironmentVariable),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static VStackWidget BuildLimitFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildTextField(v, "Max MB", scan.MaxTargetMegabytes, scan.SetMaxTargetMegabytes),
            BuildTextField(v, "Depth", scan.MaxArchiveDepth, scan.SetMaxArchiveDepth),
            BuildTextField(v, "Entries", scan.MaxArchiveEntries, scan.SetMaxArchiveEntries),
            BuildTextField(v, "Archive MB", scan.MaxArchiveMegabytes, scan.SetMaxArchiveMegabytes),
            BuildTextField(v, "Ratio", scan.MaxArchiveRatio, scan.SetMaxArchiveRatio),
            BuildTextField(v, "Timeout", scan.TimeoutSeconds, scan.SetTimeoutSeconds)
        ]);
    }

    private static string FormatScanExit(PicketTuiScanWorkspace scan)
    {
        return scan.LastExitCode.HasValue
            ? string.Concat("exit ", scan.LastExitCode.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
            : "exit -";
    }

    private static string FormatScanTargetValue(PicketTuiScanWorkspace scan)
    {
        return scan.TargetMode switch
        {
            PicketTuiScanTargetMode.GitHub => string.Concat("GitHub ", scan.GitHubTargetDisplayValue),
            PicketTuiScanTargetMode.AzureDevOps => string.Concat("Azure DevOps ", FirstNonEmpty(
                scan.AzureDevOpsRepository,
                scan.AzureDevOpsFeed,
                scan.AzureDevOpsProject,
                scan.AzureDevOpsOrganization,
                scan.AzureDevOpsEndpoint,
                "not selected")),
            PicketTuiScanTargetMode.GitLab => string.Concat("GitLab ", FirstNonEmpty(
                scan.GitLabProject,
                scan.GitLabGroup,
                string.Empty,
                "not selected")),
            PicketTuiScanTargetMode.Gitea => string.Concat("Gitea ", FirstNonEmpty(
                scan.GiteaRepository,
                scan.GiteaOrganization,
                scan.GiteaUser,
                scan.GiteaGenericPackageOwner,
                "not selected")),
            PicketTuiScanTargetMode.Bitbucket => string.Concat("Bitbucket ", FirstNonEmpty(
                scan.BitbucketRepository,
                scan.BitbucketWorkspace,
                string.Empty,
                "not selected")),
            PicketTuiScanTargetMode.BitbucketDataCenter => string.Concat("Bitbucket Data Center ", FirstNonEmpty(
                scan.BitbucketDataCenterRepository,
                scan.BitbucketDataCenterProject,
                scan.BitbucketDataCenterApiEndpoint,
                "not selected")),
            PicketTuiScanTargetMode.S3 => string.Concat("S3 ", FirstNonEmpty(
                scan.S3Bucket,
                scan.S3Prefix,
                scan.S3Endpoint,
                "not selected")),
            PicketTuiScanTargetMode.Gcs => string.Concat("GCS ", FirstNonEmpty(
                scan.GcsBucket,
                scan.GcsPrefix,
                scan.GcsEndpoint,
                "not selected")),
            PicketTuiScanTargetMode.AzureBlob => string.Concat("Azure Blob ", FirstNonEmpty(
                scan.AzureBlobContainer,
                scan.AzureBlobPrefix,
                scan.AzureBlobEndpoint,
                "not selected")),
            PicketTuiScanTargetMode.DockerArchive => string.Concat(
                "Docker archive ",
                string.IsNullOrWhiteSpace(scan.DockerArchivePath) ? "not selected" : scan.DockerArchivePath),
            PicketTuiScanTargetMode.OciArchive => string.Concat(
                "OCI archive ",
                string.IsNullOrWhiteSpace(scan.OciArchivePath) ? "not selected" : scan.OciArchivePath),
            PicketTuiScanTargetMode.RegistryImage => string.Concat(
                "Registry image ",
                string.IsNullOrWhiteSpace(scan.RegistryImage) ? "not selected" : scan.RegistryImage),
            _ => string.Concat("Local ", string.IsNullOrWhiteSpace(scan.LocalPath) ? "." : scan.LocalPath),
        };
    }

    private static string FormatLoadedFindingsLine(PicketTuiState state)
    {
        return state.Rows.Count == 0
            ? "No findings loaded. Run a scan to generate a report."
            : state.GetCompactSummaryLine();
    }

    private static string FirstNonEmpty(string first, string second, string third, string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }

        if (!string.IsNullOrWhiteSpace(second))
        {
            return second;
        }

        return !string.IsNullOrWhiteSpace(third) ? third : fallback;
    }

    private static string FirstNonEmpty(string first, string second, string third, string fourth, string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }

        if (!string.IsNullOrWhiteSpace(second))
        {
            return second;
        }

        if (!string.IsNullOrWhiteSpace(third))
        {
            return third;
        }

        return !string.IsNullOrWhiteSpace(fourth) ? fourth : fallback;
    }

    private static string FirstNonEmpty(
        string first,
        string second,
        string third,
        string fourth,
        string fifth,
        string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }

        if (!string.IsNullOrWhiteSpace(second))
        {
            return second;
        }

        if (!string.IsNullOrWhiteSpace(third))
        {
            return third;
        }

        if (!string.IsNullOrWhiteSpace(fourth))
        {
            return fourth;
        }

        return !string.IsNullOrWhiteSpace(fifth) ? fifth : fallback;
    }

    private static ThemePanelWidget BuildStatusText<TParent>(WidgetContext<TParent> ctx, string text, Hex1bColor color)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme.Set(GlobalTheme.ForegroundColor, color),
            ctx.Text(text));
    }

    private static ThemePanelWidget BuildScanCommandPreview<TParent>(
        WidgetContext<TParent> ctx,
        PicketTuiState state,
        bool wrap)
        where TParent : Hex1bWidget
    {
        bool flash = state.CurrentView == PicketTuiView.Scan && state.YankFlashRow;
        string command = state.ScanWorkspace.BuildCommandLinePreview();
        Hex1bWidget text = wrap
            ? ctx.Text(command).Wrap()
            : ctx.Text(string.Concat("Command  ", TrimMiddle(command, DetailLimit)));
        return ctx.ThemePanel(
            theme => theme
                .Set(
                    GlobalTheme.ForegroundColor,
                    flash ? PicketTuiPalette.YankFlashForeground : PicketTuiPalette.CommandForeground)
                .Set(
                    GlobalTheme.BackgroundColor,
                    flash ? PicketTuiPalette.YankFlashBackground : PicketTuiPalette.Background),
            text);
    }

    private static Hex1bColor GetScanStatusColor(PicketTuiScanWorkspace scan)
    {
        if (scan.IsRunning)
        {
            return PicketTuiPalette.InfoForeground;
        }

        if (!scan.LastExitCode.HasValue)
        {
            return PicketTuiPalette.MutedForeground;
        }

        return scan.LastExitCode.GetValueOrDefault() == 0
            ? PicketTuiPalette.SuccessForeground
            : PicketTuiPalette.ErrorForeground;
    }

    private static HStackWidget BuildBooleanField<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        bool value,
        Action<bool> setValue)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.ToggleSwitch(s_booleanOptions, value ? 1 : 0)
                .OnSelectionChanged(e => setValue(e.SelectedIndex == 1))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static HStackWidget BuildChoiceField<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        IReadOnlyList<string> options,
        int selectedIndex,
        Action<int> setValue)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.ToggleSwitch(options, selectedIndex)
                .OnSelectionChanged(e => setValue(e.SelectedIndex))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static HStackWidget BuildPickerField<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        IReadOnlyList<string> options,
        int selectedIndex,
        Action<int> setValue)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.Picker(options, selectedIndex)
                .OnSelectionChanged(e => setValue(e.SelectedIndex))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static HStackWidget BuildTextField<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        string value,
        Action<string> setValue)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.TextBox(value)
                .OnTextChanged(e => setValue(e.NewText))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static ResponsiveWidget BuildFindingsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Responsive(r => [
            r.When((width, _) => width >= FindingsSideBySideMinimumWidth,
                wide => wide.VStack(v => [
                    BuildFindingsToolbar(v, state).FixedHeight(4),
                    v.HStack(h => [
                        BuildFindingTable(h, state).FillWidth(),
                        h.DragBarPanel(BuildFindingDetailsPanel(h, state).Fill())
                            .InitialSize(FindingDetailsWidth)
                            .MinSize(FindingDetailsMinimumWidth)
                            .MaxSize(FindingDetailsMaximumWidth)
                            .HandleEdge(DragBarEdge.Left)
                            .FillHeight()
                    ]).Fill()
                ]).Fill()),
            r.Otherwise(narrow => narrow.VStack(v => [
                BuildFindingsToolbar(v, state).FixedHeight(4),
                BuildFindingTable(v, state).Fill(),
                v.Separator(),
                BuildFindingDetailsPanel(v, state).FixedHeight(5)
            ]).Fill())
        ]).Fill();
    }

    private static VStackWidget BuildFindingsToolbar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                BuildStatusText(h, string.Concat("Findings ", FormatFindingCount(state)), PicketTuiPalette.InfoForeground).FixedWidth(22),
                h.Text(FormatReportName(state.Report.Path)).FillWidth()
            ]).FixedHeight(1),
            BuildBlankLine(v),
            v.HStack(h => [
                h.Text("Filter").FixedWidth(FieldLabelWidth),
                h.TextBox(state.SearchText)
                    .OnTextChanged(e => state.SetSearchText(e.NewText))
                    .FillWidth()
            ]).FixedHeight(1)
        ]);
    }

    private static ResponsiveWidget BuildFindingTable<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Responsive(r => [
            r.When((width, _) => width >= 72,
                wide => BuildFindingTableCore(wide, state, showValidation: true)),
            r.Otherwise(narrow => BuildFindingTableCore(narrow, state, showValidation: false))
        ]).Fill();
    }

    private static TableWidget<PicketTuiFindingRow> BuildFindingTableCore<TParent>(
        WidgetContext<TParent> ctx,
        PicketTuiState state,
        bool showValidation)
        where TParent : Hex1bWidget
    {
        return ctx.Table(state.VisibleRows)
                .RowKey(static row => row.Key)
                .Header(h => BuildFindingTableHeader(h, showValidation))
                .Row((row, finding, _) => BuildFindingTableRow(
                    row,
                    finding,
                    finding.Key.Equals(state.SelectedFindingKey, StringComparison.Ordinal),
                    state.YankFlashRow,
                    showValidation))
                .Focus(state.FocusedFindingKey)
                .OnFocusChanged(key => state.FocusFinding(key))
                .Compact()
                .Empty(e => e.Text(state.Rows.Count == 0
                    ? "No findings loaded yet. Run a scan from the Scan tab."
                    : "No findings match the current filter."))
                .InputBindings(bindings =>
                {
                    bindings.Key(Hex1bKey.Escape).OverridesCapture().Action(
                        context => ClearTableSelectionOrFilter(state, context.Invalidate),
                        "Clear row selection or filter");
                    bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");
                })
                .Fill();
    }

    private static IReadOnlyList<TableCell> BuildFindingTableHeader(TableHeaderContext ctx, bool showValidation)
    {
        return showValidation
            ?
            [
                ctx.Cell("#").Width(SizeHint.Fixed(5)),
                ctx.Cell("Severity").Width(SizeHint.Fixed(10)),
                ctx.Cell("Validation").Width(SizeHint.Fixed(11)),
                ctx.Cell("Rule").Width(SizeHint.Fixed(24)),
                ctx.Cell("Location").Width(SizeHint.Fill),
            ]
            :
            [
                ctx.Cell("#").Width(SizeHint.Fixed(5)),
                ctx.Cell("Severity").Width(SizeHint.Fixed(10)),
                ctx.Cell("Rule").Width(SizeHint.Fixed(22)),
                ctx.Cell("Location").Width(SizeHint.Fill),
            ];
    }

    private static TableCell[] BuildFindingTableRow(
        TableRowContext ctx,
        PicketTuiFindingRow row,
        bool focused,
        bool yankFlash,
        bool showValidation)
    {
        bool flash = focused && yankFlash;
        Hex1bColor foreground = flash
            ? PicketTuiPalette.YankFlashForeground
            : focused
            ? PicketTuiPalette.FocusedRowForeground
            : PicketTuiPalette.Foreground;
        Hex1bColor mutedForeground = flash
            ? PicketTuiPalette.YankFlashForeground
            : focused
            ? PicketTuiPalette.FocusedRowForeground
            : PicketTuiPalette.MutedForeground;
        Hex1bColor background = flash
            ? PicketTuiPalette.YankFlashBackground
            : focused
            ? PicketTuiPalette.FocusedRowBackground
            : PicketTuiPalette.Background;
        Hex1bColor severityForeground = flash || focused
            ? foreground
            : PicketTuiSemanticColors.GetSeverity(row.Severity);
        Hex1bColor validationForeground = flash || focused
            ? foreground
            : PicketTuiSemanticColors.GetValidation(row.ValidationState);

        List<TableCell> cells =
        [
            ctx.Cell(c => BuildFindingTableCell(
                c,
                row.Index.ToString(CultureInfo.InvariantCulture).PadLeft(4),
                mutedForeground,
                background)),
            ctx.Cell(c => BuildFindingTableCell(c, TrimMiddle(row.Severity, 8), severityForeground, background)),
        ];

        if (showValidation)
        {
            cells.Add(ctx.Cell(c => BuildFindingTableCell(
                c,
                FormatValidationState(row.ValidationState),
                validationForeground,
                background)));
        }

        cells.Add(ctx.Cell(c => BuildFindingTableCell(c, TrimMiddle(row.RuleId, showValidation ? 22 : 20), foreground, background)));
        cells.Add(ctx.Cell(c => BuildFindingTableCell(c, TrimMiddle(row.Location, 92), mutedForeground, background)));
        return [.. cells];
    }

    private static ThemePanelWidget BuildFindingTableCell<TParent>(
        WidgetContext<TParent> ctx,
        string text,
        Hex1bColor foreground,
        Hex1bColor background)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme
                .Set(GlobalTheme.ForegroundColor, foreground)
                .Set(GlobalTheme.BackgroundColor, background),
            ctx.Text(text));
    }

    private static PaddingWidget BuildFindingDetailsPanel<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.Padding(
            2,
            0,
            0,
            0,
            BuildReadOnlyEditor(
                ctx,
                state,
                state.GetFindingDetailsEditorState(),
                state.FindingDetailsYankProvider,
                state.MetadataDecorationProvider));
    }

    private static HStackWidget BuildMetadataLine<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        string value)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            BuildStatusText(h, label, PicketTuiPalette.MutedForeground).FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.Text(value).FillWidth()
        ]).FixedHeight(1);
    }

    private static string FormatFindingCount(PicketTuiState state)
    {
        return string.Concat(
            state.VisibleRows.Count.ToString(CultureInfo.InvariantCulture),
            "/",
            state.Rows.Count.ToString(CultureInfo.InvariantCulture));
    }

    private static VStackWidget BuildRulesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Rules by finding count"),
            BuildBlankLine(v),
            BuildCountTable(
                v,
                state,
                state.GetTopRules(50),
                "Rule",
                state.FocusedRuleKey,
                state.SelectedRuleKey,
                state.FocusRule,
                PicketTuiCountTableKind.Rules).Fill()
        ]).Fill();
    }

    private static VStackWidget BuildFilesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Files by finding count"),
            BuildBlankLine(v),
            BuildCountTable(
                v,
                state,
                state.GetTopFiles(50),
                "File",
                state.FocusedFileKey,
                state.SelectedFileKey,
                state.FocusFile,
                PicketTuiCountTableKind.Files).Fill()
        ]).Fill();
    }

    private static VStackWidget BuildLogsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                h.Text("Search").FixedWidth(FieldLabelWidth),
                h.Text("  "),
                h.TextBox(state.LogSearchText)
                    .OnTextChanged(e => state.SetLogSearchText(e.NewText))
                    .FillWidth()
            ]).FixedHeight(1),
            BuildBlankLine(v),
            BuildReadOnlyEditor(
                v,
                state,
                state.GetLogsEditorState(),
                state.LogsYankProvider,
                state.MetadataDecorationProvider,
                state.LogDecorationProvider).Fill()
        ]).Fill();
    }

    private static InfoBarWidget BuildInfoBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        string status = state.CurrentView == PicketTuiView.Scan
            ? state.ScanWorkspace.Status
            : state.StatusMessage;

        return ctx.InfoBar(s =>
        {
            var hints = new List<IInfoBarChild>
            {
                state.ScanWorkspace.IsRunning
                    ? s.Section(inner => inner.HStack(h => [
                        h.Spinner(SpinnerStyle.Dots),
                        h.Text(" "),
                        h.Text(TrimEnd(status, 82)),
                    ]))
                    : s.Section(TrimEnd(status, 84)),
            };

            AddContextualHints(s, state, hints);
            hints.Add(s.Spacer());

            if (!string.IsNullOrEmpty(state.YankNotification))
            {
                hints.Add(s.Section(state.YankNotification).Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.SuccessForeground)));
                hints.Add(s.Divider(" "));
            }

            hints.Add(s.Section("? help"));
            hints.Add(s.Section("Ctrl+Q quit"));
            return hints;
        }, invertColors: false).Divider(" | ");
    }

    private static void AddContextualHints(InfoBarContext ctx, PicketTuiState state, List<IInfoBarChild> hints)
    {
        switch (state.CurrentView)
        {
            case PicketTuiView.Scan:
                if (state.ScanWorkspace.IsRunning)
                {
                    hints.Add(ctx.Section("Ctrl+C cancel").Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.WarningForeground)).FixedWidth(15));
                }
                else
                {
                    hints.Add(ctx.Section("Ctrl+R run").Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.CommandForeground)));
                }

                if (state.Rows.Count != 0)
                {
                    hints.Add(ctx.Section("g f findings"));
                }

                break;
            case PicketTuiView.Findings:
                if (state.SearchText.Length != 0)
                {
                    hints.Add(ctx.Section("Esc clear"));
                }

                hints.Add(ctx.Section("j/k move"));
                hints.Add(ctx.Section("o open"));
                hints.Add(ctx.Section("g s scan"));
                break;
            case PicketTuiView.Dashboard:
                hints.Add(ctx.Section("g s scan"));
                if (state.Rows.Count != 0)
                {
                    hints.Add(ctx.Section("g f findings"));
                }

                break;
            case PicketTuiView.Rules:
                hints.Add(ctx.Section("f filter"));
                hints.Add(ctx.Section("g s scan"));
                break;
            case PicketTuiView.Files:
                hints.Add(ctx.Section("f filter"));
                hints.Add(ctx.Section("o open"));
                hints.Add(ctx.Section("g s scan"));
                break;
            case PicketTuiView.Logs:
                if (state.LogSearchText.Length != 0)
                {
                    hints.Add(ctx.Section("Esc clear"));
                }

                hints.Add(ctx.Section("g s scan"));
                break;
        }

        if (state.HasYankText)
        {
            hints.Add(ctx.Section("y yank"));
        }
    }

    private static TableWidget<KeyValuePair<string, int>> BuildCountTable<TParent>(
        WidgetContext<TParent> ctx,
        PicketTuiState state,
        List<KeyValuePair<string, int>> rows,
        string keyHeader,
        string? focusedKey,
        string? selectedKey,
        Action<object?> focus,
        PicketTuiCountTableKind kind)
        where TParent : Hex1bWidget
    {
        return ctx.Table(rows)
            .RowKey(static row => row.Key)
            .Header(h =>
            [
                h.Cell("Findings").Width(SizeHint.Fixed(12)),
                h.Cell(keyHeader).Width(SizeHint.Fill)
            ])
            .Row((row, value, _) => BuildCountTableRow(
                row,
                value,
                value.Key.Equals(selectedKey, StringComparison.Ordinal),
                state.YankFlashRow
                    && state.FocusedCountTableKind == kind
                    && value.Key.Equals(selectedKey, StringComparison.Ordinal)))
            .Focus(focusedKey)
            .OnFocusChanged(focus)
            .Compact()
            .Empty(e => e.Text("No findings."))
            .InputBindings(bindings =>
            {
                bindings.Key(Hex1bKey.Escape).OverridesCapture().Action(
                    context => ClearTableSelectionOrFilter(state, context.Invalidate),
                    "Clear row selection");
                bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");
            })
            .Fill();
    }

    private static TableCell[] BuildCountTableRow(
        TableRowContext ctx,
        KeyValuePair<string, int> row,
        bool focused,
        bool yankFlash)
    {
        bool flash = yankFlash;
        Hex1bColor foreground = flash
            ? PicketTuiPalette.YankFlashForeground
            : focused
            ? PicketTuiPalette.FocusedRowForeground
            : PicketTuiPalette.Foreground;
        Hex1bColor mutedForeground = flash
            ? PicketTuiPalette.YankFlashForeground
            : focused
            ? PicketTuiPalette.FocusedRowForeground
            : PicketTuiPalette.CommandForeground;
        Hex1bColor background = flash
            ? PicketTuiPalette.YankFlashBackground
            : focused
            ? PicketTuiPalette.FocusedRowBackground
            : PicketTuiPalette.Background;

        return
        [
            ctx.Cell(c => BuildFindingTableCell(
                c,
                row.Value.ToString(CultureInfo.InvariantCulture).PadLeft(8),
                mutedForeground,
                background)),
            ctx.Cell(c => BuildFindingTableCell(c, TrimMiddle(row.Key, DetailLimit), foreground, background)),
        ];
    }

    private static ThemePanelWidget BuildReadOnlyEditor<TParent>(
        WidgetContext<TParent> ctx,
        PicketTuiState state,
        EditorState editorState,
        PicketTuiYankDecorationProvider yankProvider,
        ITextDecorationProvider? primaryDecorationProvider = null,
        ITextDecorationProvider? secondaryDecorationProvider = null)
        where TParent : Hex1bWidget
    {
        EditorWidget editor = ctx.Editor(editorState)
            .WordWrap()
            .ViewRenderer(PicketTuiReadOnlyEditorViewRenderer.Instance)
            .FillWidth()
            .FillHeight()
            .InputBindings(bindings => ConfigureReadOnlyEditorBindings(bindings, state, editorState));
        if (primaryDecorationProvider is not null)
        {
            editor = editor.Decorations(primaryDecorationProvider);
        }

        if (secondaryDecorationProvider is not null)
        {
            editor = editor.Decorations(secondaryDecorationProvider);
        }

        editor = editor.Decorations(yankProvider);

        return ctx.ThemePanel(
            theme => theme
                .Set(EditorTheme.SelectionForegroundColor, PicketTuiPalette.FocusedRowForeground)
                .Set(EditorTheme.SelectionBackgroundColor, PicketTuiPalette.EditorSelectionBackground),
            editor);
    }

    private static void ConfigureReadOnlyEditorBindings(
        InputBindingsBuilder bindings,
        PicketTuiState state,
        EditorState editorState)
    {
        ConfigureViewNavigationBindings(bindings, state);
        ConfigureNumberedViewBindings(bindings, state);
        bindings.Key(Hex1bKey.Escape).OverridesCapture().Action(
            context => ClearEditorSelectionOrFilter(state, editorState, context.Invalidate),
            "Clear text selection, row selection, or filter");
        bindings.Key(Hex1bKey.OemQuestion).Action(
            context => OpenHelpFromUi(state, context.Invalidate),
            "Keyboard help");
        bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");

        if (state.CurrentView == PicketTuiView.Findings)
        {
            bindings.Key(Hex1bKey.O).Action(context => OpenFocusedFindingFromUi(state, context), "Open file");
        }
    }

    private static void ClearEditorSelectionOrFilter(
        PicketTuiState state,
        EditorState editorState,
        Action invalidate)
    {
        if (editorState.Cursor.HasSelection)
        {
            editorState.Cursor.ClearSelection();
            invalidate();
            return;
        }

        ClearTableSelectionOrFilter(state, invalidate);
    }

    private static void ClearSelectionOrFilter(PicketTuiState state, Action invalidate)
    {
        if (state.TryGetSelectedEditorText(
            null,
            out _,
            out EditorState editorState,
            out _,
            out _))
        {
            editorState.Cursor.ClearSelection();
            invalidate();
            return;
        }

        ClearTableSelectionOrFilter(state, invalidate);
    }

    private static void HandleLogsEscape(PicketTuiState state, InputBindingActionContext context)
    {
        bool searchHasFocus = context.FocusedNode is TextBoxNode;
        ClearSelectionOrFilter(state, context.Invalidate);
        if (searchHasFocus)
        {
            context.FocusNext();
            context.Invalidate();
        }
    }

    private static void ClearTableSelectionOrFilter(PicketTuiState state, Action invalidate)
    {
        if (state.ClearSelectedRows())
        {
            invalidate();
            return;
        }

        if (state.CurrentView == PicketTuiView.Findings && state.SearchText.Length != 0)
        {
            state.ClearSearch();
            invalidate();
            return;
        }

        if (state.CurrentView == PicketTuiView.Logs && state.LogSearchText.Length != 0)
        {
            state.SetLogSearchText(string.Empty);
            invalidate();
        }
    }

    private static Hex1bWidget[] BuildScanOutput<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return
        [
            BuildSectionTitle(ctx, "Latest scanner output"),
            BuildBlankLine(ctx),
            .. BuildScannerOutputLines(ctx, scan.CapturedOutputLines),
        ];
    }

    private static Hex1bWidget[] BuildScannerOutputLines<TParent>(WidgetContext<TParent> ctx, IReadOnlyList<string> lines)
        where TParent : Hex1bWidget
    {
        var widgets = new List<Hex1bWidget>();

        if (lines.Count == 0)
        {
            widgets.Add(ctx.Text("No scanner output captured."));
            return [.. widgets];
        }

        int start = Math.Max(0, lines.Count - OutputPreviewLimit);
        for (int i = start; i < lines.Count; i++)
        {
            widgets.Add(ctx.Text(TrimEnd(lines[i], DetailLimit)).Wrap());
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

    private static string FormatReportName(string path)
    {
        string fileName = Path.GetFileName(path);
        return fileName.Length == 0 ? path : fileName;
    }

    private static string FormatValidationState(string validationState)
    {
        if (validationState.Equals("structurally-valid", StringComparison.OrdinalIgnoreCase))
        {
            return "valid";
        }

        return validationState.Equals("test-credential", StringComparison.OrdinalIgnoreCase)
            ? "test"
            : TrimMiddle(validationState, 9);
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

    private static void RunScanFromUi(PicketTuiState state, Action invalidate, CancellationToken cancellationToken)
    {
        state.StartScanInBackground(invalidate, cancellationToken);
    }

    private static void MoveFindingFromUi(PicketTuiState state, Action invalidate, int delta)
    {
        state.MoveFindingFocus(delta);
        invalidate();
    }

    private static void OpenFocusedFindingFromUi(PicketTuiState state, InputBindingActionContext context)
    {
        if (state.RequestOpenFocusedFindingFile())
        {
            context.RequestStop();
            return;
        }

        context.Invalidate();
    }

    private static void OpenFocusedFileFromUi(PicketTuiState state, InputBindingActionContext context)
    {
        if (state.RequestOpenFocusedFile())
        {
            context.RequestStop();
            return;
        }

        context.Invalidate();
    }

    private static void FilterRuleFromUi(PicketTuiState state, Action invalidate)
    {
        state.FilterFindingsToFocusedRule();
        invalidate();
    }

    private static void FilterFileFromUi(PicketTuiState state, Action invalidate)
    {
        state.FilterFindingsToFocusedFile();
        invalidate();
    }

    private static void ActivateScanButton(PicketTuiState state, Action invalidate, CancellationToken cancellationToken)
    {
        if (state.ScanWorkspace.IsRunning)
        {
            state.CancelScan(invalidate);
            return;
        }

        RunScanFromUi(state, invalidate, cancellationToken);
    }

    private static void CancelScanFromUi(PicketTuiState state, Action invalidate)
    {
        state.CancelScan(invalidate);
    }

    private static void YankCurrentView(PicketTuiState state, InputBindingActionContext context)
    {
        EditorState? focusedEditor = context.FocusedNode is EditorNode editor
            ? editor.State
            : null;
        if (state.TryGetSelectedEditorText(
            focusedEditor,
            out string selectionText,
            out EditorState selectedEditorState,
            out PicketTuiYankDecorationProvider yankProvider,
            out DocumentRange range))
        {
            context.CopyToClipboard(selectionText);
            state.ShowEditorYankNotification(
                selectionText,
                selectedEditorState,
                yankProvider,
                range,
                context.Invalidate,
                context.CancellationToken);
            context.Invalidate();
            return;
        }

        if (state.TryGetFocusedEditorYankTarget(
            focusedEditor,
            out string editorText,
            out EditorState wholeEditorState,
            out PicketTuiYankDecorationProvider wholeEditorYankProvider,
            out DocumentRange wholeEditorRange))
        {
            context.CopyToClipboard(editorText);
            state.ShowEditorYankNotification(
                editorText,
                wholeEditorState,
                wholeEditorYankProvider,
                wholeEditorRange,
                context.Invalidate,
                context.CancellationToken);
            context.Invalidate();
            return;
        }

        string text = state.GetYankText();
        if (text.Length == 0)
        {
            return;
        }

        context.CopyToClipboard(text);
        state.ShowYankNotification(text, context.Invalidate, context.CancellationToken);
        context.Invalidate();
    }
}
