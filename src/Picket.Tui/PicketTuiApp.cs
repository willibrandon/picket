using Hex1b;
using Hex1b.Input;
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
    private const int FieldLabelWidth = 16;
    private const int OutputPreviewLimit = 7;
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
        return ctx.ThemePanel(
            PicketTuiPalette.Apply,
            ctx.VStack(main => [
                BuildTitleBar(main, state),
                BuildMainTabs(main, state),
                main.Padding(3, 3, 2, 1, BuildActiveView(main, state).Fill()).Fill(),
                BuildInfoBar(main, state)
            ]).InputBindings(bindings =>
            {
                bindings.Ctrl().Key(Hex1bKey.Q).Action(context => context.RequestStop(), "Quit");
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
                    "Cancel scan");
                bindings.Ctrl().Key(Hex1bKey.R).Global().OverridesCapture().Action(
                    context => RunScanFromUi(state, context.Invalidate, context.CancellationToken),
                    "Run scan");
                if (state.CurrentView == PicketTuiView.Findings && state.SearchText.Length != 0)
                {
                    bindings.Key(Hex1bKey.Escape).Action(_ => state.ClearSearch(), "Clear filter");
                }

                if (state.CurrentView == PicketTuiView.Findings)
                {
                    bindings.Key(Hex1bKey.J).Global().Action(context => MoveFindingFromUi(state, context.Invalidate, 1), "Next finding");
                    bindings.Key(Hex1bKey.K).Global().Action(context => MoveFindingFromUi(state, context.Invalidate, -1), "Previous finding");
                }

                bindings.Key(Hex1bKey.F5).Global().Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.S).Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.D).Action(_ => state.SetView(PicketTuiView.Dashboard), "Dashboard");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.F).Action(_ => state.SetView(PicketTuiView.Findings), "Findings");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.R).Action(_ => state.SetView(PicketTuiView.Rules), "Rules");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.L).Action(_ => state.SetView(PicketTuiView.Logs), "Logs");
                bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");
            }));
    }

    private static HStackWidget BuildTitleBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.InfoBar(bar =>
            [
                bar.Section(" Picket ").Theme(theme => theme
                    .Set(GlobalTheme.ForegroundColor, PicketTuiPalette.PrimaryActionForeground)
                    .Set(GlobalTheme.BackgroundColor, PicketTuiPalette.PrimaryActionBackground)),
                bar.Divider(" "),
                bar.Section(state.GetSummaryLine()).Theme(theme => theme
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
            v.HStack(h => [
                BuildPanel(h, " Report ", h.VStack(report => [
                    BuildMetadataLine(report, "Findings", state.Rows.Count.ToString(CultureInfo.InvariantCulture)),
                    BuildMetadataLine(report, "Files", state.Report.Summary.FileCount.ToString(CultureInfo.InvariantCulture)),
                    BuildMetadataLine(report, "Format", state.Report.Summary.Format),
                    BuildMetadataLine(report, "Loaded", state.Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
                    BuildMetadataLine(report, "Report", TrimMiddle(state.Report.Path, DetailLimit)),
                ])).FillWidth(),
                h.Text("    "),
                BuildPanel(h, " Scanner ", h.VStack(scan => [
                    BuildMetadataLine(scan, "Status", state.ScanWorkspace.Status),
                    BuildMetadataLine(scan, "Target", FormatScanTargetValue(state.ScanWorkspace)),
                    BuildMetadataLine(scan, "Output", state.ScanWorkspace.CapturedOutputLines.Count == 0 ? "No captured output" : "Open Logs"),
                ])).FixedWidth(52)
            ]).FixedHeight(8),
            BuildSectionGap(v),
            v.HStack(h => [
                BuildPanel(h, " Top rules ", h.VStack(left => BuildCountList(left, state.GetTopRules(TopListLimit))).Fill()).FillWidth(),
                h.Text("    "),
                BuildPanel(h, " Top files ", h.VStack(right => BuildCountList(right, state.GetTopFiles(TopListLimit))).Fill()).FillWidth()
            ]).Fill(),
        ]).Fill();
    }

    private static ResponsiveWidget BuildScanWorkspace<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.Responsive(r => [
            r.When((width, _) => width >= 100,
                wide => wide.VStack(v => [
                    BuildScanStatusStrip(v, state).FixedHeight(5),
                    v.Separator(),
                    v.HSplitter(
                        left => [BuildScanConfigurationPane(left, scan).Fill()],
                        right => [BuildScanCommandPane(right, state)],
                        leftWidth: 86).Fill()
                ]).Fill()),
            r.Otherwise(narrow => narrow.VStack(v => [
                BuildScanStatusStrip(v, state).FixedHeight(5),
                v.Separator(),
                BuildScanConfigurationPane(v, scan).Fill()
            ]).Fill())
        ]).Fill();
    }

    private static VStackWidget BuildScanStatusStrip<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.VStack(v => [
            v.HStack(h => [
                BuildRunScanButton(h, state).FixedWidth(14),
                h.Text("  "),
                BuildStatusText(h, scan.Status, GetScanStatusColor(scan)).FillWidth(),
                BuildStatusText(h, FormatScanExit(scan), PicketTuiPalette.MutedForeground).FixedWidth(10)
            ]).FixedHeight(1),
            BuildBlankLine(v),
            v.HStack(h => [
                BuildMetadataLine(h, "Target", FormatScanTargetValue(scan)).FillWidth(),
                h.Text("    "),
                BuildMetadataLine(h, "Report", TrimMiddle(scan.ReportPath, 72)).FillWidth()
            ]).FixedHeight(1),
            v.HStack(h => [
                BuildMetadataLine(h, "Findings", FormatLoadedFindingsLine(state)).FillWidth(),
                h.Text("    "),
                BuildMetadataLine(h, "Timing", FormatScanTiming(scan)).FillWidth()
            ]).FixedHeight(1)
        ]);
    }

    private static VStackWidget BuildScanCommandPane<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Command"),
            BuildBlankLine(v),
            BuildWrappedStatusText(v, scan.BuildCommandLinePreview(), PicketTuiPalette.CommandForeground).FillWidth(),
            BuildSectionGap(v),
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
            BuildTargetModeRow(v, scan),
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
            BuildFieldGap(v),
            BuildBooleanField(v, "Verify", scan.Verify, scan.SetVerify),
            BuildSectionGap(v),
            BuildStatusText(v, "Live verification only runs when Verify is On.", PicketTuiPalette.MutedForeground)
        ]);
    }

    private static VStackWidget BuildLimitSettingsPage<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v =>
        {
            var widgets = new List<Hex1bWidget>
            {
                BuildSectionTitle(v, "Local and archive limits"),
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
            }

            return [.. widgets];
        });
    }

    private static HStackWidget BuildTargetModeRow<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text("Target").FixedWidth(FieldLabelWidth),
            h.Text("  "),
            h.ToggleSwitch(PicketTuiScanWorkspace.TargetModeLabels, scan.TargetModeIndex)
                .OnSelectionChanged(e => scan.SetTargetMode(e.SelectedIndex))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static ThemePanelWidget BuildSectionTitle<TParent>(WidgetContext<TParent> ctx, string text)
        where TParent : Hex1bWidget
    {
        return BuildStatusText(ctx, text, PicketTuiPalette.InfoForeground);
    }

    private static BorderWidget BuildPanel<TParent>(WidgetContext<TParent> ctx, string title, Hex1bWidget content)
        where TParent : Hex1bWidget
    {
        return ctx.Border(ctx.Padding(1, 1, 0, 0, content)).Title(title);
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

    private static TextBlockWidget BuildFieldGap<TParent>(WidgetContext<TParent> ctx)
        where TParent : Hex1bWidget
    {
        return ctx.Text("").FixedHeight(0);
    }

    private static VStackWidget BuildOutputFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildChoiceField(v, "Format", PicketTuiScanWorkspace.ReportFormats, scan.ReportFormatIndex, scan.SetReportFormatByIndex),
            BuildFieldGap(v),
            BuildTextField(v, "Redact", scan.RedactionPercent, scan.SetRedactionPercent),
            BuildFieldGap(v),
            BuildBooleanField(v, "Verify", scan.Verify, scan.SetVerify)
        ]);
    }

    private static VStackWidget BuildOutputPathFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildTextField(v, "Report", scan.ReportPath, scan.SetReportPath),
            BuildFieldGap(v),
            BuildTextField(v, "Profile", scan.Profile, scan.SetProfile),
            BuildFieldGap(v),
            BuildTextField(v, "Config", scan.ConfigPath, scan.SetConfigPath),
            BuildFieldGap(v),
            BuildTextField(v, "Ignore", scan.IgnorePath, scan.SetIgnorePath)
        ]);
    }

    private static VStackWidget BuildFilterFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildBooleanField(v, "No ignore", scan.NoIgnore, scan.SetNoIgnore),
            BuildFieldGap(v),
            BuildBooleanField(v, "Only valid", scan.OnlyVerified, scan.SetOnlyVerified),
            BuildFieldGap(v),
            BuildChoiceField(v, "Results", PicketTuiScanWorkspace.ResultFilterDisplayLabels, scan.ResultFilterIndex, scan.SetResultFilterByIndex),
            BuildFieldGap(v),
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
            _ =>
            [
                BuildTextField(ctx, "Path", scan.LocalPath, scan.SetLocalPath),
            ],
        };
    }

    private static HStackWidget BuildGitHubSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Repository", scan.GitHubRepository, scan.SetGitHubRepository),
                BuildFieldGap(left),
                BuildTextField(left, "Org", scan.GitHubOrganization, scan.SetGitHubOrganization),
                BuildFieldGap(left),
                BuildTextField(left, "User", scan.GitHubUser, scan.SetGitHubUser),
                BuildFieldGap(left),
                BuildTextField(left, "Token env", scan.GitHubTokenEnvironmentVariable, scan.SetGitHubTokenEnvironmentVariable),
                BuildFieldGap(left),
                BuildTextField(left, "Gist", scan.GitHubGist, scan.SetGitHubGist),
                BuildFieldGap(left),
                BuildTextField(left, "User gists", scan.GitHubUserGists, scan.SetGitHubUserGists),
                BuildFieldGap(left),
                BuildTextField(left, "Endpoint", scan.GitHubSourceApiEndpoint, scan.SetGitHubSourceApiEndpoint),
                BuildFieldGap(left),
                BuildTextField(left, "Ref", scan.GitHubRef, scan.SetGitHubRef),
                BuildFieldGap(left),
                BuildTextField(left, "PR", scan.GitHubPullRequest, scan.SetGitHubPullRequest),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Repo type", PicketTuiScanWorkspace.GitHubRepositoryTypes, scan.GitHubRepositoryTypeIndex, scan.SetGitHubRepositoryTypeByIndex),
                BuildFieldGap(right),
                BuildChoiceField(right, "Issue state", PicketTuiScanWorkspace.GitHubIssueStates, scan.GitHubIssueStateIndex, scan.SetGitHubIssueStateByIndex),
                BuildFieldGap(right),
                BuildBooleanField(right, "Issues", scan.IncludeGitHubIssues, scan.SetIncludeGitHubIssues),
                BuildFieldGap(right),
                BuildBooleanField(right, "Releases", scan.IncludeGitHubReleases, scan.SetIncludeGitHubReleases),
                BuildFieldGap(right),
                BuildBooleanField(right, "Actions", scan.IncludeGitHubActionsArtifacts, scan.SetIncludeGitHubActionsArtifacts),
                BuildFieldGap(right),
                BuildBooleanField(right, "Gists", scan.IncludeGitHubGists, scan.SetIncludeGitHubGists),
                BuildFieldGap(right),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildFieldGap(right),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static HStackWidget BuildAzureDevOpsSourceFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.VStack(left => [
                BuildTextField(left, "Org", scan.AzureDevOpsOrganization, scan.SetAzureDevOpsOrganization),
                BuildFieldGap(left),
                BuildTextField(left, "Endpoint", scan.AzureDevOpsEndpoint, scan.SetAzureDevOpsEndpoint),
                BuildFieldGap(left),
                BuildTextField(left, "Token env", scan.AzureDevOpsTokenEnvironmentVariable, scan.SetAzureDevOpsTokenEnvironmentVariable),
                BuildFieldGap(left),
                BuildTextField(left, "Project", scan.AzureDevOpsProject, scan.SetAzureDevOpsProject),
                BuildFieldGap(left),
                BuildTextField(left, "Repo", scan.AzureDevOpsRepository, scan.SetAzureDevOpsRepository),
                BuildFieldGap(left),
                BuildTextField(left, "Branch", scan.AzureDevOpsBranch, scan.SetAzureDevOpsBranch),
                BuildFieldGap(left),
                BuildTextField(left, "PR", scan.AzureDevOpsPullRequest, scan.SetAzureDevOpsPullRequest),
                BuildFieldGap(left),
                BuildTextField(left, "Build ID", scan.AzureDevOpsBuildId, scan.SetAzureDevOpsBuildId),
                BuildFieldGap(left),
                BuildTextField(left, "Release ID", scan.AzureDevOpsReleaseId, scan.SetAzureDevOpsReleaseId),
            ]).FillWidth(),
            h.Text("      "),
            h.VStack(right => [
                BuildChoiceField(right, "Token", PicketTuiScanWorkspace.AzureDevOpsTokenKinds, scan.AzureDevOpsTokenKindIndex, scan.SetAzureDevOpsTokenKindByIndex),
                BuildFieldGap(right),
                BuildBooleanField(right, "Wikis", scan.IncludeAzureDevOpsWikis, scan.SetIncludeAzureDevOpsWikis),
                BuildFieldGap(right),
                BuildBooleanField(right, "Artifacts", scan.IncludeAzureDevOpsArtifacts, scan.SetIncludeAzureDevOpsArtifacts),
                BuildFieldGap(right),
                BuildBooleanField(right, "Logs", scan.IncludeAzureDevOpsLogs, scan.SetIncludeAzureDevOpsLogs),
                BuildFieldGap(right),
                BuildBooleanField(right, "Releases", scan.IncludeAzureDevOpsReleaseArtifacts, scan.SetIncludeAzureDevOpsReleaseArtifacts),
                BuildFieldGap(right),
                BuildTextField(right, "Artifact MB", scan.AzureDevOpsMaxArtifactMegabytes, scan.SetAzureDevOpsMaxArtifactMegabytes),
                BuildFieldGap(right),
                BuildTextField(right, "Log MB", scan.AzureDevOpsMaxLogMegabytes, scan.SetAzureDevOpsMaxLogMegabytes),
                BuildFieldGap(right),
                BuildBooleanField(right, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints),
                BuildFieldGap(right),
                BuildBooleanField(right, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints),
            ]).FillWidth(),
        ]).FillWidth();
    }

    private static VStackWidget BuildLimitFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildTextField(v, "Max MB", scan.MaxTargetMegabytes, scan.SetMaxTargetMegabytes),
            BuildFieldGap(v),
            BuildTextField(v, "Depth", scan.MaxArchiveDepth, scan.SetMaxArchiveDepth),
            BuildFieldGap(v),
            BuildTextField(v, "Entries", scan.MaxArchiveEntries, scan.SetMaxArchiveEntries),
            BuildFieldGap(v),
            BuildTextField(v, "Archive MB", scan.MaxArchiveMegabytes, scan.SetMaxArchiveMegabytes),
            BuildFieldGap(v),
            BuildTextField(v, "Ratio", scan.MaxArchiveRatio, scan.SetMaxArchiveRatio),
            BuildFieldGap(v),
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
            PicketTuiScanTargetMode.GitHub => string.Concat("GitHub ", FirstNonEmpty(
                scan.GitHubRepository,
                scan.GitHubOrganization,
                scan.GitHubUser,
                scan.GitHubGist,
                "not selected")),
            PicketTuiScanTargetMode.AzureDevOps => string.Concat("Azure DevOps ", FirstNonEmpty(
                scan.AzureDevOpsRepository,
                scan.AzureDevOpsProject,
                scan.AzureDevOpsOrganization,
                "not selected")),
            _ => string.Concat("Local ", string.IsNullOrWhiteSpace(scan.LocalPath) ? "." : scan.LocalPath),
        };
    }

    private static string FormatLoadedFindingsLine(PicketTuiState state)
    {
        return state.Rows.Count == 0
            ? "No findings loaded. Run a scan to generate a report."
            : state.GetSummaryLine();
    }

    private static string FormatScanTiming(PicketTuiScanWorkspace scan)
    {
        if (!scan.LastStartedAt.HasValue)
        {
            return "Not run";
        }

        if (!scan.LastCompletedAt.HasValue)
        {
            return string.Concat("Started: ", FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()), " (running)");
        }

        return string.Concat(
            "Completed: ",
            FormatTimestamp(scan.LastCompletedAt.GetValueOrDefault()),
            " (",
            FormatElapsed(scan.LastElapsed.GetValueOrDefault()),
            ")");
    }

    private static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
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

    private static string FormatElapsed(TimeSpan value)
    {
        return value.TotalSeconds < 1
            ? string.Create(CultureInfo.InvariantCulture, $"{value.TotalMilliseconds:0} ms")
            : string.Create(CultureInfo.InvariantCulture, $"{value.TotalSeconds:0.0} s");
    }

    private static ThemePanelWidget BuildStatusText<TParent>(WidgetContext<TParent> ctx, string text, Hex1bColor color)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme.Set(GlobalTheme.ForegroundColor, color),
            ctx.Text(text));
    }

    private static ThemePanelWidget BuildWrappedStatusText<TParent>(WidgetContext<TParent> ctx, string text, Hex1bColor color)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme.Set(GlobalTheme.ForegroundColor, color),
            ctx.Text(text).Wrap());
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
            r.When((width, _) => width >= 112,
                wide => wide.VStack(v => [
                    BuildFindingsToolbar(v, state).FixedHeight(4),
                    v.HSplitter(
                        left => [BuildFindingList(left, state).Fill()],
                        right => [BuildFindingDetailsPanel(right, state.FocusedFinding).Fill()],
                        leftWidth: 72).Fill()
                ]).Fill()),
            r.Otherwise(narrow => narrow.VStack(v => [
                BuildFindingsToolbar(v, state).FixedHeight(4),
                BuildFindingList(v, state).Fill(),
                BuildBlankLine(v),
                BuildFindingDetailsPanel(v, state.FocusedFinding).FixedHeight(9)
            ]).Fill())
        ]).Fill();
    }

    private static VStackWidget BuildFindingsToolbar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                BuildStatusText(h, string.Concat("Findings ", FormatFindingCount(state)), PicketTuiPalette.InfoForeground).FixedWidth(22),
                h.Text(TrimMiddle(state.Report.Path, DetailLimit)).FillWidth()
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

    private static VStackWidget BuildFindingList<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        int focusedIndex = Math.Max(0, state.IndexOfVisibleRowKey(state.FocusedFindingKey));
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Findings"),
            BuildBlankLine(v),
            v.List(state.VisibleRows)
                .ItemHeight(2)
                .ItemKey(static row => row.Key)
                .FocusedIndex(focusedIndex)
                .OnFocusChanged(e => state.FocusFinding(e.FocusedItem.Key))
                .ItemTemplate(rowContext => BuildFindingListRow(rowContext, state.YankFlashRow))
                .Empty(e => e.Text(state.Rows.Count == 0
                    ? "No findings loaded yet. Run a scan from the Scan tab."
                    : "No findings match the current filter."))
                .Fill()
        ]).Fill();
    }

    private static VStackWidget BuildFindingListRow(ListItemContext<PicketTuiFindingRow> ctx, bool yankFlash)
    {
        PicketTuiFindingRow row = ctx.Item;
        bool flash = ctx.IsFocused && yankFlash;
        Hex1bColor markerForeground = flash
            ? PicketTuiPalette.YankFlashForeground
            : ctx.IsFocused
            ? PicketTuiPalette.FocusForeground
            : PicketTuiPalette.MutedForeground;
        Hex1bColor markerBackground = flash
            ? PicketTuiPalette.YankFlashBackground
            : ctx.IsFocused
            ? PicketTuiPalette.FocusBackground
            : PicketTuiPalette.Background;
        Hex1bColor ruleColor = flash
            ? PicketTuiPalette.YankFlashForeground
            : ctx.IsFocused
            ? PicketTuiPalette.InfoForeground
            : PicketTuiPalette.Foreground;

        return ctx.VStack(v => [
            v.HStack(h => [
                BuildInlineBadge(h, ctx.IsFocused ? ">" : " ", markerForeground, markerBackground).FixedWidth(2),
                h.Text(" "),
                BuildStatusText(h, row.Index.ToString(CultureInfo.InvariantCulture).PadLeft(3), PicketTuiPalette.MutedForeground).FixedWidth(4),
                h.Text(" "),
                BuildStatusText(h, TrimMiddle(row.RuleId, 45), ruleColor).FillWidth()
            ]).FillWidth(),
            v.HStack(h => [
                h.Text("       "),
                BuildStatusText(h, TrimMiddle(row.Location, 60), PicketTuiPalette.MutedForeground).FillWidth()
            ]).FillWidth()
        ]).FillWidth();
    }

    private static VStackWidget BuildFindingDetailsPanel<TParent>(WidgetContext<TParent> ctx, PicketTuiFindingRow? row)
        where TParent : Hex1bWidget
    {
        if (row is null)
        {
            return ctx.VStack(v => [
                BuildSectionTitle(v, "No finding selected"),
                BuildBlankLine(v),
                v.Text("Run a scan or adjust the filter.")
            ]);
        }

        return ctx.VStack(v => [
            BuildSectionTitle(v, string.Concat("Finding ", row.Index.ToString(CultureInfo.InvariantCulture))),
            BuildBlankLine(v),
            BuildStatusText(v, row.RuleId, PicketTuiPalette.InfoForeground),
            BuildSectionGap(v),
            BuildMetadataLine(v, "Rule", row.RuleId),
            BuildMetadataLine(v, "Path", TrimEnd(row.Path, DetailLimit)),
            BuildMetadataLine(v, "Line", row.Line),
            BuildMetadataLine(v, "Fingerprint", TrimMiddle(row.Fingerprint, 96)),
            BuildSectionGap(v),
            BuildStatusText(v, "Secret evidence is intentionally not loaded in this summary view.", PicketTuiPalette.MutedForeground)
        ]);
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
        return ctx.VStack(v => BuildCountList(v, state.GetTopRules(24))).Fill();
    }

    private static VStackWidget BuildFilesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => BuildCountList(v, state.GetTopFiles(24))).Fill();
    }

    private static VStackWidget BuildLogsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.Text(string.Concat("Loaded: ", state.Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))),
            v.Text(string.Concat("Report: ", state.Report.Path)).Wrap(),
            v.Text(string.Concat("Status: ", state.StatusMessage)).Wrap(),
            v.Text(string.Concat("Scan: ", state.ScanWorkspace.Status)).Wrap(),
            v.Text(string.Concat("Last run: ", state.ScanWorkspace.LastMessage)).Wrap(),
            v.Text(string.Concat("Filter: ", state.SearchText.Length == 0 ? "none" : state.SearchText)).Wrap(),
            v.Separator(),
            .. BuildScanOutput(v, state.ScanWorkspace)
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
                s.Section(TrimEnd(status, 84)),
            };

            AddContextualHints(s, state, hints);
            hints.Add(s.Spacer());

            if (!string.IsNullOrEmpty(state.YankNotification))
            {
                hints.Add(s.Section(state.YankNotification).Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.SuccessForeground)));
                hints.Add(s.Divider(" "));
            }

            hints.Add(s.Section(state.CurrentView == PicketTuiView.Scan ? "Ctrl+Q quit" : "q quit"));
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
            case PicketTuiView.Files:
            case PicketTuiView.Logs:
                hints.Add(ctx.Section("g s scan"));
                break;
        }

        if (state.HasYankText)
        {
            hints.Add(ctx.Section("y yank"));
        }
    }

    private static Hex1bWidget[] BuildCountList<TParent>(
        WidgetContext<TParent> ctx,
        List<KeyValuePair<string, int>> rows)
        where TParent : Hex1bWidget
    {
        var widgets = new List<Hex1bWidget>();

        if (rows.Count == 0)
        {
            widgets.Add(ctx.Text("No findings."));
            return [.. widgets];
        }

        for (int i = 0; i < rows.Count; i++)
        {
            KeyValuePair<string, int> row = rows[i];
            widgets.Add(ctx.HStack(h => [
                BuildStatusText(h, row.Value.ToString(CultureInfo.InvariantCulture).PadLeft(5), PicketTuiPalette.CommandForeground).FixedWidth(6),
                h.Text(TrimMiddle(row.Key, 96)).FillWidth()
            ]));
        }

        return [.. widgets];
    }

    private static Hex1bWidget[] BuildScanOutput<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return
        [
            BuildSectionTitle(ctx, "Scanner output"),
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

    private static ThemePanelWidget BuildInlineBadge<TParent>(
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

    private static void RunScanFromUi(PicketTuiState state, Action invalidate, CancellationToken cancellationToken)
    {
        state.StartScanInBackground(invalidate, cancellationToken);
    }

    private static void MoveFindingFromUi(PicketTuiState state, Action invalidate, int delta)
    {
        state.MoveFindingFocus(delta);
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
