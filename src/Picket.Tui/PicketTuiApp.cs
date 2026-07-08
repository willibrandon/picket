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
    private const int OutputPreviewLimit = 5;
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
                BuildTabBar(main, state),
                BuildCurrentView(main, state).Fill(),
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
                bar.Spacer(),
                bar.Divider("  "),
                bar.Section(state.ScanWorkspace.Status).Theme(theme => theme
                    .Set(GlobalTheme.ForegroundColor, GetScanStatusColor(state.ScanWorkspace)))
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

    private static TabPanelWidget BuildTabBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
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
        .FixedHeight(2);
    }

    private static VStackWidget BuildCurrentView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return state.CurrentView switch
        {
            PicketTuiView.Dashboard => BuildDashboard(ctx, state),
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
            BuildSectionTitle(v, "Overview"),
            BuildMetadataLine(v, "Findings", state.Rows.Count.ToString(CultureInfo.InvariantCulture)),
            BuildMetadataLine(v, "Files", state.Report.Summary.FileCount.ToString(CultureInfo.InvariantCulture)),
            BuildMetadataLine(v, "Format", state.Report.Summary.Format),
            BuildMetadataLine(v, "Report", TrimEnd(state.Report.Path, DetailLimit)),
            v.Separator(),
            v.HStack(h => [
                h.VStack(left => BuildCountList(left, "Top rules", state.GetTopRules(TopListLimit))).FillWidth(),
                h.Text("  "),
                h.VStack(right => BuildCountList(right, "Top files", state.GetTopFiles(TopListLimit))).FillWidth()
            ]).Fill(),
        ]).Fill();
    }

    private static VStackWidget BuildScanWorkspace<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        return ctx.VStack(v => [
            BuildScanActionRow(v, state),
            BuildCommandPreview(v, scan),
            BuildScanStatusPanel(v, state).FixedHeight(4),
            v.Separator(),
            BuildScanSettings(v, scan),
            BuildScannerOutputPreview(v, scan).FixedHeight(7)
        ]).Fill();
    }

    private static HStackWidget BuildScanActionRow<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            BuildRunScanButton(h, state).FixedWidth(14),
            h.Text("  "),
            h.Text("").FillWidth(),
            h.Text(FormatScanExit(state.ScanWorkspace)).FixedWidth(10)
        ]).FixedHeight(1);
    }

    private static ThemePanelWidget BuildCommandPreview<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.ThemePanel(
            theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.CommandForeground),
            ctx.Text(string.Concat("Command equivalent: ", scan.BuildCommandLinePreview())).Ellipsis());
    }

    private static HStackWidget BuildTargetModeRow<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text("Target").FixedWidth(10),
            h.ToggleSwitch(PicketTuiScanWorkspace.TargetModeLabels, scan.TargetModeIndex)
                .OnSelectionChanged(e => scan.SetTargetMode(e.SelectedIndex))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static VStackWidget BuildScanSettings<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildScanSectionRow(v, scan),
            .. BuildSelectedScanSection(v, scan)
        ]);
    }

    private static HStackWidget BuildScanSectionRow<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text("Options").FixedWidth(10),
            h.ToggleSwitch(PicketTuiScanWorkspace.ScanSectionLabels, scan.ScanSectionIndex)
                .OnSelectionChanged(e => scan.SetScanSection(e.SelectedIndex))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static Hex1bWidget[] BuildSelectedScanSection<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return scan.ScanSection switch
        {
            PicketTuiScanSection.Output =>
            [
                BuildSectionTitle(ctx, "Output"),
                BuildOutputFields(ctx, scan),
                BuildOutputPathFields(ctx, scan),
            ],
            PicketTuiScanSection.Rules =>
            [
                BuildSectionTitle(ctx, "Rules and filters"),
                BuildFilterFields(ctx, scan),
            ],
            PicketTuiScanSection.Limits =>
            [
                BuildSectionTitle(ctx, "Limits"),
                BuildLimitFields(ctx, scan),
            ],
            _ =>
            [
                BuildSectionTitle(ctx, "Target"),
                BuildTargetModeRow(ctx, scan),
                .. BuildPrimaryTargetFields(ctx, scan),
            ],
        };
    }

    private static ThemePanelWidget BuildSectionTitle<TParent>(WidgetContext<TParent> ctx, string text)
        where TParent : Hex1bWidget
    {
        return BuildStatusText(ctx, text, PicketTuiPalette.InfoForeground);
    }

    private static HStackWidget BuildOutputFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            BuildChoiceField(h, "Format", PicketTuiScanWorkspace.ReportFormats, scan.ReportFormatIndex, scan.SetReportFormatByIndex).FillWidth(),
            h.Text("  "),
            BuildTextField(h, "Redact", scan.RedactionPercent, scan.SetRedactionPercent).FixedWidth(24),
            h.Text("  "),
            BuildBooleanField(h, "Verify", scan.Verify, scan.SetVerify).FixedWidth(24)
        ]).FixedHeight(1);
    }

    private static VStackWidget BuildOutputPathFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildTextField(v, "Report", scan.ReportPath, scan.SetReportPath),
            v.HStack(h => [
                BuildTextField(h, "Profile", scan.Profile, scan.SetProfile).FixedWidth(34),
                h.Text("  "),
                BuildTextField(h, "Config", scan.ConfigPath, scan.SetConfigPath).FillWidth(),
                h.Text("  "),
                BuildTextField(h, "Ignore", scan.IgnorePath, scan.SetIgnorePath).FillWidth()
            ]).FixedHeight(1)
        ]);
    }

    private static VStackWidget BuildFilterFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                BuildBooleanField(h, "No ignore", scan.NoIgnore, scan.SetNoIgnore).FixedWidth(28),
                h.Text("  "),
                BuildBooleanField(h, "Only valid", scan.OnlyVerified, scan.SetOnlyVerified).FixedWidth(30)
            ]).FixedHeight(1),
            BuildChoiceField(v, "Results", PicketTuiScanWorkspace.ResultFilters, scan.ResultFilterIndex, scan.SetResultFilterByIndex)
        ]);
    }

    private static Hex1bWidget[] BuildPrimaryTargetFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return scan.TargetMode switch
        {
            PicketTuiScanTargetMode.GitHub =>
            [
                BuildTextField(ctx, "Repository", scan.GitHubRepository, scan.SetGitHubRepository),
                ctx.HStack(h => [
                    BuildTextField(h, "Org", scan.GitHubOrganization, scan.SetGitHubOrganization).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "User", scan.GitHubUser, scan.SetGitHubUser).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Token env", scan.GitHubTokenEnvironmentVariable, scan.SetGitHubTokenEnvironmentVariable).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildTextField(h, "Gist", scan.GitHubGist, scan.SetGitHubGist).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "User gists", scan.GitHubUserGists, scan.SetGitHubUserGists).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Endpoint", scan.GitHubSourceApiEndpoint, scan.SetGitHubSourceApiEndpoint).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildTextField(h, "Ref", scan.GitHubRef, scan.SetGitHubRef).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "PR", scan.GitHubPullRequest, scan.SetGitHubPullRequest).FillWidth(),
                    h.Text("  "),
                    BuildChoiceField(h, "Repo type", PicketTuiScanWorkspace.GitHubRepositoryTypes, scan.GitHubRepositoryTypeIndex, scan.SetGitHubRepositoryTypeByIndex).FillWidth(),
                    h.Text("  "),
                    BuildChoiceField(h, "Issue state", PicketTuiScanWorkspace.GitHubIssueStates, scan.GitHubIssueStateIndex, scan.SetGitHubIssueStateByIndex).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildBooleanField(h, "Issues", scan.IncludeGitHubIssues, scan.SetIncludeGitHubIssues).FixedWidth(24),
                    h.Text("  "),
                    BuildBooleanField(h, "Releases", scan.IncludeGitHubReleases, scan.SetIncludeGitHubReleases).FixedWidth(26),
                    h.Text("  "),
                    BuildBooleanField(h, "Actions", scan.IncludeGitHubActionsArtifacts, scan.SetIncludeGitHubActionsArtifacts).FixedWidth(24),
                    h.Text("  "),
                    BuildBooleanField(h, "Gists", scan.IncludeGitHubGists, scan.SetIncludeGitHubGists).FixedWidth(22)
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildBooleanField(h, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints).FixedWidth(28),
                    h.Text("  "),
                    BuildBooleanField(h, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints).FixedWidth(22)
                ]).FixedHeight(1),
            ],
            PicketTuiScanTargetMode.AzureDevOps =>
            [
                ctx.HStack(h => [
                    BuildTextField(h, "Org", scan.AzureDevOpsOrganization, scan.SetAzureDevOpsOrganization).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Endpoint", scan.AzureDevOpsEndpoint, scan.SetAzureDevOpsEndpoint).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Token env", scan.AzureDevOpsTokenEnvironmentVariable, scan.SetAzureDevOpsTokenEnvironmentVariable).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildTextField(h, "Project", scan.AzureDevOpsProject, scan.SetAzureDevOpsProject).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Repo", scan.AzureDevOpsRepository, scan.SetAzureDevOpsRepository).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "Branch", scan.AzureDevOpsBranch, scan.SetAzureDevOpsBranch).FillWidth(),
                    h.Text("  "),
                    BuildTextField(h, "PR", scan.AzureDevOpsPullRequest, scan.SetAzureDevOpsPullRequest).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildCompactTextField(h, "Build ID", scan.AzureDevOpsBuildId, scan.SetAzureDevOpsBuildId).FillWidth(),
                    h.Text("  "),
                    BuildCompactTextField(h, "Release ID", scan.AzureDevOpsReleaseId, scan.SetAzureDevOpsReleaseId).FillWidth(),
                    h.Text("  "),
                    BuildChoiceField(h, "Token", PicketTuiScanWorkspace.AzureDevOpsTokenKinds, scan.AzureDevOpsTokenKindIndex, scan.SetAzureDevOpsTokenKindByIndex).FillWidth()
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildBooleanField(h, "Wikis", scan.IncludeAzureDevOpsWikis, scan.SetIncludeAzureDevOpsWikis).FixedWidth(22),
                    h.Text("  "),
                    BuildBooleanField(h, "Artifacts", scan.IncludeAzureDevOpsArtifacts, scan.SetIncludeAzureDevOpsArtifacts).FixedWidth(28),
                    h.Text("  "),
                    BuildBooleanField(h, "Logs", scan.IncludeAzureDevOpsLogs, scan.SetIncludeAzureDevOpsLogs).FixedWidth(22),
                    h.Text("  "),
                    BuildBooleanField(h, "Releases", scan.IncludeAzureDevOpsReleaseArtifacts, scan.SetIncludeAzureDevOpsReleaseArtifacts).FixedWidth(28)
                ]).FixedHeight(1),
                ctx.HStack(h => [
                    BuildCompactTextField(h, "Artifact MB", scan.AzureDevOpsMaxArtifactMegabytes, scan.SetAzureDevOpsMaxArtifactMegabytes).FillWidth(),
                    h.Text("  "),
                    BuildCompactTextField(h, "Log MB", scan.AzureDevOpsMaxLogMegabytes, scan.SetAzureDevOpsMaxLogMegabytes).FillWidth(),
                    h.Text("  "),
                    BuildBooleanField(h, "Non-public", scan.AllowNonPublicSourceEndpoints, scan.SetAllowNonPublicSourceEndpoints).FixedWidth(28),
                    h.Text("  "),
                    BuildBooleanField(h, "HTTP", scan.AllowInsecureSourceEndpoints, scan.SetAllowInsecureSourceEndpoints).FixedWidth(22)
                ]).FixedHeight(1),
            ],
            _ =>
            [
                BuildTextField(ctx, "Path", scan.LocalPath, scan.SetLocalPath),
            ],
        };
    }

    private static VStackWidget BuildLimitFields<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                BuildCompactTextField(h, "Max MB", scan.MaxTargetMegabytes, scan.SetMaxTargetMegabytes).FillWidth(),
                h.Text("  "),
                BuildCompactTextField(h, "Depth", scan.MaxArchiveDepth, scan.SetMaxArchiveDepth).FillWidth(),
                h.Text("  "),
                BuildCompactTextField(h, "Entries", scan.MaxArchiveEntries, scan.SetMaxArchiveEntries).FillWidth()
            ]).FixedHeight(1),
            v.HStack(h => [
                BuildCompactTextField(h, "Archive MB", scan.MaxArchiveMegabytes, scan.SetMaxArchiveMegabytes).FillWidth(),
                h.Text("  "),
                BuildCompactTextField(h, "Ratio", scan.MaxArchiveRatio, scan.SetMaxArchiveRatio).FillWidth(),
                h.Text("  "),
                BuildCompactTextField(h, "Timeout", scan.TimeoutSeconds, scan.SetTimeoutSeconds).FillWidth()
            ]).FixedHeight(1)
        ]);
    }

    private static VStackWidget BuildScanStatusPanel<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildSectionTitle(v, "Run status"),
            v.Text(GetScanOutcomeLine(state)).Ellipsis(),
            v.Text(FormatScanTiming(state.ScanWorkspace)).Ellipsis(),
            v.Text(string.Concat("Report: ", state.Report.Path)).Ellipsis()
        ]).Fill();
    }

    private static VStackWidget BuildScannerOutputPreview<TParent>(WidgetContext<TParent> ctx, PicketTuiScanWorkspace scan)
        where TParent : Hex1bWidget
    {
        IReadOnlyList<string> lines = scan.CapturedOutputLines;
        return ctx.VStack(v => [
            v.Separator(),
            BuildSectionTitle(v, "Scanner output"),
            .. BuildScannerOutputLines(v, lines)
        ]);
    }

    private static string FormatScanExit(PicketTuiScanWorkspace scan)
    {
        return scan.LastExitCode.HasValue
            ? string.Concat("exit ", scan.LastExitCode.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
            : "exit -";
    }

    private static string GetScanOutcomeLine(PicketTuiState state)
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        if (scan.IsRunning)
        {
            return string.Concat("Running. ", scan.LastMessage);
        }

        string review = state.Rows.Count == 0
            ? "No findings loaded."
            : string.Concat(state.GetSummaryLine(), ". Use g f to review.");
        return string.Concat(review, " ", scan.LastMessage);
    }

    private static string FormatScanTiming(PicketTuiScanWorkspace scan)
    {
        if (!scan.LastStartedAt.HasValue)
        {
            return "Last run: not run yet";
        }

        if (!scan.LastCompletedAt.HasValue)
        {
            return string.Concat("Started: ", FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()), " (running)");
        }

        return string.Concat(
            "Started: ",
            FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()),
            "  Completed: ",
            FormatTimestamp(scan.LastCompletedAt.GetValueOrDefault()),
            "  Elapsed: ",
            FormatElapsed(scan.LastElapsed.GetValueOrDefault()));
    }

    private static string FormatTimestamp(DateTimeOffset value)
    {
        return value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
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
            h.Text(label).FixedWidth(14),
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
            h.Text(label).FixedWidth(14),
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
            h.Text(label).FixedWidth(14),
            h.TextBox(value)
                .OnTextChanged(e => setValue(e.NewText))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static HStackWidget BuildCompactTextField<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        string value,
        Action<string> setValue)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(11),
            h.TextBox(value)
                .OnTextChanged(e => setValue(e.NewText))
                .FillWidth()
        ]).FixedHeight(1);
    }

    private static VStackWidget BuildFindingsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            v.HStack(h => [
                h.Text(FormatFindingCount(state)).FixedWidth(22),
                h.Text("Filter").FixedWidth(8),
                h.TextBox(state.SearchText)
                    .OnTextChanged(e => state.SetSearchText(e.NewText))
                    .FillWidth()
            ]).FixedHeight(1),
            v.Responsive(r => [
                r.WhenMinWidth(110, wide => wide.HStack(h => [
                    BuildFindingsList(h, state).FixedWidth(58),
                    h.Text("  "),
                    BuildFindingDetailsPanel(h, state.FocusedFinding).Fill()
                ]).Fill()),
                r.Otherwise(narrow => narrow.VStack(stack => [
                    BuildFindingsList(stack, state).Fill(),
                    BuildFindingDetailsPanel(stack, state.FocusedFinding).FixedHeight(7)
                ]).Fill())
            ]).Fill()
        ]).Fill();
    }

    private static InputOverrideWidget BuildFindingsList<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        int focusedIndex = Math.Max(0, state.IndexOfVisibleRowKey(state.FocusedFindingKey));
        ListWidget<PicketTuiFindingRow> list = ctx.List(state.VisibleRows)
            .ItemHeight(2)
            .ItemKey(row => row.Key)
            .FocusedIndex(focusedIndex)
            .OnFocusChanged(e => state.FocusFinding(e.FocusedItem.Key))
            .OnItemActivated(e => state.FocusFinding(e.ActivatedItem.Key))
            .ItemTemplate(rowContext => BuildFindingListRow(rowContext, state.YankFlashRow))
            .Empty(empty => empty.Text(state.Rows.Count == 0
                ? "No findings loaded yet. Press Run scan or Ctrl+R to scan the selected target."
                : "No findings match the current filter."))
            .Fill();

        return ctx.InputOverride(list)
            .Override<ListWidget<PicketTuiFindingRow>>(bindings =>
            {
                bindings.Key(Hex1bKey.K).Triggers(ListWidget<PicketTuiFindingRow>.MoveUp);
                bindings.Key(Hex1bKey.J).Triggers(ListWidget<PicketTuiFindingRow>.MoveDown);
            });
    }

    private static ThemePanelWidget BuildFindingListRow(ListItemContext<PicketTuiFindingRow> rowContext, bool yankFlash)
    {
        PicketTuiFindingRow row = rowContext.Item;
        Hex1bColor foreground = rowContext.IsFocused
            ? yankFlash ? PicketTuiPalette.YankFlashForeground : PicketTuiPalette.FocusedRowForeground
            : PicketTuiPalette.Foreground;
        Hex1bColor background = rowContext.IsFocused
            ? yankFlash ? PicketTuiPalette.YankFlashBackground : PicketTuiPalette.FocusedRowBackground
            : PicketTuiPalette.Background;

        return rowContext.ThemePanel(
            theme => theme
                .Set(GlobalTheme.ForegroundColor, foreground)
                .Set(GlobalTheme.BackgroundColor, background),
            rowContext.VStack(v => [
                v.HStack(h => [
                    h.Text(rowContext.IsFocused ? ">" : " ").FixedWidth(2),
                    h.Text(row.Index.ToString(CultureInfo.InvariantCulture)).FixedWidth(4),
                    h.Text(TrimMiddle(row.RuleId, 44)).FillWidth()
                ]).FixedHeight(1),
                v.HStack(h => [
                    h.Text("      ").FixedWidth(6),
                    h.Text(TrimMiddle(row.Location, 72)).FillWidth()
                ]).FixedHeight(1)
            ]));
    }

    private static VStackWidget BuildFindingDetailsPanel<TParent>(WidgetContext<TParent> ctx, PicketTuiFindingRow? row)
        where TParent : Hex1bWidget
    {
        if (row is null)
        {
            return ctx.VStack(v => [
                BuildSectionTitle(v, "Selected finding"),
                v.Text("No finding selected."),
                v.Text("Run a scan or adjust the filter.")
            ]).Fill();
        }

        return ctx.VStack(v => [
            BuildSectionTitle(v, "Selected finding"),
            BuildMetadataLine(v, "Rule", row.RuleId),
            BuildMetadataLine(v, "Path", TrimEnd(row.Path, DetailLimit)),
            BuildMetadataLine(v, "Line", row.Line),
            BuildMetadataLine(v, "Fingerprint", TrimEnd(row.Fingerprint, DetailLimit)),
            v.Text("No secret evidence loaded.").Wrap()
        ]).Fill();
    }

    private static HStackWidget BuildMetadataLine<TParent>(
        WidgetContext<TParent> ctx,
        string label,
        string value)
        where TParent : Hex1bWidget
    {
        return ctx.HStack(h => [
            h.Text(label).FixedWidth(13),
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
        return ctx.VStack(v => BuildCountList(v, "Top rules", state.GetTopRules(24))).Fill();
    }

    private static VStackWidget BuildFilesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => BuildCountList(v, "Top files", state.GetTopFiles(24))).Fill();
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
        string title,
        List<KeyValuePair<string, int>> rows)
        where TParent : Hex1bWidget
    {
        var widgets = new List<Hex1bWidget>
        {
            BuildStatusText(ctx, title, PicketTuiPalette.InfoForeground),
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
            BuildStatusText(ctx, "Scanner output", PicketTuiPalette.InfoForeground),
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

    private static void RunScanFromUi(PicketTuiState state, Action invalidate, CancellationToken cancellationToken)
    {
        state.StartScanInBackground(invalidate, cancellationToken);
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
