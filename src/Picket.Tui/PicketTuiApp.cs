using Hex1b;
using Hex1b.Input;
using Hex1b.Layout;
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
                BuildHeader(main, state),
                main.Separator(),
                BuildCurrentView(main, state).Fill(),
                BuildInfoBar(main, state)
            ]).InputBindings(bindings =>
            {
                bindings.Ctrl().Key(Hex1bKey.Q).Action(context => context.RequestStop(), "Quit");
                bindings.Ctrl().Key(Hex1bKey.C).Global().OverridesCapture().Action(
                    context => CancelScanFromUi(state, context.Invalidate),
                    "Cancel scan");
                bindings.Ctrl().Key(Hex1bKey.R).Global().OverridesCapture().Action(
                    context => RunScanFromUi(state, context.CancellationToken, context.Invalidate),
                    "Run scan");
                bindings.Key(Hex1bKey.Escape).Action(_ => state.ClearSearch(), "Clear filter");
                bindings.Key(Hex1bKey.F5).Global().Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.S).Action(_ => state.SetView(PicketTuiView.Scan), "Scan workspace");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.D).Action(_ => state.SetView(PicketTuiView.Dashboard), "Dashboard");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.F).Action(_ => state.SetView(PicketTuiView.Findings), "Findings");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.R).Action(_ => state.SetView(PicketTuiView.Rules), "Rules");
                bindings.Key(Hex1bKey.G).Then().Key(Hex1bKey.L).Action(_ => state.SetView(PicketTuiView.Logs), "Logs");
                bindings.Key(Hex1bKey.Y).Action(context => YankCurrentView(state, context), "Yank");
            }));
    }

    private static HStackWidget BuildHeader<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        string[] labels = [.. PicketTuiState.NavigationItems.Select(PicketTuiState.GetViewLabel)];
        return ctx.HStack(h => [
            BuildStatusText(h, "Picket", PicketTuiPalette.CommandForeground).FixedWidth(10),
            h.ToggleSwitch(labels, state.CurrentNavigationIndex)
                .OnSelectionChanged(e => state.SetViewByIndex(e.SelectedIndex))
                .FillWidth(),
            h.ThemePanel(
                theme => theme
                    .Set(ButtonTheme.BackgroundColor, PicketTuiPalette.PrimaryActionBackground)
                    .Set(ButtonTheme.ForegroundColor, PicketTuiPalette.PrimaryActionForeground)
                    .Set(ButtonTheme.FocusedBackgroundColor, PicketTuiPalette.FocusBackground)
                    .Set(ButtonTheme.FocusedForegroundColor, PicketTuiPalette.FocusForeground)
                    .Set(ButtonTheme.HoveredBackgroundColor, PicketTuiPalette.FocusBackground)
                    .Set(ButtonTheme.HoveredForegroundColor, PicketTuiPalette.FocusForeground),
                h.Button(state.ScanWorkspace.IsRunning ? "Cancel" : "Run scan")
                    .OnClick(e => ActivateScanButton(state, e.CancellationToken, e.Context.Invalidate))).FixedWidth(14)
        ]).FixedHeight(1);
    }

    private static Hex1bWidget BuildCurrentView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
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
            _ => ctx.Text("Unknown view")
        };
    }

    private static VStackWidget BuildDashboard<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildStatusText(v, "Dashboard", PicketTuiPalette.InfoForeground),
            v.Text(state.GetSummaryLine()).Wrap(),
            v.Text(string.Concat("Report: ", state.Report.Path)).Ellipsis(),
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
            BuildScanActionBar(v, state),
            BuildScanHeadline(v, state),
            BuildCommandPreview(v, scan),
            v.Separator(),
            BuildScanSettings(v, scan),
            v.Separator(),
            BuildScanStatusPanel(v, state).Fill()
        ]).Fill();
    }

    private static HStackWidget BuildScanActionBar<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string exitCode = scan.LastExitCode.HasValue
            ? scan.LastExitCode.GetValueOrDefault().ToString(CultureInfo.InvariantCulture)
            : "-";

        return ctx.HStack(h => [
            h.ThemePanel(
                theme => theme
                    .Set(ButtonTheme.BackgroundColor, PicketTuiPalette.PrimaryActionBackground)
                    .Set(ButtonTheme.ForegroundColor, PicketTuiPalette.PrimaryActionForeground)
                    .Set(ButtonTheme.FocusedBackgroundColor, PicketTuiPalette.FocusBackground)
                    .Set(ButtonTheme.FocusedForegroundColor, PicketTuiPalette.FocusForeground)
                    .Set(ButtonTheme.HoveredBackgroundColor, PicketTuiPalette.FocusBackground)
                    .Set(ButtonTheme.HoveredForegroundColor, PicketTuiPalette.FocusForeground),
                h.Button(scan.IsRunning ? "Cancel" : "Run scan")
                    .OnClick(e => ActivateScanButton(state, e.CancellationToken, e.Context.Invalidate))).FixedWidth(14),
            BuildStatusText(h, string.Concat("Status: ", scan.Status), GetScanStatusColor(scan)).FillWidth(),
            BuildStatusText(h, string.Concat("Exit: ", exitCode), GetScanStatusColor(scan)).FixedWidth(10)
        ]).FixedHeight(1);
    }

    private static ThemePanelWidget BuildScanHeadline<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string text = scan.IsRunning
            ? string.Concat("Running scan. ", scan.LastMessage)
            : string.Concat(state.GetSummaryLine(), ". ", scan.LastMessage);

        return ctx.ThemePanel(
            theme => theme.Set(GlobalTheme.ForegroundColor, GetScanStatusColor(scan)),
            ctx.Text(text).Wrap());
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
            BuildTargetModeRow(v, scan),
            .. BuildPrimaryTargetFields(v, scan),
            v.HStack(h => [
                BuildChoiceField(h, "Format", PicketTuiScanWorkspace.ReportFormats, scan.ReportFormatIndex, scan.SetReportFormatByIndex).FillWidth(),
                h.Text("  "),
                BuildTextField(h, "Redact", scan.RedactionPercent, scan.SetRedactionPercent).FixedWidth(24),
                h.Text("  "),
                BuildBooleanField(h, "Verify", scan.Verify, scan.SetVerify).FixedWidth(24)
            ]).FixedHeight(1),
            BuildTextField(v, "Report", scan.ReportPath, scan.SetReportPath),
            BuildTextField(v, "Profile", scan.Profile, scan.SetProfile),
            BuildTextField(v, "Config", scan.ConfigPath, scan.SetConfigPath),
            BuildTextField(v, "Ignore", scan.IgnorePath, scan.SetIgnorePath),
            v.HStack(h => [
                BuildBooleanField(h, "No ignore", scan.NoIgnore, scan.SetNoIgnore).FixedWidth(28),
                h.Text("  "),
                BuildBooleanField(h, "Only valid", scan.OnlyVerified, scan.SetOnlyVerified).FixedWidth(30),
                h.Text("  "),
                BuildChoiceField(h, "Results", PicketTuiScanWorkspace.ResultFilters, scan.ResultFilterIndex, scan.SetResultFilterByIndex).FillWidth()
            ]).FixedHeight(1),
            BuildLimitFields(v, scan)
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
                    BuildBooleanField(h, "Gists", scan.IncludeGitHubGists, scan.SetIncludeGitHubGists).FixedWidth(22),
                    h.Text("  "),
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
            BuildStatusText(v, "Scan status", PicketTuiPalette.InfoForeground),
            v.Text(GetScanOutcomeLine(state)).Wrap(),
            v.Text(FormatScanTiming(state.ScanWorkspace)).Wrap(),
            v.Text(string.Concat("Report: ", state.Report.Path)).Ellipsis(),
            v.Text(GetScanReviewLine(state)).Wrap(),
            v.Separator(),
            v.VStack(output => BuildScanOutput(output, state.ScanWorkspace)).Fill()
        ]).Fill();
    }

    private static string GetScanOutcomeLine(PicketTuiState state)
    {
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        if (scan.IsRunning)
        {
            return string.Concat("Running. ", scan.LastMessage);
        }

        return string.Concat(state.GetSummaryLine(), ". ", scan.LastMessage);
    }

    private static string GetScanReviewLine(PicketTuiState state)
    {
        return state.Rows.Count == 0
            ? "No findings are loaded. Run a scan to populate the Findings tab."
            : "Findings are loaded. Press g f to review and filter them.";
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
            BuildStatusText(v, "Findings", PicketTuiPalette.InfoForeground),
            v.HStack(h => [
                h.Text("Filter").FixedWidth(8),
                h.TextBox(state.SearchText)
                    .OnTextChanged(e => state.SetSearchText(e.NewText))
                    .FillWidth()
            ]).FixedHeight(1),
            BuildFindingsTable(v, state).Fill(),
            v.Separator(),
            v.VStack(details => BuildFindingDetails(details, state.FocusedFinding)).FixedHeight(8)
        ]).Fill();
    }

    private static TableWidget<PicketTuiFindingRow> BuildFindingsTable<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        TableWidget<PicketTuiFindingRow> table = ctx.Table(state.FindingDataSource)
            .RowKey(row => row.Key)
            .Header(h => [
                h.Cell("#").Width(SizeHint.Fixed(6)).Align(Alignment.Right),
                h.Cell("Rule").Width(SizeHint.Fixed(30)),
                h.Cell("Location").Width(SizeHint.Fill),
                h.Cell("Fingerprint").Width(SizeHint.Fixed(28))
            ])
            .Row((r, row, rowState) => [
                r.Cell(c => BuildFocusedCell(c, row.Index.ToString(CultureInfo.InvariantCulture), rowState.IsFocused, state.YankFlashRow)),
                r.Cell(c => BuildFocusedCell(c, TrimMiddle(row.RuleId, 28), rowState.IsFocused, state.YankFlashRow)),
                r.Cell(c => BuildFocusedCell(c, TrimMiddle(row.Location, 96), rowState.IsFocused, state.YankFlashRow)),
                r.Cell(c => BuildFocusedCell(c, TrimMiddle(row.Fingerprint, 26), rowState.IsFocused, state.YankFlashRow))
            ])
            .Empty(empty => empty.Text(state.Rows.Count == 0
                ? "No findings loaded yet. Press Run scan or Ctrl+R to scan the selected target."
                : "No findings match the current filter."))
            .Focus(state.FocusedFindingKey)
            .OnFocusChanged(state.FocusFinding)
            .Compact()
            .Fill();

        return table;
    }

    private static Hex1bWidget[] BuildFindingDetails<TParent>(WidgetContext<TParent> ctx, PicketTuiFindingRow? row)
        where TParent : Hex1bWidget
    {
        if (row is null)
        {
            return [
                ctx.Text("No finding selected."),
                ctx.Text("Open a report with findings or run a scan that reports findings.")
            ];
        }

        return [
            ctx.Text(string.Concat("Rule: ", row.RuleId)).Wrap(),
            ctx.Text(string.Concat("Path: ", TrimEnd(row.Path, DetailLimit))).Wrap(),
            ctx.Text(string.Concat("Line: ", row.Line)),
            ctx.Text(string.Concat("Fingerprint: ", TrimEnd(row.Fingerprint, DetailLimit))).Wrap(),
            ctx.Text("Secret evidence is intentionally not loaded in this summary view.").Wrap()
        ];
    }

    private static Hex1bWidget BuildFocusedCell<TParent>(
        WidgetContext<TParent> ctx,
        string text,
        bool isFocused,
        bool yankFlash)
        where TParent : Hex1bWidget
    {
        Hex1bWidget child = ctx.Text(text).Ellipsis();
        if (!isFocused)
        {
            return child;
        }

        Hex1bColor foreground = yankFlash
            ? PicketTuiPalette.YankFlashForeground
            : PicketTuiPalette.FocusedRowForeground;
        Hex1bColor background = yankFlash
            ? PicketTuiPalette.YankFlashBackground
            : PicketTuiPalette.FocusedRowBackground;

        return ctx.ThemePanel(
            theme => theme
                .Set(GlobalTheme.ForegroundColor, foreground)
                .Set(GlobalTheme.BackgroundColor, background),
            child);
    }

    private static VStackWidget BuildRulesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => BuildCountList(v, "Rules", state.GetTopRules(24))).Fill();
    }

    private static VStackWidget BuildFilesView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => BuildCountList(v, "Files", state.GetTopFiles(24))).Fill();
    }

    private static VStackWidget BuildLogsView<TParent>(WidgetContext<TParent> ctx, PicketTuiState state)
        where TParent : Hex1bWidget
    {
        return ctx.VStack(v => [
            BuildStatusText(v, "Logs", PicketTuiPalette.InfoForeground),
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
                s.Section(status).FillWidth(),
            };

            AddContextualHints(s, state, hints);

            hints.Add(s.Spacer());
            if (!string.IsNullOrEmpty(state.YankNotification))
            {
                hints.Add(s.Section(state.YankNotification).Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.SuccessForeground)));
            }

            hints.Add(s.Section("Ctrl+Q quit").FixedWidth(12));
            return hints;
        }).Divider("  ");
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
                    hints.Add(ctx.Section("Ctrl+R run").Theme(theme => theme.Set(GlobalTheme.ForegroundColor, PicketTuiPalette.CommandForeground)).FixedWidth(12));
                }

                if (state.Rows.Count != 0)
                {
                    hints.Add(ctx.Section("g f findings").FixedWidth(14));
                }

                break;
            case PicketTuiView.Findings:
                if (state.SearchText.Length != 0)
                {
                    hints.Add(ctx.Section("Esc clear").FixedWidth(10));
                }

                hints.Add(ctx.Section("g s scan").FixedWidth(10));
                break;
            case PicketTuiView.Dashboard:
                hints.Add(ctx.Section("g s scan").FixedWidth(10));
                if (state.Rows.Count != 0)
                {
                    hints.Add(ctx.Section("g f findings").FixedWidth(14));
                }

                break;
            case PicketTuiView.Rules:
            case PicketTuiView.Files:
            case PicketTuiView.Logs:
                hints.Add(ctx.Section("g s scan").FixedWidth(10));
                break;
        }

        if (state.HasYankText)
        {
            hints.Add(ctx.Section("y yank").FixedWidth(8));
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
        var widgets = new List<Hex1bWidget>
        {
            BuildStatusText(ctx, "Scanner output", PicketTuiPalette.InfoForeground)
        };

        IReadOnlyList<string> lines = scan.CapturedOutputLines;
        if (lines.Count == 0)
        {
            widgets.Add(ctx.Text("No scanner output captured."));
            return [.. widgets];
        }

        for (int i = 0; i < lines.Count; i++)
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

    private static void RunScanFromUi(PicketTuiState state, CancellationToken cancellationToken, Action invalidate)
    {
        state.StartScanInBackground(invalidate, cancellationToken);
    }

    private static void ActivateScanButton(PicketTuiState state, CancellationToken cancellationToken, Action invalidate)
    {
        if (state.ScanWorkspace.IsRunning)
        {
            state.CancelScan(invalidate);
            return;
        }

        RunScanFromUi(state, cancellationToken, invalidate);
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
