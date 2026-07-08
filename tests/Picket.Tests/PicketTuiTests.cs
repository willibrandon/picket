using Hex1b;
using Hex1b.Automation;
using Hex1b.Input;
using Hex1b.Theming;
using Picket.Report;
using Picket.Tui;
using System.Diagnostics;

namespace Picket.Tests;

/// <summary>
/// Tests the interactive report triage console state and terminal accessibility requirements.
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
    /// Verifies that repeated fingerprints remain valid table rows.
    /// </summary>
    [TestMethod]
    public void StateAllowsDuplicateFindingFingerprints()
    {
        var summary = new ReportSummary(
            "picket-json",
            [
                new ReportFindingSummary("rule", "first.cs", 1, "duplicate-fingerprint"),
                new ReportFindingSummary("rule", "second.cs", 2, "duplicate-fingerprint"),
            ]);

        var state = new PicketTuiState(new PicketTuiReport("report.json", summary, DateTimeOffset.UnixEpoch));

        Assert.HasCount(2, state.Rows);
        Assert.AreNotEqual(state.Rows[0].Key, state.Rows[1].Key);
        Assert.AreEqual("duplicate-fingerprint", state.Rows[0].Fingerprint);
        Assert.AreEqual("duplicate-fingerprint", state.Rows[1].Fingerprint);
    }

    /// <summary>
    /// Verifies that contextual yanking copies useful finding metadata without loading secret evidence.
    /// </summary>
    [TestMethod]
    public void StateYanksFocusedFindingMetadata()
    {
        PicketTuiState state = CreateState();
        string text = state.GetYankText();

        Assert.IsTrue(state.HasYankText);
        Assert.Contains("Rule: github-token", text);
        Assert.Contains("Path: src/auth.cs", text);
        Assert.Contains("Line: 12", text);
        Assert.Contains("Fingerprint: fp-auth-1", text);
        Assert.Contains("Report: report.json", text);
        Assert.DoesNotContain("Secret", text);
    }

    /// <summary>
    /// Verifies that scan-page yanking copies scan context without duplicating finding triage details.
    /// </summary>
    [TestMethod]
    public void StateYanksScanContextFromScanView()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);

        string text = state.GetYankText();

        Assert.Contains("Command: picket scan", text);
        Assert.Contains("Report: picket-results/picket-tui.jsonl", text);
        Assert.Contains("Status: Ready to scan", text);
        Assert.Contains("Timing: not run yet", text);
        Assert.Contains("Summary: 3 findings across 2 files in picket-json", text);
        Assert.DoesNotContain("Focused finding:", text);
        Assert.DoesNotContain("Rule: github-token", text);
        Assert.Contains("Scanner output:", text);
        Assert.Contains("No scanner output captured.", text);
        Assert.DoesNotContain("Secret", text);
    }

    /// <summary>
    /// Verifies that the scan workspace builds command-equivalent native scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsNativeScanArguments()
    {
        using TempDirectory temp = TempDirectory.Create();
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");

        scan.SetLocalPath("src");
        scan.SetReportPath(reportPath);
        scan.SetVerify(true);
        scan.SetOnlyVerified(true);
        scan.SetNoIgnore(true);
        scan.SetRedactionPercent("100");
        scan.SetMaxTargetMegabytes("25");
        scan.SetMaxArchiveDepth("2");
        scan.SetMaxArchiveEntries("128");
        scan.SetMaxArchiveMegabytes("64");
        scan.SetMaxArchiveRatio("500");
        scan.SetTimeoutSeconds("30");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("scan", arguments);
        Assert.Contains("src", arguments);
        Assert.Contains("--verify", arguments);
        Assert.Contains("--only-verified", arguments);
        Assert.Contains("--no-ignore", arguments);
        Assert.Contains("--redact=100", arguments);
        Assert.Contains("--max-target-megabytes", arguments);
        Assert.Contains("25", arguments);
        Assert.Contains("--max-archive-depth", arguments);
        Assert.Contains("2", arguments);
        Assert.Contains("--max-archive-entries", arguments);
        Assert.Contains("128", arguments);
        Assert.Contains("--max-archive-megabytes", arguments);
        Assert.Contains("64", arguments);
        Assert.Contains("--max-archive-ratio", arguments);
        Assert.Contains("500", arguments);
        Assert.Contains("--timeout", arguments);
        Assert.Contains("30", arguments);
        Assert.Contains("--report-path", arguments);
        Assert.Contains(reportPath, arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds GitHub Actions artifact scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGitHubActionsArtifactArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(1);
        scan.SetGitHubRepository("owner/repo");
        scan.SetGitHubRef("main");
        scan.SetGitHubTokenEnvironmentVariable("PICKET_GITHUB_SECRET_SCANNING_PAT");
        scan.SetGitHubRepositoryTypeByIndex(1);
        scan.SetGitHubIssueStateByIndex(2);
        scan.SetGitHubSourceApiEndpoint("https://api.github.example");
        scan.SetIncludeGitHubActionsArtifacts(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--github-repository", arguments);
        Assert.Contains("owner/repo", arguments);
        Assert.Contains("--github-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--github-token-env", arguments);
        Assert.Contains("PICKET_GITHUB_SECRET_SCANNING_PAT", arguments);
        Assert.Contains("--github-repository-type", arguments);
        Assert.Contains("public", arguments);
        Assert.Contains("--github-issue-state", arguments);
        Assert.Contains("closed", arguments);
        Assert.Contains("--github-source-api-endpoint", arguments);
        Assert.Contains("https://api.github.example", arguments);
        Assert.Contains("--github-include-actions-artifacts", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds GitHub gist scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGitHubGistArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(1);
        scan.SetGitHubGist("abc123");
        scan.SetGitHubTokenEnvironmentVariable("PICKET_GITHUB_SECRET_SCANNING_PAT");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--github-gist", arguments);
        Assert.Contains("abc123", arguments);
        Assert.Contains("--github-token-env", arguments);
        Assert.Contains("PICKET_GITHUB_SECRET_SCANNING_PAT", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects ambiguous GitHub source selectors before launching the scanner.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMultipleGitHubSourceSelectors()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(1);
        scan.SetGitHubRepository("owner/repo");
        scan.SetGitHubGist("abc123");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("exactly one repository, organization, user, gist, authenticated-gists, or user-gists selector", error);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Azure DevOps artifact, log, and endpoint policy arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsAzureDevOpsArtifactArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(2);
        scan.SetAzureDevOpsEndpoint("https://dev.azure.com/example");
        scan.SetAzureDevOpsOrganization("example");
        scan.SetAzureDevOpsProject("project");
        scan.SetAzureDevOpsRepository("repo");
        scan.SetAzureDevOpsBranch("main");
        scan.SetAzureDevOpsPullRequest("5");
        scan.SetAzureDevOpsTokenEnvironmentVariable("AZURE_DEVOPS_TEST_PAT");
        scan.SetAzureDevOpsTokenKindByIndex(1);
        scan.SetAzureDevOpsBuildId("42");
        scan.SetAzureDevOpsReleaseId("7");
        scan.SetIncludeAzureDevOpsWikis(true);
        scan.SetIncludeAzureDevOpsArtifacts(true);
        scan.SetIncludeAzureDevOpsLogs(true);
        scan.SetIncludeAzureDevOpsReleaseArtifacts(true);
        scan.SetAzureDevOpsMaxArtifactMegabytes("25");
        scan.SetAzureDevOpsMaxLogMegabytes("5");
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--azure-devops-endpoint", arguments);
        Assert.Contains("https://dev.azure.com/example", arguments);
        Assert.Contains("--azure-devops-organization", arguments);
        Assert.Contains("example", arguments);
        Assert.Contains("--azure-devops-project", arguments);
        Assert.Contains("project", arguments);
        Assert.Contains("--azure-devops-repository", arguments);
        Assert.Contains("repo", arguments);
        Assert.Contains("--azure-devops-branch", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--azure-devops-pull-request", arguments);
        Assert.Contains("5", arguments);
        Assert.Contains("--azure-devops-token-env", arguments);
        Assert.Contains("AZURE_DEVOPS_TEST_PAT", arguments);
        Assert.Contains("--azure-devops-token-kind", arguments);
        Assert.Contains("bearer", arguments);
        Assert.Contains("--azure-devops-build-id", arguments);
        Assert.Contains("42", arguments);
        Assert.Contains("--azure-devops-release-id", arguments);
        Assert.Contains("7", arguments);
        Assert.Contains("--azure-devops-include-wikis", arguments);
        Assert.Contains("--azure-devops-include-artifacts", arguments);
        Assert.Contains("--azure-devops-include-logs", arguments);
        Assert.Contains("--azure-devops-include-release-artifacts", arguments);
        Assert.Contains("--azure-devops-max-artifact-megabytes", arguments);
        Assert.Contains("25", arguments);
        Assert.Contains("--azure-devops-max-log-megabytes", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace can run through the scanner executor and load the generated report summary.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceRunsAndLoadsGeneratedReport()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor();
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");

        scan.SetLocalPath(temp.Path);
        scan.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, scan.LastExitCode);
        Assert.Contains("--report-path", executor.CapturedArguments);
        Assert.AreEqual(reportPath, executor.CapturedReportPath);
        Assert.AreEqual(reportPath, state.Report.Path);
        Assert.AreEqual(1, state.Report.Summary.FindingCount);
        Assert.AreEqual("fake-rule", state.Rows[0].RuleId);
        Assert.AreEqual(PicketTuiView.Scan, state.CurrentView);
        Assert.IsNotNull(scan.LastStartedAt);
        Assert.IsNotNull(scan.LastCompletedAt);
        Assert.IsNotNull(scan.LastElapsed);
        Assert.HasCount(2, scan.CapturedOutputLines);
        Assert.Contains("stderr: 1 finding", scan.CapturedOutputText);
        Assert.Contains("stdout: scan complete", scan.CapturedOutputText);
    }

    /// <summary>
    /// Verifies that the scan workspace prepares report directories before invoking the scanner.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceCreatesReportDirectoryBeforeRunningScanner()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor();
        PicketTuiState state = CreateState(executor);
        string reportPath = Path.Combine(temp.Path, "nested", "reports", "picket.jsonl");

        state.ScanWorkspace.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(File.Exists(reportPath));
        Assert.AreEqual(reportPath, executor.CapturedReportPath);
        Assert.AreEqual(1, state.Report.Summary.FindingCount);
        Assert.AreEqual(PicketTuiView.Scan, state.CurrentView);
    }

    /// <summary>
    /// Verifies that a background scan can be cancelled from the scanner-console state.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceCancelsBackgroundScan()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            InitialOutputLine = "enumerated 1 file",
            WaitForCancellation = true,
        };
        PicketTuiState state = CreateState(executor);
        int invalidationCount = 0;

        state.ScanWorkspace.SetLocalPath(temp.Path);
        state.ScanWorkspace.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));
        state.StartScanInBackground(() => Interlocked.Increment(ref invalidationCount), TestContext.CancellationToken);

        await executor.Started.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await WaitUntilAsync(
            () => state.ScanWorkspace.CapturedOutputText.Contains("enumerated 1 file", StringComparison.Ordinal),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(state.ScanWorkspace.IsRunning);
        Assert.Contains("Running", state.ScanWorkspace.Status);
        Assert.IsGreaterThanOrEqualTo(2, invalidationCount);

        state.CancelScan(() => Interlocked.Increment(ref invalidationCount));
        await WaitUntilAsync(
            () => !state.ScanWorkspace.IsRunning
                && state.ScanWorkspace.LastExitCode == 130
                && state.ScanWorkspace.Status.Equals("Scan cancelled", StringComparison.Ordinal)
                && state.StatusMessage.Equals("Scan cancelled", StringComparison.Ordinal),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(130, state.ScanWorkspace.LastExitCode);
        Assert.AreEqual("Scan cancelled", state.ScanWorkspace.Status);
        Assert.AreEqual("Scan cancelled", state.StatusMessage);
        Assert.Contains("running scan was cancelled", state.ScanWorkspace.CapturedOutputText);
        Assert.IsGreaterThan(0, invalidationCount);
    }

    /// <summary>
    /// Verifies that reopening the scan workspace can load the existing scan report from disk.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceLoadsPreviousReport()
    {
        using TempDirectory temp = TempDirectory.Create();
        PicketTuiState state = CreateEmptyState();
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");

        File.WriteAllText(reportPath, CreateFakeReportJsonLine());
        state.ScanWorkspace.SetReportPath(reportPath);

        bool loaded = state.TryLoadPreviousScanReport();

        Assert.IsTrue(loaded);
        Assert.AreEqual(PicketTuiView.Scan, state.CurrentView);
        Assert.AreEqual(reportPath, state.Report.Path);
        Assert.AreEqual(1, state.Report.Summary.FindingCount);
        Assert.AreEqual("fake-rule", state.Rows[0].RuleId);
        Assert.Contains("Loaded previous scan", state.ScanWorkspace.Status);
    }

    /// <summary>
    /// Verifies that the scanner-console palette satisfies the terminal-adapted WCAG contrast thresholds.
    /// </summary>
    [TestMethod]
    public void PaletteMeetsContrastThresholds()
    {
        AssertTextContrast(PicketTuiPalette.Foreground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.Foreground, PicketTuiPalette.PanelBackground);
        AssertTextContrast(PicketTuiPalette.MutedForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.CommandForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.ErrorForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.InfoForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.PrimaryActionForeground, PicketTuiPalette.PrimaryActionBackground);
        AssertTextContrast(PicketTuiPalette.SuccessForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.WarningForeground, PicketTuiPalette.Background);
        AssertTextContrast(PicketTuiPalette.FocusForeground, PicketTuiPalette.FocusBackground);
        AssertTextContrast(PicketTuiPalette.FocusedRowForeground, PicketTuiPalette.FocusedRowBackground);
        AssertTextContrast(PicketTuiPalette.YankFlashForeground, PicketTuiPalette.YankFlashBackground);
        AssertUiContrast(PicketTuiPalette.Border, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusedRowBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.YankFlashBackground, PicketTuiPalette.Background);
    }

    /// <summary>
    /// Verifies that table focus chrome uses the same selected-row highlight as list rows.
    /// </summary>
    [TestMethod]
    public void PaletteKeepsTableFocusChromeConsistent()
    {
        Hex1bTheme theme = PicketTuiPalette.CreateTheme();

        Assert.AreEqual(PicketTuiPalette.Border, theme.Get(TableTheme.FocusedBorderColor));
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, theme.Get(TableTheme.FocusedRowBackground));
        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, theme.Get(TableTheme.FocusedRowForeground));
        Assert.AreEqual(PicketTuiPalette.Border, theme.Get(TableTheme.ScrollbarThumbColor));
        Assert.AreEqual(PicketTuiPalette.Border, theme.Get(TableTheme.TableFocusedBorderColor));
    }

    /// <summary>
    /// Verifies that selected toggle choices do not change color when the field receives focus.
    /// </summary>
    [TestMethod]
    public void PaletteKeepsToggleSelectionColorStableWhenFocused()
    {
        Hex1bTheme theme = PicketTuiPalette.CreateTheme();

        Assert.AreEqual(
            theme.Get(ToggleSwitchTheme.UnfocusedSelectedBackgroundColor),
            theme.Get(ToggleSwitchTheme.FocusedSelectedBackgroundColor));
        Assert.AreEqual(
            theme.Get(ToggleSwitchTheme.UnfocusedSelectedForegroundColor),
            theme.Get(ToggleSwitchTheme.FocusedSelectedForegroundColor));
        Assert.AreEqual(
            PicketTuiPalette.PrimaryActionBackground,
            theme.Get(TabBarTheme.SelectedBackgroundColor));
    }

    /// <summary>
    /// Verifies that yanking briefly flashes the focused row before leaving only the footer notification.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task StateYankFlashSetsAndClearsBeforeNotification()
    {
        PicketTuiState state = CreateState();
        using var invalidated = new ManualResetEventSlim();

        state.ShowYankNotification("github-token", invalidated.Set, TestContext.CancellationToken);

        Assert.IsTrue(state.YankFlashRow);
        string yankNotification = state.YankNotification ?? string.Empty;
        Assert.Contains("Yanked: github-token", yankNotification);

        while (state.YankFlashRow)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsFalse(state.YankFlashRow);
        Assert.IsTrue(invalidated.IsSet);
        Assert.IsNotNull(state.YankNotification);
    }

    /// <summary>
    /// Verifies that the full-screen scanner console opens a loaded report directly on findings and exits through its keyboard binding.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersFindingsAndExits()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Findings"), TimeSpan.FromSeconds(5), "findings to render")
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
        Assert.Contains("github-token", screenText);
        Assert.Contains("src/auth.cs", screenText);
        Assert.Contains("g s scan", screenText);
        Assert.Contains("y yank", screenText);
        Assert.DoesNotContain("Ctrl+R run", screenText);
    }

    /// <summary>
    /// Verifies that the selected finding row uses the Picket focus color without falling back to table chrome.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleKeepsSelectedRowChromeNeutral()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("src/auth.cs"), TimeSpan.FromSeconds(5), "finding row to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string[] lines = snapshot.GetScreenText().Split('\n');
        int rowY = Array.FindIndex(lines, line => line.Contains('>')
            && line.Contains("github-token", StringComparison.Ordinal));
        Assert.AreEqual(0, exitCode);
        Assert.IsGreaterThanOrEqualTo(0, rowY);

        int textX = lines[rowY].IndexOf("github-token", StringComparison.Ordinal);
        int nextRowY = Array.FindIndex(lines, line => line.Contains("src/auth.cs:18", StringComparison.Ordinal));
        Assert.IsGreaterThanOrEqualTo(0, textX);
        Assert.IsGreaterThanOrEqualTo(0, nextRowY);

        TerminalCell textCell = snapshot.GetCell(textX, rowY);
        TerminalCell nextRowCell = snapshot.GetCell(lines[nextRowY].IndexOf("src/auth.cs:18", StringComparison.Ordinal), nextRowY);

        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, textCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, textCell.Background);
        Assert.AreEqual(PicketTuiPalette.Foreground, nextRowCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.Background, nextRowCell.Background);
    }

    /// <summary>
    /// Verifies that the scanner console remains useful in a narrow terminal and exposes Vim-style navigation through Hex1b input.
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
            .WaitUntil(s => s.ContainsText("Findings"), TimeSpan.FromSeconds(5), "findings to render")
            .Key(Hex1bKey.G)
            .Key(Hex1bKey.S)
            .WaitUntil(s => s.ContainsText("Source"), TimeSpan.FromSeconds(5), "scan workspace to render")
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
        Assert.Contains("Run scan", screenText);
        Assert.Contains("Ctrl+R run", screenText);
        Assert.Contains("g f findings", screenText);
        Assert.DoesNotContain("Use g f to review", screenText);
        Assert.Contains("Source", screenText);
        Assert.Contains("Last run: not run yet", screenText);
        Assert.DoesNotContain("Latest results", screenText);
        Assert.DoesNotContain("g s scan", screenText);
    }

    /// <summary>
    /// Verifies that the full-screen scanner console renders the native scan workspace through Hex1b.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersScanWorkspace()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("picket scan"), TimeSpan.FromSeconds(5), "scan workspace to render")
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
        Assert.Contains("picket scan", screenText);
        Assert.Contains("Target", screenText);
        Assert.Contains("Source", screenText);
        Assert.Contains("Output", screenText);
        Assert.Contains("Validation", screenText);
        Assert.Contains("Limits", screenText);
        Assert.Contains("Path", screenText);
        Assert.Contains("Run scan", screenText);
        Assert.Contains("Ctrl+R run", screenText);
        Assert.Contains("g f findings", screenText);
        Assert.DoesNotContain("Use g f to review", screenText);
        Assert.Contains("Last run: not run yet", screenText);
        Assert.DoesNotContain("Latest results", screenText);
        Assert.DoesNotContain("src/auth.cs", screenText);
        Assert.DoesNotContain("g s scan", screenText);
    }

    /// <summary>
    /// Verifies that the scan workspace output section renders report and verification options.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersScanOutputSection()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetScanSettingPageByIndex(1);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Redact"), TimeSpan.FromSeconds(5), "output section to render")
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
        Assert.Contains("Output", screenText);
        Assert.Contains("Format", screenText);
        Assert.Contains("Redact", screenText);
        Assert.Contains("Verify", screenText);
        Assert.Contains("Report", screenText);
        Assert.Contains("Profile", screenText);
        Assert.Contains("Config", screenText);
        Assert.Contains("Ignore", screenText);
    }

    /// <summary>
    /// Verifies that the scan workspace validation page renders ignore and result-filter options.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersScanValidationSection()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetScanSettingPageByIndex(2);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Results"), TimeSpan.FromSeconds(5), "rules section to render")
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
        Assert.Contains("Validation", screenText);
        Assert.Contains("No ignore", screenText);
        Assert.Contains("Only valid", screenText);
        Assert.Contains("Results", screenText);
        Assert.Contains("structurally-valid", screenText);
        Assert.Contains("Verify", screenText);
    }

    /// <summary>
    /// Verifies that the scan workspace limits section renders archive and timeout options.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersScanLimitsSection()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetScanSettingPageByIndex(3);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Archive MB"), TimeSpan.FromSeconds(5), "limits section to render")
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
        Assert.Contains("Limits", screenText);
        Assert.Contains("Max MB", screenText);
        Assert.Contains("Depth", screenText);
        Assert.Contains("Entries", screenText);
        Assert.Contains("Archive MB", screenText);
        Assert.Contains("Ratio", screenText);
        Assert.Contains("Timeout", screenText);
    }

    /// <summary>
    /// Verifies that GitHub source scan controls include Actions artifact scanning.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersGitHubSourceControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode(1);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 160, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Actions"), TimeSpan.FromSeconds(5), "GitHub controls to render")
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
        Assert.Contains("Repository", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Gist", screenText);
        Assert.Contains("Repo type", screenText);
        Assert.Contains("Issue state", screenText);
        Assert.Contains("Endpoint", screenText);
        Assert.Contains("Actions", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
    }

    /// <summary>
    /// Verifies that Azure DevOps source scan controls include pipeline artifacts and endpoint policy fields.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersAzureDevOpsSourceControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode(2);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 160, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Artifact MB"), TimeSpan.FromSeconds(5), "Azure DevOps controls to render")
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
        Assert.Contains("Endpoint", screenText);
        Assert.Contains("Build ID", screenText);
        Assert.Contains("Release ID", screenText);
        Assert.Contains("Artifact MB", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
    }

    /// <summary>
    /// Verifies that the full-screen scanner console can run a scan from its keyboard command model.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRunsScanFromShortcut()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor();
        PicketTuiState state = CreateState(executor);
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Run scan"), TimeSpan.FromSeconds(5), "scan workspace to render")
            .Ctrl().Key(Hex1bKey.R)
            .WaitUntil(s => s.ContainsText("Scan completed: findings reported"), TimeSpan.FromSeconds(5), "scan result to load")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot findingsSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.G)
            .Key(Hex1bKey.F)
            .WaitUntil(s => s.ContainsText("fake-rule"), TimeSpan.FromSeconds(5), "findings result to render")
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
        string findingsText = findingsSnapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.DoesNotContain("Use g f to review", screenText);
        Assert.Contains("Started:", screenText);
        Assert.Contains("Completed:", screenText);
        Assert.Contains("Elapsed:", screenText);
        Assert.DoesNotContain("fake-rule", screenText);
        Assert.Contains("fake-rule", findingsText);
        Assert.Contains("scan", executor.CapturedArguments);
        Assert.Contains("Output", screenText);
    }

    /// <summary>
    /// Verifies that the full-screen scanner console can cancel a running scan from its keyboard command model.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleCancelsScanFromShortcut()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            WaitForCancellation = true,
        };
        PicketTuiState state = CreateState(executor);
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Run scan"), TimeSpan.FromSeconds(5), "scan workspace to render")
            .Ctrl().Key(Hex1bKey.R)
            .WaitUntil(s => s.ContainsText("Ctrl+C cancel"), TimeSpan.FromSeconds(5), "cancel hint to render")
            .Ctrl().Key(Hex1bKey.C)
            .WaitUntil(s => s.ContainsText("Scan cancelled"), TimeSpan.FromSeconds(5), "cancelled status to render")
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
        Assert.Contains("Scan cancelled", screenText);
        Assert.Contains("Run scan", screenText);
        Assert.Contains("scan", executor.CapturedArguments);
    }

    /// <summary>
    /// Verifies that scan process launch failures stay inside TUI state instead of crashing the app.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceReportsProcessLaunchFailure()
    {
        PicketTuiState state = CreateState(new PicketTuiProcessScanExecutor("picket-missing-for-test"));

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(126, state.ScanWorkspace.LastExitCode);
        Assert.Contains("could not start scanner", state.ScanWorkspace.Status);
    }

    /// <summary>
    /// Verifies that the companion CLI uses the shared System.CommandLine-style help surface.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompanionHelpAdvertisesScanWorkspace()
    {
        CliResult result = await RunTuiCliAsync("--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket-tui [<report>] [options]", result.Stdout);
        Assert.Contains("--flow", result.Stdout);
        Assert.Contains("--scan", result.Stdout);
        Assert.Contains("--version", result.Stdout);
    }

    private static PicketTuiState CreateState(IPicketTuiScanExecutor? executor = null)
    {
        var summary = new ReportSummary(
            "picket-json",
            [
                new ReportFindingSummary("github-token", "src/auth.cs", 12, "fp-auth-1"),
                new ReportFindingSummary("github-token", "src/auth.cs", 18, "fp-auth-2"),
                new ReportFindingSummary("aws-key", "infra/main.tf", 4, "fp-infra-1"),
            ]);

        return new PicketTuiState(new PicketTuiReport("report.json", summary, DateTimeOffset.UnixEpoch), executor);
    }

    private static PicketTuiState CreateEmptyState(IPicketTuiScanExecutor? executor = null)
    {
        return new PicketTuiState(
            new PicketTuiReport("empty.jsonl", new ReportSummary("picket-jsonl", []), DateTimeOffset.UnixEpoch),
            executor);
    }

    private static string CreateFakeReportJsonLine()
    {
        return string.Concat(
            "{\"ruleId\":\"fake-rule\",",
            "\"file\":\"src/app.cs\",",
            "\"startLine\":7,",
            "\"fingerprint\":\"fake-fingerprint\"}",
            Environment.NewLine);
    }

    private static Hex1bTerminal CreateHeadlessTerminal(PicketTuiState state, int width, int height)
    {
        return Hex1bTerminal.CreateBuilder()
            .WithHex1bApp(
                options =>
                {
                    options.EnableMouse = true;
                    options.Theme = PicketTuiPalette.CreateTheme();
                },
                ctx => PicketTuiApp.Build(ctx, state))
            .WithHeadless()
            .WithDimensions(width, height)
            .Build();
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, CancellationToken cancellationToken)
    {
        while (!predicate())
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
        }
    }

    private static void AssertTextContrast(Hex1bColor foreground, Hex1bColor background)
    {
        double ratio = PicketTuiPalette.ContrastRatio(foreground, background);
        Assert.IsGreaterThanOrEqualTo(PicketTuiPalette.TextContrastMinimum, ratio);
    }

    private static void AssertUiContrast(Hex1bColor foreground, Hex1bColor background)
    {
        double ratio = PicketTuiPalette.ContrastRatio(foreground, background);
        Assert.IsGreaterThanOrEqualTo(PicketTuiPalette.UiContrastMinimum, ratio);
    }

    private static async Task<CliResult> RunTuiCliAsync(params string[] arguments)
    {
        string repositoryRoot = FindRepositoryRoot();
        using TempDirectory outputRoot = TempDirectory.Create();
        string outputPath = Path.Combine(outputRoot.Path, "picket-tui-cli");

        CliResult build = await RunProcessAsync(
            "dotnet",
            [
                "build",
                Path.Combine("src", "Picket.Tui.Cli", "Picket.Tui.Cli.csproj"),
                "--no-restore",
                "--output",
                outputPath,
            ],
            repositoryRoot).ConfigureAwait(false);

        if (build.ExitCode != 0)
        {
            return build;
        }

        string executablePath = Path.Combine(outputPath, OperatingSystem.IsWindows() ? "picket-tui.exe" : "picket-tui");
        return await RunProcessAsync(executablePath, arguments, repositoryRoot).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunProcessAsync(
        string fileName,
        string[] arguments,
        string workingDirectory)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(fileName)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        for (int i = 0; i < arguments.Length; i++)
        {
            process.StartInfo.ArgumentList.Add(arguments[i]);
        }

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
    }

    private static string FindRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory, "Picket.slnx")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
