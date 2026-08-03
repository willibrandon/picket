using Hex1b;
using Hex1b.Automation;
using Hex1b.Documents;
using Hex1b.Input;
using Hex1b.Theming;
using Hex1b.Widgets;
using Picket.Report;
using Picket.Tui;
using System.Diagnostics;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests the interactive report triage console state and terminal accessibility requirements.
/// </summary>
[TestClass]
public sealed class PicketTuiTests
{
    private static readonly Lock s_editorEnvironmentLock = new();
    private static readonly HashSet<string> s_spinnerFrames = [.. SpinnerStyle.Dots.Frames];

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that every TUI workspace opens on the first-position dashboard.
    /// </summary>
    [TestMethod]
    public void StateStartsOnFirstPositionDashboard()
    {
        PicketTuiState populatedState = CreateState();
        PicketTuiState emptyState = CreateEmptyState();

        Assert.AreEqual(PicketTuiView.Dashboard, populatedState.CurrentView);
        Assert.AreEqual(PicketTuiView.Dashboard, emptyState.CurrentView);
        Assert.HasCount(6, PicketTuiState.NavigationItems);
        Assert.AreEqual(PicketTuiView.Dashboard, PicketTuiState.NavigationItems[0]);
        Assert.AreEqual(PicketTuiView.Scan, PicketTuiState.NavigationItems[1]);
    }

    /// <summary>
    /// Verifies that one-based tab numbers select each top-level view.
    /// </summary>
    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    [DataRow(6)]
    public void StateSelectsViewByOneBasedTabNumber(int tabNumber)
    {
        PicketTuiState state = CreateState();

        state.SetViewByTabNumber(tabNumber);

        Assert.AreEqual((PicketTuiView)(tabNumber - 1), state.CurrentView);
    }

    /// <summary>
    /// Verifies that one-based tab selection rejects values outside the visible tab range.
    /// </summary>
    [TestMethod]
    public void StateRejectsTabNumberOutsideVisibleRange()
    {
        PicketTuiState state = CreateState();

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => state.SetViewByTabNumber(0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => state.SetViewByTabNumber(7));
    }

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
    /// Verifies that Vim-style finding movement stays within the filtered visible rows.
    /// </summary>
    [TestMethod]
    public void StateMovesFocusedFindingWithinVisibleRows()
    {
        PicketTuiState state = CreateState();

        state.MoveFindingFocus(1);

        Assert.AreEqual("fp-auth-2", state.FocusedFinding?.Fingerprint);

        state.MoveFindingFocus(99);

        Assert.AreEqual("fp-infra-1", state.FocusedFinding?.Fingerprint);

        state.SetSearchText("auth");
        state.MoveFindingFocus(-99);

        Assert.AreEqual("fp-auth-1", state.FocusedFinding?.Fingerprint);
    }

    /// <summary>
    /// Verifies that contextual yanking copies useful finding metadata without loading secret evidence.
    /// </summary>
    [TestMethod]
    public void StateYanksFocusedFindingMetadata()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);

        string text = state.GetYankText();

        Assert.IsTrue(state.HasYankText);
        Assert.Contains("Rule: github-token", text);
        Assert.Contains("Severity: critical", text);
        Assert.Contains("Confidence: high", text);
        Assert.Contains("Validation: active", text);
        Assert.Contains("Path: src/auth.cs", text);
        Assert.Contains("Line: 12", text);
        Assert.Contains("Commit: 0123456789abcdef", text);
        Assert.Contains("Author: Ada Lovelace", text);
        Assert.Contains("Fingerprint: fp-auth-1", text);
        Assert.Contains("Randomness: 0.902542 (likely-random)", text);
        Assert.Contains("Randomness model: picket-random-v1", text);
        Assert.Contains("Report: report.json", text);
        Assert.DoesNotContain("Secret", text);
        Assert.IsLessThan(
            text.IndexOf("Randomness:", StringComparison.Ordinal),
            text.IndexOf("Severity:", StringComparison.Ordinal));
    }

    /// <summary>
    /// Verifies that dashboard yanking includes labelled report, scanner, rule, and file summaries.
    /// </summary>
    [TestMethod]
    public void StateYanksLabelledDashboardSummary()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Dashboard);

        string text = state.GetYankText();

        Assert.Contains("Report", text);
        Assert.Contains("Scanner", text);
        Assert.Contains("Top rules by finding count", text);
        Assert.Contains("Findings  Rule", text);
        Assert.Contains("github-token", text);
        Assert.Contains("Top files by finding count", text);
        Assert.Contains("Findings  File", text);
        Assert.Contains("src/auth.cs", text);
    }

    /// <summary>
    /// Verifies that selected read-only editor text is yankable, flashes, and collapses to its final character.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task StateYanksSelectedReadOnlyEditorTextWithFlashAndCollapsesSelection()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Dashboard);
        state.GetDashboardEditorState().SelectAll();
        using var invalidated = new ManualResetEventSlim();

        bool selected = state.TryGetSelectedEditorText(
            null,
            out string text,
            out var editorState,
            out var provider,
            out var range);

        Assert.IsTrue(selected);
        Assert.Contains("Report", text);
        Assert.Contains("Scanner", text);

        state.ShowEditorYankNotification(text, editorState, provider, range, invalidated.Set, TestContext.CancellationToken);

        Assert.IsFalse(editorState.Cursor.HasSelection);
        Assert.AreEqual(new DocumentOffset(range.End.Value - 1), editorState.Cursor.Position);
        Assert.IsNotNull(provider.HighlightRange);
        Assert.IsFalse(state.YankFlashRow);
        Assert.IsNotNull(state.YankNotification);

        while (provider.HighlightRange is not null)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsTrue(invalidated.IsSet);
        Assert.IsNull(provider.HighlightRange);
        Assert.IsFalse(editorState.Cursor.HasSelection);
        Assert.AreEqual(new DocumentOffset(range.End.Value - 1), editorState.Cursor.Position);
    }

    /// <summary>
    /// Verifies that multiline yank flashes stop at each line's selected text instead of filling the viewport.
    /// </summary>
    [TestMethod]
    public void YankDecorationStopsAtSelectedTextOnEachLine()
    {
        var document = new Hex1bDocument("alpha\nmiddle\nbeta");
        var provider = new PicketTuiYankDecorationProvider
        {
            HighlightRange = (new DocumentPosition(1, 2), new DocumentPosition(3, 3)),
        };

        IReadOnlyList<TextDecorationSpan> spans = provider.GetDecorations(1, 3, document);

        Assert.HasCount(3, spans);
        Assert.AreEqual(new DocumentPosition(1, 2), spans[0].Start);
        Assert.AreEqual(new DocumentPosition(1, 6), spans[0].End);
        Assert.AreEqual(new DocumentPosition(2, 1), spans[1].Start);
        Assert.AreEqual(new DocumentPosition(2, 7), spans[1].End);
        Assert.AreEqual(new DocumentPosition(3, 1), spans[2].Start);
        Assert.AreEqual(new DocumentPosition(3, 3), spans[2].End);
    }

    /// <summary>
    /// Verifies that a plain yank targets and flashes the complete focused read-only pane.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task StateFlashesWholeFocusedReadOnlyEditorForPlainYank()
    {
        PicketTuiState state = CreateState();
        EditorState dashboardEditor = state.GetDashboardEditorState();
        using var invalidated = new ManualResetEventSlim();

        bool found = state.TryGetFocusedEditorYankTarget(
            dashboardEditor,
            out string text,
            out EditorState editorState,
            out PicketTuiYankDecorationProvider provider,
            out DocumentRange range);

        Assert.IsTrue(found);
        Assert.Contains("Severity:", text);
        Assert.Contains("Validation:", text);
        Assert.AreSame(dashboardEditor, editorState);
        Assert.AreSame(state.DashboardYankProvider, provider);
        Assert.AreEqual(DocumentOffset.Zero, range.Start);
        Assert.AreEqual((DocumentOffset)dashboardEditor.Document.Length, range.End);

        state.ShowEditorYankNotification(
            text,
            editorState,
            provider,
            range,
            invalidated.Set,
            TestContext.CancellationToken);

        Assert.IsNotNull(provider.HighlightRange);
        Assert.IsFalse(state.YankFlashRow);
        Assert.AreEqual(DocumentOffset.Zero, editorState.Cursor.Position);

        while (provider.HighlightRange is not null)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsTrue(invalidated.IsSet);
    }

    /// <summary>
    /// Verifies that rules and files expose focused-row yanks with labelled counts.
    /// </summary>
    [TestMethod]
    public void StateYanksFocusedRuleAndFileRows()
    {
        PicketTuiState state = CreateState();

        state.SetView(PicketTuiView.Rules);
        state.FocusRule("github-token");

        string ruleText = state.GetYankText();

        Assert.Contains("Rule: github-token", ruleText);
        Assert.Contains("Findings: 2", ruleText);

        state.SetView(PicketTuiView.Files);
        state.FocusFile("src/auth.cs");

        string fileText = state.GetYankText();

        Assert.Contains("File: src/auth.cs", fileText);
        Assert.Contains("Findings: 2", fileText);
    }

    /// <summary>
    /// Verifies that clearing table selection removes every selected row relevant to the active view.
    /// </summary>
    [TestMethod]
    public void StateClearsSelectedRowsForActiveView()
    {
        PicketTuiState state = CreateState();
        state.FocusRule("github-token");
        state.FocusFile("src/auth.cs");

        Assert.IsTrue(state.ClearSelectedRows());
        Assert.AreEqual("github-token", state.FocusedRuleKey);
        Assert.AreEqual("src/auth.cs", state.FocusedFileKey);
        Assert.IsNull(state.SelectedRuleKey);
        Assert.IsNull(state.SelectedFileKey);
        Assert.IsNull(state.FocusedCountTableKind);

        state.SetView(PicketTuiView.Findings);
        state.FocusFinding(state.VisibleRows[0].Key);

        Assert.IsTrue(state.ClearSelectedRows());
        Assert.IsNotNull(state.FocusedFindingKey);
        Assert.IsNull(state.SelectedFindingKey);

        state.SetView(PicketTuiView.Rules);
        state.FocusRule("github-token");

        Assert.IsTrue(state.ClearSelectedRows());
        Assert.AreEqual("github-token", state.FocusedRuleKey);
        Assert.IsNull(state.SelectedRuleKey);

        state.SetView(PicketTuiView.Files);
        state.FocusFile("src/auth.cs");

        Assert.IsTrue(state.ClearSelectedRows());
        Assert.AreEqual("src/auth.cs", state.FocusedFileKey);
        Assert.IsNull(state.SelectedFileKey);
        Assert.IsFalse(state.ClearSelectedRows());
    }

    /// <summary>
    /// Verifies that rule and file rows can filter the findings table.
    /// </summary>
    [TestMethod]
    public void StateFiltersFindingsFromFocusedRuleAndFileRows()
    {
        PicketTuiState state = CreateState();

        state.FocusRule("github-token");
        state.FilterFindingsToFocusedRule();

        Assert.AreEqual(PicketTuiView.Findings, state.CurrentView);
        Assert.AreEqual("github-token", state.SearchText);
        Assert.HasCount(2, state.VisibleRows);

        state.ClearSearch();
        state.FocusFile("infra/main.tf");
        state.FilterFindingsToFocusedFile();

        Assert.AreEqual(PicketTuiView.Findings, state.CurrentView);
        Assert.AreEqual("infra/main.tf", state.SearchText);
        Assert.HasCount(1, state.VisibleRows);
        Assert.AreEqual("aws-key", state.VisibleRows[0].RuleId);
    }

    /// <summary>
    /// Verifies that count-table filters select exact rule and path keys instead of substring matches.
    /// </summary>
    [TestMethod]
    public void StateFiltersCountRowsByExactKey()
    {
        var summary = new ReportSummary(
            "picket-json",
            [
                new ReportFindingSummary("token", "src/app.cs", 1, "fp-1"),
                new ReportFindingSummary("token-extended", "src/app.generated.cs", 2, "fp-2"),
            ]);
        var state = new PicketTuiState(new PicketTuiReport("report.json", summary, DateTimeOffset.UnixEpoch));

        state.FocusRule("token");
        state.FilterFindingsToFocusedRule();

        Assert.HasCount(1, state.VisibleRows);
        Assert.AreEqual("token", state.VisibleRows[0].RuleId);

        state.ClearSearch();
        state.FocusFile("src/app.cs");
        state.FilterFindingsToFocusedFile();

        Assert.HasCount(1, state.VisibleRows);
        Assert.AreEqual("src/app.cs", state.VisibleRows[0].Path);
    }

    /// <summary>
    /// Verifies that each top-level tab publishes a deterministic primary focus target.
    /// </summary>
    [TestMethod]
    public void StateQueuesExpectedFocusTargetForEachTab()
    {
        PicketTuiState state = CreateState();

        Assert.AreEqual(PicketTuiFocusTarget.DashboardEditor, state.ConsumePendingFocusTarget());
        Assert.IsNull(state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Scan);
        Assert.AreEqual(PicketTuiFocusTarget.ScanPrimaryControl, state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Findings);
        Assert.AreEqual(PicketTuiFocusTarget.FindingsTable, state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Rules);
        Assert.AreEqual(PicketTuiFocusTarget.RulesTable, state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Files);
        Assert.AreEqual(PicketTuiFocusTarget.FilesTable, state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Logs);
        Assert.AreEqual(PicketTuiFocusTarget.LogsSearch, state.ConsumePendingFocusTarget());
    }

    /// <summary>
    /// Verifies that opening a focused finding queues and then launches the file request with the finding line.
    /// </summary>
    [TestMethod]
    public void StateQueuesAndOpensFocusedFindingFile()
    {
        var launcher = new PicketTuiFakeFileLauncher { Message = "Opened src/auth.cs" };
        PicketTuiState state = CreateState(fileLauncher: launcher);

        bool queued = state.RequestOpenFocusedFindingFile();

        Assert.IsTrue(queued);
        Assert.AreEqual(string.Empty, launcher.CapturedPath);
        Assert.IsTrue(state.TryOpenPendingFile());
        Assert.AreEqual("src/auth.cs", launcher.CapturedPath);
        Assert.AreEqual(12, launcher.CapturedLine);
        Assert.AreEqual(7, launcher.CapturedColumn);
        Assert.AreEqual("Opened src/auth.cs", state.StatusMessage);
        Assert.AreEqual(PicketTuiFocusTarget.FindingsTable, state.ConsumePendingFocusTarget());
    }

    /// <summary>
    /// Verifies that opening a focused file queues and then launches the file request at that file's first finding.
    /// </summary>
    [TestMethod]
    public void StateQueuesAndOpensFocusedFileRowAtFirstFinding()
    {
        var launcher = new PicketTuiFakeFileLauncher { Message = "Opened infra/main.tf" };
        PicketTuiState state = CreateState(fileLauncher: launcher);
        state.FocusFile("infra/main.tf");

        bool queued = state.RequestOpenFocusedFile();

        Assert.IsTrue(queued);
        Assert.AreEqual(string.Empty, launcher.CapturedPath);
        Assert.IsTrue(state.TryOpenPendingFile());
        Assert.AreEqual("infra/main.tf", launcher.CapturedPath);
        Assert.AreEqual(4, launcher.CapturedLine);
        Assert.AreEqual(3, launcher.CapturedColumn);
        Assert.AreEqual("Opened infra/main.tf", state.StatusMessage);
        Assert.AreEqual(PicketTuiFocusTarget.FilesTable, state.ConsumePendingFocusTarget());
    }

    /// <summary>
    /// Verifies that all findings remain present when navigating away from and back to the findings tab.
    /// </summary>
    [TestMethod]
    public void StateKeepsVisibleRowsStableAcrossTabSwitches()
    {
        List<ReportFindingSummary> findings = [];
        for (int i = 0; i < 51; i++)
        {
            findings.Add(new ReportFindingSummary("generic-api-key", "src/file.cs", i + 1, string.Concat("fp-", i.ToString("00"))));
        }

        findings.Add(new ReportFindingSummary("aws-access-token", "src/last.cs", 52, "fp-last"));
        var state = new PicketTuiState(new PicketTuiReport(
            "report.json",
            new ReportSummary("picket-json", findings),
            DateTimeOffset.UnixEpoch));

        for (int i = 0; i < 3; i++)
        {
            state.SetView(PicketTuiView.Dashboard);
            state.SetView(PicketTuiView.Findings);

            Assert.HasCount(52, state.VisibleRows);
            Assert.AreEqual("aws-access-token", state.VisibleRows[^1].RuleId);
        }
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
        string defaultReportPath = Path.Combine(Path.GetTempPath(), "picket", "reports", "picket-tui.jsonl");

        Assert.Contains("Command: picket scan", text);
        Assert.Contains($"Report: {defaultReportPath}", text);
        Assert.Contains("Status: Ready to scan", text);
        Assert.Contains("Timing: Not run yet", text);
        Assert.Contains("Summary: 3 findings across 2 files in picket-json", text);
        Assert.DoesNotContain("Focused finding:", text);
        Assert.DoesNotContain("Rule: github-token", text);
        Assert.Contains("Scanner output:", text);
        Assert.Contains("No scanner output captured.", text);
        Assert.DoesNotContain("Secret", text);
    }

    /// <summary>
    /// Verifies that log search filters scanner output while preserving scan metadata.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task StateSearchesAndYanksLogs()
    {
        var executor = new PicketTuiFakeScanExecutor { InitialOutputLine = "enumerated 1 file" };
        PicketTuiState state = CreateState(executor);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);
        state.SetView(PicketTuiView.Logs);
        string status = state.StatusMessage;
        state.SetLogSearchText("finding");

        string text = state.GetYankText();

        Assert.AreEqual(status, state.StatusMessage);
        Assert.DoesNotContain("Log search:", text);
        Assert.Contains("Scanner output matching \"finding\"", text);
        Assert.Contains("stderr: 1 finding", text);
        Assert.DoesNotContain("enumerated 1 file", text);
        Assert.DoesNotContain("stdout: scan complete", text);
    }

    /// <summary>
    /// Verifies that log decorations distinguish failures, warnings, and active search matches.
    /// </summary>
    [TestMethod]
    public void LogDecorationsExposeSemanticLevelsAndSearchMatches()
    {
        var document = new Hex1bDocument(
            """
            stderr: fatal error
            stderr: warning: archive limit reached
            stdout: token found
            """);
        var provider = new PicketTuiLogDecorationProvider
        {
            Query = "token",
        };

        IReadOnlyList<TextDecorationSpan> decorations = provider.GetDecorations(1, 3, document);

        Assert.HasCount(3, decorations);
        TextDecorationSpan error = decorations.Single(static span => span.Start.Line == 1);
        TextDecorationSpan warning = decorations.Single(static span => span.Start.Line == 2);
        TextDecorationSpan search = decorations.Single(static span => span.Start.Line == 3);
        Assert.AreEqual(PicketTuiPalette.ErrorForeground, error.Decoration.Foreground);
        Assert.AreEqual(PicketTuiPalette.WarningForeground, warning.Decoration.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, search.Decoration.Foreground);
        Assert.AreEqual(PicketTuiPalette.EditorSelectionBackground, search.Decoration.Background);
    }

    /// <summary>
    /// Verifies that editor launch arguments are line-aware for common developer editor commands.
    /// </summary>
    [TestMethod]
    public void FileLauncherCreatesLineAwareCodeCommand()
    {
        lock (s_editorEnvironmentLock)
        {
            string? previousPicketEditor = Environment.GetEnvironmentVariable("PICKET_EDITOR");
            try
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", "code -g");

                ProcessStartInfo startInfo = PicketTuiProcessFileLauncher.CreateStartInfo("src/app.cs", 42, 9);

                Assert.AreEqual("code", startInfo.FileName);
                Assert.IsFalse(startInfo.UseShellExecute);
                Assert.Contains("-g", startInfo.ArgumentList);
                Assert.Contains("src/app.cs:42:8", startInfo.ArgumentList);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", previousPicketEditor);
            }
        }
    }

    /// <summary>
    /// Verifies that terminal editor launch arguments are line-aware.
    /// </summary>
    [TestMethod]
    public void FileLauncherCreatesLineAwareTerminalEditorCommand()
    {
        lock (s_editorEnvironmentLock)
        {
            string? previousPicketEditor = Environment.GetEnvironmentVariable("PICKET_EDITOR");
            try
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", "nvim");

                ProcessStartInfo startInfo = PicketTuiProcessFileLauncher.CreateStartInfo("src/app.cs", 12, 5);

                Assert.AreEqual("nvim", startInfo.FileName);
                Assert.IsFalse(startInfo.UseShellExecute);
                Assert.Contains("+call cursor(12, 4)", startInfo.ArgumentList);
                Assert.Contains("src/app.cs", startInfo.ArgumentList);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", previousPicketEditor);
            }
        }
    }

    /// <summary>
    /// Verifies that first-line editor columns are not shifted.
    /// </summary>
    [TestMethod]
    public void FileLauncherKeepsFirstLineEditorColumn()
    {
        lock (s_editorEnvironmentLock)
        {
            string? previousPicketEditor = Environment.GetEnvironmentVariable("PICKET_EDITOR");
            try
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", "nvim");

                ProcessStartInfo startInfo = PicketTuiProcessFileLauncher.CreateStartInfo("src/app.cs", 1, 5);

                Assert.Contains("+call cursor(1, 5)", startInfo.ArgumentList);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", previousPicketEditor);
            }
        }
    }

    /// <summary>
    /// Verifies that opening a finding never shell-executes its path when no editor is available.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public void FileLauncherRequiresAnEditorInsteadOfShellExecutingPath()
    {
        lock (s_editorEnvironmentLock)
        {
            string? previousPicketEditor = Environment.GetEnvironmentVariable("PICKET_EDITOR");
            string? previousVisual = Environment.GetEnvironmentVariable("VISUAL");
            string? previousEditor = Environment.GetEnvironmentVariable("EDITOR");
            string? previousPath = Environment.GetEnvironmentVariable("PATH");
            try
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", null);
                Environment.SetEnvironmentVariable("VISUAL", null);
                Environment.SetEnvironmentVariable("EDITOR", null);
                Environment.SetEnvironmentVariable("PATH", string.Empty);

                InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
                    () => PicketTuiProcessFileLauncher.CreateStartInfo("untrusted.exe", 1, 1));

                Assert.Contains("Set PICKET_EDITOR", exception.Message);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_EDITOR", previousPicketEditor);
                Environment.SetEnvironmentVariable("VISUAL", previousVisual);
                Environment.SetEnvironmentVariable("EDITOR", previousEditor);
                Environment.SetEnvironmentVariable("PATH", previousPath);
            }
        }
    }

    /// <summary>
    /// Verifies that scanner resolution never discovers a development project from the working directory.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    public void ScanExecutorDoesNotResolveWorkingDirectoryProject()
    {
        lock (s_editorEnvironmentLock)
        {
            using TempDirectory temp = TempDirectory.Create();
            string projectDirectory = Path.Combine(temp.Path, "src", "Picket.Cli");
            Directory.CreateDirectory(projectDirectory);
            File.WriteAllText(Path.Combine(projectDirectory, "Picket.Cli.csproj"), "<Project />");
            string previousDirectory = Directory.GetCurrentDirectory();
            string? previousPath = Environment.GetEnvironmentVariable("PATH");
            string? previousScanner = Environment.GetEnvironmentVariable("PICKET_SCANNER");
            try
            {
                Directory.SetCurrentDirectory(temp.Path);
                Environment.SetEnvironmentVariable("PATH", string.Empty);
                Environment.SetEnvironmentVariable("PICKET_SCANNER", null);

                string resolvedPath = PicketTuiProcessScanExecutor.ResolvePicketPath();

                Assert.IsTrue(Path.IsPathFullyQualified(resolvedPath));
                Assert.DoesNotContain("Picket.Cli.csproj", resolvedPath);
                Assert.DoesNotContain(temp.Path, resolvedPath);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_SCANNER", previousScanner);
                Environment.SetEnvironmentVariable("PATH", previousPath);
                Directory.SetCurrentDirectory(previousDirectory);
            }
        }
    }

    /// <summary>
    /// Verifies that the scan executor resolves and launches a Windows global-tool command shim.
    /// </summary>
    [TestMethod]
    [DoNotParallelize]
    [OSCondition(ConditionMode.Include, OperatingSystems.Windows)]
    public async Task ScanExecutorLaunchesWindowsGlobalToolCommandShim()
    {
        using TempDirectory temp = TempDirectory.Create();
        string shimPath = Path.Combine(temp.Path, "picket.cmd");
        File.WriteAllText(
            shimPath,
            "@echo off\r\necho scanner-shim %*\r\nexit /b 0\r\n",
            Encoding.ASCII);
        string tuiDirectory = Path.Combine(temp.Path, "tui");
        Directory.CreateDirectory(tuiDirectory);
        string resolvedPath;
        lock (s_editorEnvironmentLock)
        {
            string? previousPath = Environment.GetEnvironmentVariable("PATH");
            string? previousScanner = Environment.GetEnvironmentVariable("PICKET_SCANNER");
            try
            {
                Environment.SetEnvironmentVariable("PATH", temp.Path);
                Environment.SetEnvironmentVariable("PICKET_SCANNER", null);
                resolvedPath = PicketTuiProcessScanExecutor.ResolvePicketPath(tuiDirectory);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PICKET_SCANNER", previousScanner);
                Environment.SetEnvironmentVariable("PATH", previousPath);
            }
        }

        Assert.AreEqual(shimPath, resolvedPath, StringComparer.OrdinalIgnoreCase);
        var executor = new PicketTuiProcessScanExecutor(resolvedPath);
        PicketTuiScanExecutionResult result = await executor.RunAsync(
            ["scan", "."],
            Path.Combine(temp.Path, "picket.jsonl"),
            static _ => { },
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("scanner-shim scan .", result.StandardOutput);
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
        scan.SetLiveMaxRequests("40");
        scan.SetLiveMaxRequestsPerProvider("10");
        scan.SetStrictRulePack(true);
        scan.SetExperimentalRulePack(true);
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
        Assert.Contains("--live-max-requests", arguments);
        Assert.Contains("40", arguments);
        Assert.Contains("--live-max-requests-per-provider", arguments);
        Assert.Contains("10", arguments);
        Assert.HasCount(2, arguments.Where(static argument => argument == "--rule-pack").ToArray());
        Assert.Contains("picket-strict", arguments);
        Assert.Contains("picket-experimental", arguments);
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
    /// Verifies that the scan workspace rejects non-positive live request budgets.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsNonPositiveLiveRequestBudget()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetVerify(true);
        scan.SetLiveMaxRequestsPerProvider("0");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--live-max-requests-per-provider requires an integer from 1", error);
    }

    /// <summary>
    /// Verifies the scan workspace exposes native Git changes with its local path and checkpoint.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGitChangesArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetTargetMode((int)PicketTuiScanTargetMode.GitChanges);
        scan.SetLocalPath("src");
        scan.SetCheckpointPath("picket-results/git-changes.checkpoint");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--git-changes", arguments);
        Assert.Contains("src", arguments);
        Assert.Contains("--checkpoint", arguments);
        Assert.Contains("picket-results/git-changes.checkpoint", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace groups targets so the TUI selector stays readable.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceGroupsTargetModesByCategory()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        Assert.AreEqual(PicketTuiScanTargetCategory.Local, scan.TargetCategory);
        Assert.HasCount(4, PicketTuiScanWorkspace.TargetCategoryLabels);
        Assert.HasCount(2, scan.ActiveTargetModeLabels);
        Assert.Contains("Git changes", scan.ActiveTargetModeLabels);

        scan.SetTargetModeByCategoryIndex(1);

        Assert.AreEqual(PicketTuiScanTargetMode.GitChanges, scan.TargetMode);
        Assert.AreEqual(1, scan.TargetModeIndex);

        scan.SetTargetCategoryByIndex((int)PicketTuiScanTargetCategory.ObjectStore);

        Assert.AreEqual(PicketTuiScanTargetMode.S3, scan.TargetMode);
        Assert.AreEqual(0, scan.TargetModeIndex);
        Assert.HasCount(3, scan.ActiveTargetModeLabels);
        Assert.Contains("Azure Blob", scan.ActiveTargetModeLabels);

        scan.SetTargetModeByCategoryIndex(2);

        Assert.AreEqual(PicketTuiScanTargetMode.AzureBlob, scan.TargetMode);
        Assert.AreEqual(PicketTuiScanTargetCategory.ObjectStore, scan.TargetCategory);
        Assert.AreEqual(2, scan.TargetModeIndex);

        scan.SetTargetCategoryByIndex((int)PicketTuiScanTargetCategory.Container);

        Assert.AreEqual(PicketTuiScanTargetMode.DockerArchive, scan.TargetMode);
        Assert.HasCount(3, scan.ActiveTargetModeLabels);
        Assert.Contains("OCI archive", scan.ActiveTargetModeLabels);
        Assert.Contains("Registry", scan.ActiveTargetModeLabels);

        scan.SetTargetCategoryByIndex((int)PicketTuiScanTargetCategory.SourceHost);
        scan.SetTargetModeByCategoryIndex(5);

        Assert.AreEqual(PicketTuiScanTargetMode.BitbucketDataCenter, scan.TargetMode);
        Assert.HasCount(7, scan.ActiveTargetModeLabels);
        Assert.Contains("Bitbucket Data Center", scan.ActiveTargetModeLabels);
        Assert.Contains("Hugging Face", scan.ActiveTargetModeLabels);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Docker archive scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsDockerArchiveScanArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.DockerArchive);
        scan.SetDockerArchivePath("images/app.tar");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--docker-archive", arguments);
        Assert.Contains("images/app.tar", arguments);
        Assert.DoesNotContain("--oci-archive", arguments);
    }

    /// <summary>
    /// Verifies that source scans can persist and explicitly reset checkpoint state.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsCheckpointArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetTargetMode((int)PicketTuiScanTargetMode.DockerArchive);
        scan.SetDockerArchivePath("images/app.tar");
        scan.SetCheckpointPath("picket-results/app.checkpoint");
        scan.SetResetCheckpoint(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--checkpoint", arguments);
        Assert.Contains("picket-results/app.checkpoint", arguments);
        Assert.Contains("--checkpoint-reset", arguments);
    }

    /// <summary>
    /// Verifies that local filesystem scans reject source checkpointing.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsCheckpointForLocalTarget()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetCheckpointPath("picket-results/local.checkpoint");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Checkpointing requires", error);
    }

    /// <summary>
    /// Verifies that reset cannot be selected without a checkpoint path.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsCheckpointResetWithoutPath()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetTargetMode((int)PicketTuiScanTargetMode.DockerArchive);
        scan.SetDockerArchivePath("images/app.tar");
        scan.SetResetCheckpoint(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("requires a checkpoint path", error);
    }

    /// <summary>
    /// Verifies that the scan workspace builds OCI archive scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsOciArchiveScanArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.OciArchive);
        scan.SetOciArchivePath("images/app.oci.tar");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--oci-archive", arguments);
        Assert.Contains("images/app.oci.tar", arguments);
        Assert.DoesNotContain("--docker-archive", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds remote container-registry scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsContainerRegistryScanArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.RegistryImage);
        scan.SetRegistryImage("ghcr.io/willibrandon/picket:latest");
        scan.SetRegistryEndpoint("https://ghcr.io/");
        scan.SetRegistryAuthenticationEndpoint("https://ghcr.io/token");
        scan.SetRegistryTokenEnvironmentVariable("PICKET_REGISTRY_TOKEN");
        scan.SetRegistryPlatform("linux/amd64");
        scan.SetRegistryMaxImageMegabytes("256");
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--registry-image", arguments);
        Assert.Contains("ghcr.io/willibrandon/picket:latest", arguments);
        Assert.Contains("--registry-endpoint", arguments);
        Assert.Contains("https://ghcr.io/", arguments);
        Assert.Contains("--registry-auth-endpoint", arguments);
        Assert.Contains("https://ghcr.io/token", arguments);
        Assert.Contains("--registry-token-env", arguments);
        Assert.Contains("PICKET_REGISTRY_TOKEN", arguments);
        Assert.Contains("--registry-platform", arguments);
        Assert.Contains("linux/amd64", arguments);
        Assert.Contains("--registry-max-image-megabytes", arguments);
        Assert.Contains("256", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds S3 object-store scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsS3SourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.S3);
        scan.SetS3Bucket("secret-bucket");
        scan.SetS3Region("us-west-2");
        scan.SetS3Endpoint("https://s3.example");
        scan.SetS3Prefix("prod/");
        scan.SetS3AccessKeyIdEnvironmentVariable("PICKET_S3_ACCESS_KEY_ID");
        scan.SetS3SecretAccessKeyEnvironmentVariable("PICKET_S3_SECRET_ACCESS_KEY");
        scan.SetS3SessionTokenEnvironmentVariable("PICKET_S3_SESSION_TOKEN");
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--s3-bucket", arguments);
        Assert.Contains("secret-bucket", arguments);
        Assert.Contains("--s3-region", arguments);
        Assert.Contains("us-west-2", arguments);
        Assert.Contains("--s3-endpoint", arguments);
        Assert.Contains("https://s3.example", arguments);
        Assert.Contains("--s3-prefix", arguments);
        Assert.Contains("prod/", arguments);
        Assert.Contains("--s3-access-key-id-env", arguments);
        Assert.Contains("PICKET_S3_ACCESS_KEY_ID", arguments);
        Assert.Contains("--s3-secret-access-key-env", arguments);
        Assert.Contains("PICKET_S3_SECRET_ACCESS_KEY", arguments);
        Assert.Contains("--s3-session-token-env", arguments);
        Assert.Contains("PICKET_S3_SESSION_TOKEN", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Google Cloud Storage scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGcsSourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.Gcs);
        scan.SetGcsBucket("secret-bucket");
        scan.SetGcsEndpoint("https://storage.example");
        scan.SetGcsPrefix("prod/");
        scan.SetGcsTokenEnvironmentVariable("PICKET_GCS_TOKEN");
        scan.SetGcsUserProject("billing-project");
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--gcs-bucket", arguments);
        Assert.Contains("secret-bucket", arguments);
        Assert.Contains("--gcs-endpoint", arguments);
        Assert.Contains("https://storage.example", arguments);
        Assert.Contains("--gcs-prefix", arguments);
        Assert.Contains("prod/", arguments);
        Assert.Contains("--gcs-token-env", arguments);
        Assert.Contains("PICKET_GCS_TOKEN", arguments);
        Assert.Contains("--gcs-user-project", arguments);
        Assert.Contains("billing-project", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Azure Blob Storage scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsAzureBlobSourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.AzureBlob);
        scan.SetAzureBlobEndpoint("https://account.blob.core.windows.net");
        scan.SetAzureBlobContainer("secrets");
        scan.SetAzureBlobPrefix("prod/");
        scan.SetAzureBlobTokenEnvironmentVariable("PICKET_AZURE_BLOB_TOKEN");
        scan.SetAzureBlobTokenKindByIndex(1);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--azure-blob-endpoint", arguments);
        Assert.Contains("https://account.blob.core.windows.net", arguments);
        Assert.Contains("--azure-blob-container", arguments);
        Assert.Contains("secrets", arguments);
        Assert.Contains("--azure-blob-prefix", arguments);
        Assert.Contains("prod/", arguments);
        Assert.Contains("--azure-blob-token-env", arguments);
        Assert.Contains("PICKET_AZURE_BLOB_TOKEN", arguments);
        Assert.Contains("--azure-blob-token-kind", arguments);
        Assert.Contains("sas", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that Docker archive scans require an archive path before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMissingDockerArchivePath()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.DockerArchive);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Docker archive scans require an archive path", error);
    }

    /// <summary>
    /// Verifies that OCI archive scans require an archive path before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMissingOciArchivePath()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.OciArchive);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("OCI archive scans require an archive path", error);
    }

    /// <summary>
    /// Verifies that remote container-registry scans require an image reference before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMissingContainerRegistryImage()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.RegistryImage);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Container registry scans require an image reference", error);
    }

    /// <summary>
    /// Verifies that remote container-registry scans reject ambiguous credential modes.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsAmbiguousContainerRegistryCredentials()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.RegistryImage);
        scan.SetRegistryImage("registry.example/team/app:latest");
        scan.SetRegistryTokenEnvironmentVariable("PICKET_REGISTRY_TOKEN");
        scan.SetRegistryUsernameEnvironmentVariable("PICKET_REGISTRY_USERNAME");
        scan.SetRegistryPasswordEnvironmentVariable("PICKET_REGISTRY_PASSWORD");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Registry authentication accepts a token environment variable or both username and password environment variables", error);
    }

    /// <summary>
    /// Verifies registry layer traversal keeps archive safety limits unless traversal is disabled.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRequiresContainerRegistryArchiveLimits()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.RegistryImage);
        scan.SetRegistryImage("registry.example/team/app:latest");
        scan.SetMaxArchiveEntries("0");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--max-archive-entries requires an integer from 1", error);

        scan.SetMaxArchiveDepth("0");
        scan.SetMaxArchiveMegabytes("0");
        scan.SetMaxArchiveRatio("0");
        built = scan.TryBuildArguments(out arguments, out error);

        Assert.IsTrue(built, error);
        Assert.Contains("--max-archive-depth", arguments);
        Assert.Contains("0", arguments);
    }

    /// <summary>
    /// Verifies that S3 scans require the CLI's required source inputs before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsIncompleteS3Source()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.S3);
        scan.SetS3Bucket("secret-bucket");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("S3 scans require a region", error);
    }

    /// <summary>
    /// Verifies that Google Cloud Storage scans require the CLI's required source inputs before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsIncompleteGcsSource()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.Gcs);
        scan.SetGcsBucket("secret-bucket");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("GCS scans require a token environment variable", error);
    }

    /// <summary>
    /// Verifies that Azure Blob Storage scans require the CLI's required source inputs before launch.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsIncompleteAzureBlobSource()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.AzureBlob);
        scan.SetAzureBlobEndpoint("https://account.blob.core.windows.net");
        scan.SetAzureBlobContainer("secrets");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Azure Blob scans require a token environment variable", error);
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
    /// Verifies that the selected GitHub scope prevents retained values from creating a second source target.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsOnlySelectedGitHubSourceScope()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(1);
        scan.SetGitHubRepository("owner/repo");
        scan.SetGitHubOrganization("organization");
        scan.SetGitHubGist("abc123");
        scan.SetGitHubTokenEnvironmentVariable("PICKET_GITHUB_SECRET_SCANNING_PAT");
        scan.SetGitHubScopeByIndex((int)PicketTuiGitHubScope.Repository);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--github-repository", arguments);
        Assert.Contains("owner/repo", arguments);
        Assert.DoesNotContain("--github-organization", arguments);
        Assert.DoesNotContain("--github-gist", arguments);
    }

    /// <summary>
    /// Verifies that an incomplete GitHub repository scope reports the field and accepted value shape.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceExplainsIncompleteGitHubRepositoryScope()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(1);
        scan.SetGitHubTokenEnvironmentVariable("PICKET_GITHUB_SECRET_SCANNING_PAT");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.AreEqual(
            "Repository required: enter owner/name; personal repos use your username as owner.",
            error);
        Assert.IsEmpty(scan.BuildCommandLinePreview());
    }

    /// <summary>
    /// Verifies that failed TUI validation surfaces one actionable status without scanner-output duplication.
    /// </summary>
    [TestMethod]
    public async Task ScanWorkspaceUsesActionableGitHubValidationAsStatus()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetTargetMode(1);
        scan.SetGitHubRepository("willibrandon/picket");

        PicketTuiScanExecutionResult? result = await scan.RunAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result);
        Assert.AreEqual("Token env required: enter the variable name containing your GitHub token.", scan.Status);
        Assert.AreEqual(scan.Status, scan.LastMessage);
        Assert.IsEmpty(scan.CapturedOutputLines);

        scan.SetGitHubTokenEnvironmentVariable("PICKET_GITHUB_SECRET_SCANNING_PAT");

        Assert.AreEqual("Ready to scan", scan.Status);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Hugging Face repository arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsHuggingFaceRepositoryArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.HuggingFace);
        scan.SetHuggingFaceResourceKindByIndex((int)PicketTuiHuggingFaceResourceKind.Dataset);
        scan.SetHuggingFaceResourceId("owner/dataset");
        scan.SetHuggingFaceRevision("main");
        scan.SetHuggingFaceTokenEnvironmentVariable("HF_TOKEN");
        scan.SetHuggingFaceEndpoint("https://huggingface.example");
        scan.SetIncludeHuggingFaceDiscussions(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--huggingface-dataset", arguments);
        Assert.Contains("owner/dataset", arguments);
        Assert.Contains("--huggingface-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--huggingface-token-env", arguments);
        Assert.Contains("HF_TOKEN", arguments);
        Assert.Contains("--huggingface-endpoint", arguments);
        Assert.Contains("https://huggingface.example", arguments);
        Assert.Contains("--huggingface-include-discussions", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Hugging Face bucket arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsHuggingFaceBucketArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.HuggingFace);
        scan.SetHuggingFaceResourceKindByIndex((int)PicketTuiHuggingFaceResourceKind.Bucket);
        scan.SetHuggingFaceResourceId("owner/bucket");
        scan.SetHuggingFaceBucketPrefix("models/");
        scan.SetHuggingFaceTokenEnvironmentVariable("HF_TOKEN");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--huggingface-bucket", arguments);
        Assert.Contains("owner/bucket", arguments);
        Assert.Contains("--huggingface-bucket-prefix", arguments);
        Assert.Contains("models/", arguments);
        Assert.DoesNotContain("--huggingface-ref", arguments);
        Assert.DoesNotContain("--huggingface-pull-request", arguments);
        Assert.DoesNotContain("--huggingface-include-discussions", arguments);
    }

    /// <summary>
    /// Verifies that changing Hugging Face resource kinds clears settings that no longer apply.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceClearsHuggingFaceSettingsWhenResourceKindChanges()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode((int)PicketTuiScanTargetMode.HuggingFace);
        scan.SetHuggingFaceResourceId("owner/bucket");
        scan.SetHuggingFaceTokenEnvironmentVariable("HF_TOKEN");
        scan.SetHuggingFaceRevision("main");
        scan.SetHuggingFacePullRequest("7");
        scan.SetIncludeHuggingFaceDiscussions(true);
        scan.SetHuggingFaceResourceKindByIndex((int)PicketTuiHuggingFaceResourceKind.Bucket);

        Assert.IsEmpty(scan.HuggingFaceRevision);
        Assert.IsEmpty(scan.HuggingFacePullRequest);
        Assert.IsFalse(scan.IncludeHuggingFaceDiscussions);

        scan.SetHuggingFaceBucketPrefix("models/");
        scan.SetHuggingFaceResourceKindByIndex((int)PicketTuiHuggingFaceResourceKind.Model);

        Assert.IsEmpty(scan.HuggingFaceBucketPrefix);
    }

    /// <summary>
    /// Verifies that the scan workspace builds GitLab source scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGitLabSourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(3);
        scan.SetGitLabProject("group/project");
        scan.SetGitLabRef("main");
        scan.SetGitLabPipelineId("123");
        scan.SetGitLabTokenEnvironmentVariable("PICKET_GITLAB_SOURCE_TOKEN");
        scan.SetGitLabApiEndpoint("https://gitlab.example/api/v4");
        scan.SetIncludeGitLabSnippets(true);
        scan.SetIncludeGitLabJobArtifacts(true);
        scan.SetIncludeGitLabJobLogs(true);
        scan.SetIncludeGitLabPackages(true);
        scan.SetIncludeGitLabIssues(true);
        scan.SetGitLabIssueStateByIndex(2);
        scan.SetIncludeGitLabReleases(true);
        scan.SetIncludeGitLabReleaseAssets(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--gitlab-project", arguments);
        Assert.Contains("group/project", arguments);
        Assert.Contains("--gitlab-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--gitlab-pipeline-id", arguments);
        Assert.Contains("123", arguments);
        Assert.Contains("--gitlab-token-env", arguments);
        Assert.Contains("PICKET_GITLAB_SOURCE_TOKEN", arguments);
        Assert.Contains("--gitlab-api-endpoint", arguments);
        Assert.Contains("https://gitlab.example/api/v4", arguments);
        Assert.Contains("--gitlab-include-snippets", arguments);
        Assert.Contains("--gitlab-include-job-artifacts", arguments);
        Assert.Contains("--gitlab-include-job-logs", arguments);
        Assert.Contains("--gitlab-include-packages", arguments);
        Assert.Contains("--gitlab-include-issues", arguments);
        Assert.Contains("--gitlab-issue-state", arguments);
        Assert.Contains("closed", arguments);
        Assert.Contains("--gitlab-include-releases", arguments);
        Assert.Contains("--gitlab-include-release-assets", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects ambiguous GitLab source selectors.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMultipleGitLabSourceSelectors()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(3);
        scan.SetGitLabProject("group/project");
        scan.SetGitLabGroup("group");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("exactly one project or group selector", error);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects GitLab pipeline scans without a job source.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsGitLabPipelineWithoutJobSource()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(3);
        scan.SetGitLabProject("group/project");
        scan.SetGitLabPipelineId("123");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--gitlab-pipeline-id requires GitLab job logs or artifacts", error);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects GitLab merge request scans with issue and release scopes.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsGitLabMergeRequestWithIssuesAndReleases()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(3);
        scan.SetGitLabProject("group/project");
        scan.SetGitLabMergeRequest("42");
        scan.SetIncludeGitLabIssues(true);
        scan.SetIncludeGitLabReleases(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("merge request scans cannot include issues, releases, or release assets", error);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Gitea source scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGiteaSourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(4);
        scan.SetGiteaRepository("owner/repo");
        scan.SetGiteaRef("main");
        scan.SetGiteaActionsRunId("99");
        scan.SetGiteaTokenEnvironmentVariable("PICKET_GITEA_SOURCE_TOKEN");
        scan.SetGiteaApiEndpoint("https://gitea.example/api/v1");
        scan.SetGiteaIssueStateByIndex(2);
        scan.SetIncludeGiteaIssues(true);
        scan.SetIncludeGiteaReleases(true);
        scan.SetIncludeGiteaActionsArtifacts(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--gitea-repository", arguments);
        Assert.Contains("owner/repo", arguments);
        Assert.Contains("--gitea-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--gitea-actions-run-id", arguments);
        Assert.Contains("99", arguments);
        Assert.Contains("--gitea-token-env", arguments);
        Assert.Contains("PICKET_GITEA_SOURCE_TOKEN", arguments);
        Assert.Contains("--gitea-api-endpoint", arguments);
        Assert.Contains("https://gitea.example/api/v1", arguments);
        Assert.Contains("--gitea-issue-state", arguments);
        Assert.Contains("closed", arguments);
        Assert.Contains("--gitea-include-issues", arguments);
        Assert.Contains("--gitea-include-releases", arguments);
        Assert.Contains("--gitea-include-actions-artifacts", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Gitea generic package scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsGiteaGenericPackageArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(4);
        scan.SetGiteaGenericPackageOwner("owner");
        scan.SetGiteaGenericPackageName("package");
        scan.SetGiteaGenericPackageVersion("1.2.3");
        scan.SetGiteaGenericPackageFile("package.zip");
        scan.SetGiteaTokenEnvironmentVariable("PICKET_GITEA_SOURCE_TOKEN");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--gitea-generic-package-owner", arguments);
        Assert.Contains("owner", arguments);
        Assert.Contains("--gitea-generic-package-name", arguments);
        Assert.Contains("package", arguments);
        Assert.Contains("--gitea-generic-package-version", arguments);
        Assert.Contains("1.2.3", arguments);
        Assert.Contains("--gitea-generic-package-file", arguments);
        Assert.Contains("package.zip", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects ambiguous Gitea source selectors.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMultipleGiteaSourceSelectors()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(4);
        scan.SetGiteaRepository("owner/repo");
        scan.SetGiteaOrganization("org");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("exactly one repository, organization, user, or generic-package selector", error);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects Gitea Actions run IDs without artifact enumeration.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsGiteaActionsRunWithoutArtifacts()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(4);
        scan.SetGiteaRepository("owner/repo");
        scan.SetGiteaActionsRunId("99");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--gitea-actions-run-id requires --gitea-include-actions-artifacts", error);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Bitbucket source scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsBitbucketSourceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(5);
        scan.SetBitbucketRepository("workspace/repo");
        scan.SetBitbucketRef("main");
        scan.SetBitbucketPipelineId("pipeline-123");
        scan.SetBitbucketTokenEnvironmentVariable("PICKET_BITBUCKET_SOURCE_TOKEN");
        scan.SetBitbucketUsernameEnvironmentVariable("PICKET_BITBUCKET_SOURCE_USER");
        scan.SetBitbucketTokenKindByIndex(1);
        scan.SetBitbucketApiEndpoint("https://api.bitbucket.example/2.0");
        scan.SetIncludeBitbucketDownloads(true);
        scan.SetIncludeBitbucketPipelineLogs(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--bitbucket-repository", arguments);
        Assert.Contains("workspace/repo", arguments);
        Assert.Contains("--bitbucket-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--bitbucket-pipeline-id", arguments);
        Assert.Contains("pipeline-123", arguments);
        Assert.Contains("--bitbucket-token-env", arguments);
        Assert.Contains("PICKET_BITBUCKET_SOURCE_TOKEN", arguments);
        Assert.Contains("--bitbucket-username-env", arguments);
        Assert.Contains("PICKET_BITBUCKET_SOURCE_USER", arguments);
        Assert.Contains("--bitbucket-token-kind", arguments);
        Assert.Contains("app-password", arguments);
        Assert.Contains("--bitbucket-api-endpoint", arguments);
        Assert.Contains("https://api.bitbucket.example/2.0", arguments);
        Assert.Contains("--bitbucket-include-downloads", arguments);
        Assert.Contains("--bitbucket-include-pipeline-logs", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Bitbucket workspace scan arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsBitbucketWorkspaceArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(5);
        scan.SetBitbucketWorkspace("workspace");
        scan.SetBitbucketProject("PROJ");
        scan.SetBitbucketTokenEnvironmentVariable("PICKET_BITBUCKET_SOURCE_TOKEN");
        scan.SetIncludeBitbucketDownloads(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--bitbucket-workspace", arguments);
        Assert.Contains("workspace", arguments);
        Assert.Contains("--bitbucket-project", arguments);
        Assert.Contains("PROJ", arguments);
        Assert.Contains("--bitbucket-token-env", arguments);
        Assert.Contains("PICKET_BITBUCKET_SOURCE_TOKEN", arguments);
        Assert.Contains("--bitbucket-include-downloads", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects ambiguous Bitbucket source selectors.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsMultipleBitbucketSourceSelectors()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(5);
        scan.SetBitbucketRepository("workspace/repo");
        scan.SetBitbucketWorkspace("workspace");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("exactly one repository or workspace selector", error);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects Bitbucket pipeline scans without log enumeration.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsBitbucketPipelineWithoutLogs()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(5);
        scan.SetBitbucketRepository("workspace/repo");
        scan.SetBitbucketPipelineId("pipeline-123");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--bitbucket-pipeline-id requires --bitbucket-include-pipeline-logs", error);
    }

    /// <summary>
    /// Verifies that the scan workspace builds Bitbucket Data Center source arguments.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceBuildsBitbucketDataCenterArguments()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(12);
        scan.SetBitbucketDataCenterApiEndpoint("https://bitbucket.example/rest/api/1.0/");
        scan.SetBitbucketDataCenterProject("CORE");
        scan.SetBitbucketDataCenterRepository("picket");
        scan.SetBitbucketDataCenterRef("main");
        scan.SetBitbucketDataCenterTokenEnvironmentVariable("PICKET_BITBUCKET_DC_TOKEN");
        scan.SetBitbucketDataCenterUsernameEnvironmentVariable("PICKET_BITBUCKET_DC_USER");
        scan.SetBitbucketDataCenterTokenKindByIndex(1);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--bitbucket-data-center-api-endpoint", arguments);
        Assert.Contains("https://bitbucket.example/rest/api/1.0/", arguments);
        Assert.Contains("--bitbucket-data-center-project", arguments);
        Assert.Contains("CORE", arguments);
        Assert.Contains("--bitbucket-data-center-repository", arguments);
        Assert.Contains("picket", arguments);
        Assert.Contains("--bitbucket-data-center-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--bitbucket-data-center-token-env", arguments);
        Assert.Contains("PICKET_BITBUCKET_DC_TOKEN", arguments);
        Assert.Contains("--bitbucket-data-center-username-env", arguments);
        Assert.Contains("PICKET_BITBUCKET_DC_USER", arguments);
        Assert.Contains("--bitbucket-data-center-token-kind", arguments);
        Assert.Contains("basic", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that Bitbucket Data Center pull request scans require a repository slug.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsBitbucketDataCenterPullRequestWithoutRepository()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(12);
        scan.SetBitbucketDataCenterApiEndpoint("https://bitbucket.example/rest/api/1.0/");
        scan.SetBitbucketDataCenterProject("CORE");
        scan.SetBitbucketDataCenterPullRequest("7");
        scan.SetBitbucketDataCenterTokenEnvironmentVariable("PICKET_BITBUCKET_DC_TOKEN");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("pull request scans require a repository slug", error);
    }

    /// <summary>
    /// Verifies that Bitbucket Data Center Basic authentication requires a username environment variable.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsBitbucketDataCenterBasicWithoutUsername()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(12);
        scan.SetBitbucketDataCenterApiEndpoint("https://bitbucket.example/rest/api/1.0/");
        scan.SetBitbucketDataCenterProject("CORE");
        scan.SetBitbucketDataCenterTokenEnvironmentVariable("PICKET_BITBUCKET_DC_TOKEN");
        scan.SetBitbucketDataCenterTokenKindByIndex(1);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("Basic authentication requires a username environment variable", error);
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
        scan.SetAzureDevOpsProject("project");
        scan.SetAzureDevOpsRepository("repo");
        scan.SetAzureDevOpsBranch("main");
        scan.SetAzureDevOpsFeed("release");
        scan.SetAzureDevOpsPackage("Picket.Sample");
        scan.SetAzureDevOpsPackageVersion("1.2.3");
        scan.SetAzureDevOpsTokenEnvironmentVariable("AZURE_DEVOPS_TEST_PAT");
        scan.SetAzureDevOpsTokenKindByIndex(1);
        scan.SetAzureDevOpsBuildId("42");
        scan.SetAzureDevOpsReleaseId("7");
        scan.SetIncludeAzureDevOpsWikis(true);
        scan.SetIncludeAzureDevOpsArtifacts(true);
        scan.SetIncludeAzureDevOpsLogs(true);
        scan.SetIncludeAzureDevOpsPackages(true);
        scan.SetIncludeAzureDevOpsReleaseArtifacts(true);
        scan.SetAzureDevOpsMaxArtifactMegabytes("25");
        scan.SetAzureDevOpsMaxLogMegabytes("5");
        scan.SetAzureDevOpsMaxPackageMegabytes("50");
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--azure-devops-endpoint", arguments);
        Assert.Contains("https://dev.azure.com/example", arguments);
        Assert.Contains("--azure-devops-project", arguments);
        Assert.Contains("project", arguments);
        Assert.Contains("--azure-devops-repository", arguments);
        Assert.Contains("repo", arguments);
        Assert.Contains("--azure-devops-branch", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--azure-devops-feed", arguments);
        Assert.Contains("release", arguments);
        Assert.Contains("--azure-devops-package", arguments);
        Assert.Contains("Picket.Sample", arguments);
        Assert.Contains("--azure-devops-package-version", arguments);
        Assert.Contains("1.2.3", arguments);
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
        Assert.Contains("--azure-devops-include-packages", arguments);
        Assert.Contains("--azure-devops-include-release-artifacts", arguments);
        Assert.Contains("--azure-devops-max-artifact-megabytes", arguments);
        Assert.Contains("25", arguments);
        Assert.Contains("--azure-devops-max-log-megabytes", arguments);
        Assert.Contains("--azure-devops-max-package-megabytes", arguments);
        Assert.Contains("50", arguments);
        Assert.Contains("--allow-non-public-source-endpoints", arguments);
        Assert.Contains("--allow-insecure-source-endpoints", arguments);
    }

    /// <summary>
    /// Verifies that the scan workspace rejects Azure DevOps source combinations that the CLI cannot execute.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsInvalidAzureDevOpsSourceCombinations()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(2);
        scan.SetAzureDevOpsOrganization("example");
        scan.SetAzureDevOpsBranch("main");
        scan.SetAzureDevOpsPullRequest("5");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("either a branch or pull request", error);

        scan.SetAzureDevOpsBranch(string.Empty);
        scan.SetIncludeAzureDevOpsWikis(true);

        built = scan.TryBuildArguments(out arguments, out error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("pull request scans cannot include wikis", error);
    }

    /// <summary>
    /// Verifies that remote Azure DevOps byte caps must be positive in the scan workspace.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceRejectsZeroAzureDevOpsRemoteByteCap()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        scan.SetTargetMode(2);
        scan.SetAzureDevOpsOrganization("example");
        scan.SetIncludeAzureDevOpsPackages(true);
        scan.SetAzureDevOpsMaxPackageMegabytes("0");

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--azure-devops-max-package-megabytes requires an integer from 1", error);

        scan.SetAzureDevOpsMaxPackageMegabytes("1");
        scan.SetMaxTargetMegabytes("0");

        built = scan.TryBuildArguments(out arguments, out error);

        Assert.IsFalse(built);
        Assert.IsEmpty(arguments);
        Assert.Contains("--max-target-megabytes requires an integer from 1", error);
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
    /// Verifies that a readable empty report from an incomplete scan replaces the previous report.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceRetainsEmptyReportFromIncompleteScan()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            ReportContent = string.Empty,
            StandardError = "scan incomplete: one or more inputs could not be scanned",
            StandardOutput = string.Empty,
        };
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        File.WriteAllText(reportPath, CreateFakeReportJsonLine());
        scan.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, scan.LastExitCode);
        Assert.IsFalse(scan.LastRunSucceeded);
        Assert.IsTrue(scan.LastRunReportAvailable);
        Assert.AreEqual(0, scan.LastRunReportFindingCount);
        Assert.AreEqual("Scan incomplete: 0 findings; partial report retained", scan.Status);
        Assert.DoesNotContain("findings reported", scan.Status);
        Assert.Contains("scan incomplete", scan.CapturedOutputText);
        Assert.IsEmpty(File.ReadAllText(reportPath));
        Assert.AreEqual(Path.GetFullPath(reportPath), state.Report.Path);
        Assert.IsEmpty(state.Rows);
    }

    /// <summary>
    /// Verifies that findings produced before an incomplete scan are retained and loaded for triage.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceRetainsFindingsReportFromIncompleteScan()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            StandardError = "scan incomplete: one or more inputs could not be scanned",
            StandardOutput = string.Empty,
        };
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        scan.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, scan.LastExitCode);
        Assert.IsFalse(scan.LastRunSucceeded);
        Assert.IsTrue(scan.LastRunReportAvailable);
        Assert.AreEqual(1, scan.LastRunReportFindingCount);
        Assert.AreEqual("Scan incomplete: 1 finding; partial report retained", scan.Status);
        Assert.IsTrue(File.Exists(reportPath));
        Assert.AreEqual(Path.GetFullPath(reportPath), state.Report.Path);
        Assert.HasCount(1, state.Rows);
        Assert.AreEqual("fake-rule", state.Rows[0].RuleId);
    }

    /// <summary>
    /// Verifies that an empty report and a successful scanner exit load as a valid no-findings result.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceLoadsEmptyReportWithSuccessExitCode()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            ExitCode = 0,
            ReportContent = string.Empty,
            StandardError = string.Empty,
        };
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        scan.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, scan.LastExitCode);
        Assert.IsTrue(scan.LastRunSucceeded);
        Assert.AreEqual(0, scan.LastRunReportFindingCount);
        Assert.AreEqual("Scan completed: no findings", scan.Status);
        Assert.AreEqual(Path.GetFullPath(reportPath), state.Report.Path);
        Assert.AreEqual(0, state.Report.Summary.FindingCount);
        Assert.IsEmpty(state.Rows);
    }

    /// <summary>
    /// Verifies that a failed scan cannot reuse or discard a report left by an earlier run.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspacePreservesPreviousReportAfterFailedRun()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            StandardError = "source enumeration failed",
            StandardOutput = string.Empty,
            WriteReport = false,
        };
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        File.WriteAllText(reportPath, CreateFakeReportJsonLine());
        scan.SetReportPath(reportPath);

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(CreateFakeReportJsonLine(), File.ReadAllText(reportPath));
        Assert.IsFalse(scan.LastRunSucceeded);
        Assert.IsNull(scan.LastRunReportFindingCount);
        Assert.Contains("Scan failed: source enumeration failed", scan.Status);
        Assert.AreEqual("report.json", state.Report.Path);
        Assert.HasCount(3, state.Rows);
    }

    /// <summary>
    /// Verifies that a malformed report is not loaded after the scanner exits.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task ScanWorkspaceRejectsMalformedReport()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            ReportContent = "{not-json",
            StandardError = string.Empty,
            StandardOutput = string.Empty,
        };
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        scan.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));

        await state.RunScanAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(scan.LastRunSucceeded);
        Assert.IsNull(scan.LastRunReportFindingCount);
        Assert.Contains("format of the file", scan.Status);
        Assert.DoesNotContain("findings reported", scan.Status);
        Assert.AreEqual("report.json", state.Report.Path);
        Assert.HasCount(3, state.Rows);
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
        string reportPath = Path.Combine(temp.Path, "picket.jsonl");
        File.WriteAllText(reportPath, CreateFakeReportJsonLine());

        state.ScanWorkspace.SetLocalPath(temp.Path);
        state.ScanWorkspace.SetReportPath(reportPath);
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
        Assert.AreEqual(CreateFakeReportJsonLine(), File.ReadAllText(reportPath));
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
        Assert.AreEqual(PicketTuiView.Dashboard, state.CurrentView);
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
        AssertTextContrast(PicketTuiPalette.FocusedRowForeground, PicketTuiPalette.EditorSelectionBackground);
        AssertTextContrast(PicketTuiPalette.YankFlashForeground, PicketTuiPalette.YankFlashBackground);
        AssertUiContrast(PicketTuiPalette.Border, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusedRowBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.EditorSelectionBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.YankFlashBackground, PicketTuiPalette.Background);
    }

    /// <summary>
    /// Verifies that any non-empty NO_COLOR value selects the monochrome terminal palette.
    /// </summary>
    [TestMethod]
    public void PaletteHonorsNoColorConvention()
    {
        Assert.IsTrue(PicketTuiPalette.IsColorEnabled(null));
        Assert.IsTrue(PicketTuiPalette.IsColorEnabled(string.Empty));
        Assert.IsFalse(PicketTuiPalette.IsColorEnabled("1"));
        Assert.IsFalse(PicketTuiPalette.IsColorEnabled("0"));
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
        Assert.AreEqual(PicketTuiPalette.EditorSelectionBackground, theme.Get(EditorTheme.SelectionBackgroundColor));
        Assert.AreEqual(PicketTuiPalette.ScrollbarThumb, theme.Get(TableTheme.ScrollbarThumbColor));
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
            PicketTuiPalette.FocusedRowBackground,
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
    /// Verifies that the full-screen scanner console negotiates mouse tracking with the presentation terminal.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleNegotiatesMouseTracking()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => s.MouseProtocolAnyEnabled && s.MouseEncodingSgrEnabled,
                TimeSpan.FromSeconds(5),
                "mouse tracking modes to be enabled")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(snapshot.MouseProtocolAnyEnabled);
        Assert.IsTrue(snapshot.MouseEncodingSgrEnabled);
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
        Assert.Contains("critical", screenText);
        Assert.Contains("active", screenText);
        Assert.Contains("g s scan", screenText);
        Assert.Contains("y yank", screenText);
        Assert.Contains("? help", screenText);
        Assert.DoesNotContain("Ctrl+R run", screenText);
    }

    /// <summary>
    /// Verifies that the selected finding row uses the Picket table focus color.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleKeepsSelectedRowChromeConsistent()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
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
        int rowY = Array.FindIndex(lines, line =>
            line.Contains("github-token", StringComparison.Ordinal)
            && line.Contains("src/auth.cs:12", StringComparison.Ordinal));
        Assert.AreEqual(0, exitCode);
        Assert.IsGreaterThanOrEqualTo(0, rowY);

        int textX = lines[rowY].IndexOf("github-token", StringComparison.Ordinal);
        int locationX = lines[rowY].IndexOf("src/auth.cs:12", StringComparison.Ordinal);
        int nextRowY = Array.FindIndex(lines, line =>
            line.Contains("github-token", StringComparison.Ordinal)
            && line.Contains("src/auth.cs:18", StringComparison.Ordinal));
        int inactiveRowY = Array.FindIndex(lines, line =>
            line.Contains("aws-key", StringComparison.Ordinal)
            && line.Contains("infra/main.tf:4", StringComparison.Ordinal));
        Assert.IsGreaterThanOrEqualTo(0, textX);
        Assert.IsGreaterThanOrEqualTo(0, locationX);
        Assert.IsGreaterThanOrEqualTo(0, nextRowY);
        Assert.IsGreaterThanOrEqualTo(0, inactiveRowY);

        TerminalCell textCell = snapshot.GetCell(textX, rowY);
        TerminalCell locationCell = snapshot.GetCell(locationX, rowY);
        TerminalCell nextRowCell = snapshot.GetCell(lines[nextRowY].IndexOf("github-token", StringComparison.Ordinal), nextRowY);
        TerminalCell lowSeverityCell = snapshot.GetCell(lines[inactiveRowY].IndexOf("low", StringComparison.Ordinal), inactiveRowY);
        TerminalCell inactiveStateCell = snapshot.GetCell(lines[inactiveRowY].IndexOf("inactive", StringComparison.Ordinal), inactiveRowY);

        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, textCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, textCell.Background);
        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, locationCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, locationCell.Background);
        Assert.AreEqual(PicketTuiPalette.Foreground, nextRowCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.Background, nextRowCell.Background);
        Assert.AreEqual(PicketTuiPalette.InfoForeground, lowSeverityCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.SuccessForeground, inactiveStateCell.Foreground);
    }

    /// <summary>
    /// Verifies that the dashboard exposes triage breakdowns with semantic colors and structured top lists.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bDashboardRendersSemanticTriageSummary()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Severity: 1 critical"), TimeSpan.FromSeconds(5), "dashboard triage summary to render")
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
        int severityY = Array.FindIndex(lines, static line => line.Contains("Severity: 1 critical", StringComparison.Ordinal));
        int validationY = Array.FindIndex(lines, static line => line.Contains("Validation: 1 active", StringComparison.Ordinal));

        Assert.AreEqual(0, exitCode);
        Assert.IsGreaterThanOrEqualTo(0, severityY);
        Assert.IsGreaterThanOrEqualTo(0, validationY);
        Assert.Contains("Top rules", snapshot.GetScreenText());
        Assert.Contains("Top files", snapshot.GetScreenText());
        Assert.AreEqual(
            PicketTuiPalette.ErrorForeground,
            snapshot.GetCell(lines[severityY].IndexOf("critical", StringComparison.Ordinal), severityY).Foreground);
        Assert.AreEqual(
            PicketTuiPalette.ErrorForeground,
            snapshot.GetCell(lines[validationY].IndexOf("active", StringComparison.Ordinal), validationY).Foreground);
    }

    /// <summary>
    /// Verifies that Escape removes the selected rows from both dashboard count tables.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bDashboardEscapeClearsBothSelectedCountRows()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot initialSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => s.ContainsText("github-token") && s.ContainsText("src/auth.cs"),
                TimeSpan.FromSeconds(5),
                "dashboard count rows to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string[] initialLines = initialSnapshot.GetScreenText().Split('\n');
        int ruleY = Array.FindIndex(initialLines, static line => line.Contains("github-token", StringComparison.Ordinal));
        int fileY = Array.FindIndex(initialLines, static line => line.Contains("src/auth.cs", StringComparison.Ordinal));
        Assert.IsGreaterThanOrEqualTo(0, ruleY);
        Assert.IsGreaterThanOrEqualTo(0, fileY);
        int ruleX = initialLines[ruleY].IndexOf("github-token", StringComparison.Ordinal);
        int fileX = initialLines[fileY].IndexOf("src/auth.cs", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, ruleX);
        Assert.IsGreaterThanOrEqualTo(0, fileX);

        Hex1bTerminalSnapshot selectedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .ClickAt(ruleX, ruleY)
            .WaitUntil(
                _ => state.FocusedRuleKey == "github-token",
                TimeSpan.FromSeconds(5),
                "dashboard rule row to be selected")
            .ClickAt(fileX, fileY)
            .WaitUntil(
                s => state.FocusedFileKey == "src/auth.cs"
                    && HasRowColors(
                        s,
                        "github-token",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground)
                    && HasRowColors(
                        s,
                        "src/auth.cs",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground),
                TimeSpan.FromSeconds(5),
                "both dashboard count rows to be selected")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot clearedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.Escape)
            .WaitUntil(
                s => state.SelectedRuleKey is null
                    && state.SelectedFileKey is null
                    && !HasRowColors(
                        s,
                        "github-token",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground)
                    && !HasRowColors(
                        s,
                        "src/auth.cs",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground),
                TimeSpan.FromSeconds(5),
                "both dashboard count rows to clear")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(HasRowColors(
            selectedSnapshot,
            "github-token",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
        Assert.IsTrue(HasRowColors(
            selectedSnapshot,
            "src/auth.cs",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
        Assert.IsFalse(HasRowColors(
            clearedSnapshot,
            "github-token",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
        Assert.IsFalse(HasRowColors(
            clearedSnapshot,
            "src/auth.cs",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
    }

    /// <summary>
    /// Verifies that Escape reliably clears a Files row across rapid input and focus changes.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFilesEscapeReliablyClearsSelectedRow()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Files);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot initialSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => s.ContainsText("src/auth.cs"),
                TimeSpan.FromSeconds(5),
                "file row to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string[] initialLines = initialSnapshot.GetScreenText().Split('\n');
        int fileY = Array.FindIndex(initialLines, static line => line.Contains("src/auth.cs", StringComparison.Ordinal));
        Assert.IsGreaterThanOrEqualTo(0, fileY);
        int fileX = initialLines[fileY].IndexOf("src/auth.cs", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, fileX);

        await new Hex1bTerminalInputSequenceBuilder()
            .ClickAt(fileX, fileY)
            .Key(Hex1bKey.Escape)
            .WaitUntil(
                s => state.SelectedFileKey is null
                    && !HasRowColors(
                        s,
                        "src/auth.cs",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground),
                TimeSpan.FromSeconds(5),
                "rapidly selected file row to clear")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot selectedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.DownArrow)
            .WaitUntil(
                s => state.FocusedFileKey == "infra/main.tf"
                    && state.SelectedFileKey == "infra/main.tf"
                    && HasRowColors(
                        s,
                        "infra/main.tf",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground),
                TimeSpan.FromSeconds(5),
                "keyboard navigation to select the next file row")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot clearedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.Tab)
            .Key(Hex1bKey.Escape)
            .WaitUntil(
                s => state.SelectedFileKey is null
                    && !HasRowColors(
                        s,
                        "infra/main.tf",
                        PicketTuiPalette.FocusedRowForeground,
                        PicketTuiPalette.FocusedRowBackground),
                TimeSpan.FromSeconds(5),
                "file row to clear after focus changes")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(HasRowColors(
            selectedSnapshot,
            "infra/main.tf",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
        Assert.IsFalse(HasRowColors(
            clearedSnapshot,
            "infra/main.tf",
            PicketTuiPalette.FocusedRowForeground,
            PicketTuiPalette.FocusedRowBackground));
    }

    /// <summary>
    /// Verifies that Rules and Files flash the complete focused row after a contextual yank.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bCountTablesFlashYankedRows()
    {
        await AssertCountTableYankFlashAsync(
            PicketTuiView.Rules,
            "github-token",
            TestContext.CancellationToken).ConfigureAwait(false);
        await AssertCountTableYankFlashAsync(
            PicketTuiView.Files,
            "src/auth.cs",
            TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that a wide findings view keeps its details pane readable beside the findings table.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleKeepsWideFindingDetailsReadable()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 140, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Validation: active"), TimeSpan.FromSeconds(5), "finding details to render")
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
        Assert.Contains("Severity", screenText);
        Assert.Contains("Validation", screenText);
        Assert.Contains("Validation: active", screenText);
        Assert.Contains("Commit: 0123456789abcdef", screenText);
        Assert.Contains("Author: Ada Lovelace", screenText);
        Assert.Contains("Fingerprint: fp-auth-1", screenText);
        Assert.Contains("src/auth.cs:12", screenText);
        Assert.DoesNotContain("~", screenText);
    }

    /// <summary>
    /// Verifies that the wide finding-details panel can be resized by dragging its left handle.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleResizesFindingDetailsWithDragHandle()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 140, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot initialSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => FindFindingDetailsHandleColumn(s) >= 0, TimeSpan.FromSeconds(5), "finding details drag handle to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        int initialHandleX = FindFindingDetailsHandleColumn(initialSnapshot);
        int expectedHandleX = initialHandleX - 8;
        Hex1bTerminalSnapshot resizedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Drag(initialHandleX, 18, expectedHandleX, 18)
            .WaitUntil(
                s => FindFindingDetailsHandleColumn(s) == expectedHandleX,
                TimeSpan.FromSeconds(5),
                "finding details panel to resize")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsGreaterThanOrEqualTo(0, initialHandleX);
        Assert.AreEqual(expectedHandleX, FindFindingDetailsHandleColumn(resizedSnapshot));
    }

    /// <summary>
    /// Verifies that the scanner console remains useful in a narrow terminal and exposes Vim-style navigation through Hex1b input.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleHandlesNarrowTerminalAndKeyboardNavigation()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 80, height: 24);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot findingsSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("src/auth.cs:12"), TimeSpan.FromSeconds(5), "findings to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
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
        string findingsText = findingsSnapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("github-token", findingsText);
        Assert.Contains("src/auth.cs:12", findingsText);
        Assert.Contains("Severity", findingsText);
        Assert.Contains("Run scan", screenText);
        Assert.Contains("Ctrl+R run", screenText);
        Assert.Contains("g f findings", screenText);
        Assert.DoesNotContain("Use g f to review", screenText);
        Assert.Contains("Source", screenText);
        Assert.Contains("Not run", screenText);
        Assert.DoesNotContain("Latest results", screenText);
        Assert.DoesNotContain("g s scan", screenText);
    }

    /// <summary>
    /// Verifies that Vim-style navigation and yank commands work while the Dashboard editor has focus.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleHandlesCommandsFromDashboardEditor()
    {
        PicketTuiState state = CreateState();
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot yankSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Top rules"), TimeSpan.FromSeconds(5), "dashboard to render")
            .Key(Hex1bKey.Y)
            .WaitUntil(s => s.ContainsText("Yanked"), TimeSpan.FromSeconds(5), "dashboard content to be yanked")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Hex1bTerminalSnapshot findingsSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.G)
            .Key(Hex1bKey.F)
            .WaitUntil(s => s.ContainsText("src/auth.cs:12"), TimeSpan.FromSeconds(5), "findings to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.Contains("Yanked", yankSnapshot.GetScreenText());
        Assert.Contains("github-token", findingsSnapshot.GetScreenText());
        Assert.AreEqual(PicketTuiView.Findings, state.CurrentView);
    }

    /// <summary>
    /// Verifies that Tab and Shift+Tab traverse each page's controls in opposite visual order.
    /// </summary>
    [TestMethod]
    [DataRow(1, 2, "ButtonNode,TabPanelNode,EditorNode,TableNode`1,TableNode`1")]
    [DataRow(2, 1, "TabPanelNode,ButtonNode,ToggleSwitchNode,ToggleSwitchNode,ToggleSwitchNode,TextBoxNode,SplitterNode")]
    [DataRow(3, 3, "ButtonNode,TabPanelNode,TextBoxNode,TableNode`1,DragBarPanelNode,EditorNode")]
    [DataRow(4, 2, "ButtonNode,TabPanelNode,TableNode`1")]
    [DataRow(5, 2, "ButtonNode,TabPanelNode,TableNode`1")]
    [DataRow(6, 2, "ButtonNode,TabPanelNode,TextBoxNode,EditorNode")]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleTraversesEachTabInLogicalOrder(
        int tabNumber,
        int initialFocusIndex,
        string expectedFocusOrder)
    {
        PicketTuiState state = CreateState();
        state.SetViewByTabNumber(tabNumber);
        Hex1bApp? app = null;
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(
            state,
            width: 140,
            height: 38,
            createdApp => app = createdApp);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                _ => app is not null
                    && app.Focusables.Count > initialFocusIndex
                    && ReferenceEquals(app.FocusedNode, app.Focusables[initialFocusIndex]),
                TimeSpan.FromSeconds(5),
                "initial page control to receive focus")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Hex1bNode[] focusables = [.. app!.Focusables];
        string[] expectedNodeNames = expectedFocusOrder.Split(',');
        Assert.HasCount(expectedNodeNames.Length, focusables);
        for (int index = 0; index < expectedNodeNames.Length; index++)
        {
            Assert.AreEqual(expectedNodeNames[index], focusables[index].GetType().Name);
        }

        var traversal = new Hex1bTerminalInputSequenceBuilder();
        for (int offset = 1; offset <= focusables.Length; offset++)
        {
            int expectedIndex = (initialFocusIndex + offset) % focusables.Length;
            Hex1bNode expectedNode = focusables[expectedIndex];
            traversal
                .Key(Hex1bKey.Tab)
                .WaitUntil(
                    _ => ReferenceEquals(app.FocusedNode, expectedNode),
                    TimeSpan.FromSeconds(5),
                    "Tab to move to the next page control");
        }

        for (int offset = 1; offset <= focusables.Length; offset++)
        {
            int expectedIndex = (initialFocusIndex - offset + focusables.Length) % focusables.Length;
            Hex1bNode expectedNode = focusables[expectedIndex];
            traversal
                .Shift().Key(Hex1bKey.Tab)
                .WaitUntil(
                    _ => ReferenceEquals(app.FocusedNode, expectedNode),
                    TimeSpan.FromSeconds(5),
                    "Shift+Tab to move to the previous page control");
        }

        await traversal
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(ReferenceEquals(focusables[initialFocusIndex], app.FocusedNode));
    }

    /// <summary>
    /// Verifies that number keys select tabs without preventing numeric text entry.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleUsesNumberedTabsOutsideTextEntry()
    {
        PicketTuiState state = CreateState();
        Hex1bApp? app = null;
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(
            state,
            width: 140,
            height: 38,
            createdApp => app = createdApp);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Dashboard"), TimeSpan.FromSeconds(5), "tabs to render")
            .Key(Hex1bKey.D2)
            .WaitUntil(_ => state.CurrentView == PicketTuiView.Scan, TimeSpan.FromSeconds(5), "Scan tab to open")
            .Key(Hex1bKey.D3)
            .WaitUntil(_ => state.CurrentView == PicketTuiView.Findings, TimeSpan.FromSeconds(5), "Findings tab to open")
            .Key(Hex1bKey.D4)
            .WaitUntil(_ => state.CurrentView == PicketTuiView.Rules, TimeSpan.FromSeconds(5), "Rules tab to open")
            .Key(Hex1bKey.D5)
            .WaitUntil(_ => state.CurrentView == PicketTuiView.Files, TimeSpan.FromSeconds(5), "Files tab to open")
            .Key(Hex1bKey.D6)
            .WaitUntil(
                _ => state.CurrentView == PicketTuiView.Logs
                    && string.Equals(app?.FocusedNode?.GetType().Name, "TextBoxNode", StringComparison.Ordinal),
                TimeSpan.FromSeconds(5),
                "Logs search to enter text-entry mode")
            .Key(Hex1bKey.D1)
            .WaitUntil(
                _ => state.CurrentView == PicketTuiView.Logs && state.LogSearchText == "1",
                TimeSpan.FromSeconds(5),
                "numeric search text to be entered")
            .Key(Hex1bKey.Tab)
            .WaitUntil(
                _ => string.Equals(app?.FocusedNode?.GetType().Name, "EditorNode", StringComparison.Ordinal),
                TimeSpan.FromSeconds(5),
                "Logs output to receive focus")
            .Key(Hex1bKey.D1)
            .WaitUntil(_ => state.CurrentView == PicketTuiView.Dashboard, TimeSpan.FromSeconds(5), "Dashboard tab to open")
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.AreEqual(PicketTuiView.Dashboard, state.CurrentView);
        Assert.AreEqual("1", state.LogSearchText);
    }

    /// <summary>
    /// Verifies that Escape leaves the Logs search field and returns focus to scanner output.
    /// </summary>
    [TestMethod]
    [DataRow("")]
    [DataRow("finding")]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bLogsEscapeLeavesSearchField(string searchText)
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Logs);
        state.SetLogSearchText(searchText);
        Hex1bApp? app = null;
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(
            state,
            width: 120,
            height: 32,
            createdApp => app = createdApp);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => app?.FocusedNode is TextBoxNode
                    && s.ContainsText("Dashboard")
                    && s.ContainsText("Logs"),
                TimeSpan.FromSeconds(5),
                "Logs view to render with search focus")
            .Key(Hex1bKey.Escape)
            .WaitUntil(
                s => app?.FocusedNode is EditorNode
                    && s.ContainsText("Dashboard")
                    && s.ContainsText("Logs"),
                TimeSpan.FromSeconds(5),
                "Logs view to render with output focus")
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
        Assert.IsEmpty(state.LogSearchText);
        Assert.DoesNotContain("1 Dashboard", screenText);
        Assert.DoesNotContain("2 Scan", screenText);
        Assert.DoesNotContain("3 Findings", screenText);
        Assert.DoesNotContain("4 Rules", screenText);
        Assert.DoesNotContain("5 Files", screenText);
        Assert.DoesNotContain("6 Logs", screenText);
        Assert.Contains("Dashboard", screenText);
        Assert.Contains("Logs", screenText);
    }

    /// <summary>
    /// Verifies that Escape clears a focused read-only editor selection without moving its cursor.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bReadOnlyEditorEscapeClearsSelectionWithoutMovingCursor()
    {
        PicketTuiState state = CreateState();
        EditorState editorState = state.GetDashboardEditorState();
        editorState.SelectAll();
        DocumentOffset expectedCursorPosition = editorState.Cursor.Position;
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Report"), TimeSpan.FromSeconds(5), "dashboard selection to render")
            .Key(Hex1bKey.Escape)
            .WaitUntil(_ => !editorState.Cursor.HasSelection, TimeSpan.FromSeconds(5), "dashboard selection to clear")
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);

        Assert.AreEqual(0, exitCode);
        Assert.IsFalse(editorState.Cursor.HasSelection);
        Assert.AreEqual(expectedCursorPosition, editorState.Cursor.Position);
    }

    /// <summary>
    /// Verifies that the generated keyboard reference exposes global, navigation, and contextual bindings.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleShowsGeneratedKeyboardHelp()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot helpSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("? help"), TimeSpan.FromSeconds(5), "help hint to render")
            .Key(Hex1bKey.F1)
            .WaitUntil(s => s.ContainsText("Keyboard help"), TimeSpan.FromSeconds(5), "keyboard help to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Key(Hex1bKey.Escape)
            .WaitUntil(s => s.ContainsText("src/auth.cs:12"), TimeSpan.FromSeconds(5), "findings to regain focus")
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string helpText = helpSnapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("Global", helpText);
        Assert.Contains("Navigation", helpText);
        Assert.Contains("g b", helpText);
        Assert.Contains("Files", helpText);
        Assert.Contains("j", helpText);
        Assert.Contains("Move finding", helpText);
        Assert.Contains("Esc closes this reference.", helpText);
    }

    /// <summary>
    /// Verifies that returning to the findings tab gives keyboard focus back to the table.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleFocusesFindingsTableAfterTabSwitch()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Findings);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Findings"), TimeSpan.FromSeconds(5), "findings to render")
            .Key(Hex1bKey.G)
            .Key(Hex1bKey.S)
            .WaitUntil(s => s.ContainsText("Source"), TimeSpan.FromSeconds(5), "scan workspace to render")
            .Key(Hex1bKey.G)
            .Key(Hex1bKey.F)
            .WaitUntil(s => s.ContainsText("src/auth.cs:12"), TimeSpan.FromSeconds(5), "findings table to render")
            .Key(Hex1bKey.DownArrow)
            .WaitUntil(_ => state.FocusedFinding?.Fingerprint == "fp-auth-2", TimeSpan.FromSeconds(5), "second finding to receive focus")
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
        Assert.Contains("src/auth.cs:18", screenText);
        Assert.AreEqual("18", state.FocusedFinding?.Line);
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
            .WaitUntil(s => s.ContainsText("Ready to scan"), TimeSpan.FromSeconds(5), "scan workspace to render")
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
        Assert.Contains("Ready to scan", screenText);
        Assert.Contains("Target", screenText);
        Assert.Contains("Kind", screenText);
        Assert.Contains("Source host", screenText);
        Assert.Contains("Object store", screenText);
        Assert.Contains("Source", screenText);
        Assert.Contains("Output", screenText);
        Assert.Contains("Validation", screenText);
        Assert.Contains("Limits", screenText);
        Assert.Contains("Path", screenText);
        Assert.Contains("Run scan", screenText);
        Assert.Contains("Ctrl+R run", screenText);
        Assert.Contains("g f findings", screenText);
        Assert.DoesNotContain("Use g f to review", screenText);
        Assert.Contains("Not run", screenText);
        Assert.DoesNotContain("Latest results", screenText);
        Assert.DoesNotContain("src/auth.cs", screenText);
        Assert.DoesNotContain("g s scan", screenText);
    }

    /// <summary>
    /// Verifies that an active scan has animated progress and a textual running state.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleShowsRunningScanProgress()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            WaitForCancellation = true,
        };
        PicketTuiState state = CreateState(executor);
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));
        state.StartScanInBackground(static () => { }, TestContext.CancellationToken);
        await executor.Started.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Running"), TimeSpan.FromSeconds(5), "running scan status to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        state.CancelScan(static () => { });
        await WaitUntilAsync(() => !state.ScanWorkspace.IsRunning, TestContext.CancellationToken).ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string screenText = snapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("Running", screenText);
        Assert.Contains("Ctrl+C cancel", screenText);
        Assert.IsTrue(ContainsSpinnerFrame(snapshot));
    }

    /// <summary>
    /// Verifies that the scan workspace output section renders report options.
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
        Assert.Contains("Report", screenText);
        Assert.Contains("Profile", screenText);
        Assert.Contains("Config", screenText);
        Assert.Contains("Ignore", screenText);
        Assert.DoesNotContain("Checkpoint", screenText);
    }

    /// <summary>
    /// Verifies that source-provider output settings render checkpoint controls.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersCheckpointControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode((int)PicketTuiScanTargetMode.DockerArchive);
        state.ScanWorkspace.SetDockerArchivePath("images/app.tar");
        state.ScanWorkspace.SetScanSettingPageByIndex(1);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 34);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Checkpoint"), TimeSpan.FromSeconds(5), "checkpoint controls to render")
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
        Assert.Contains("Checkpoint", screenText);
        Assert.Contains("Reset state", screenText);
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
        Assert.Contains("Result value", screenText);
        Assert.Contains("Verify", screenText);
        Assert.Contains("Live request budget", screenText);
        Assert.Contains("Per provider", screenText);
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
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 38);

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
        Assert.Contains("Scope", screenText);
        Assert.Contains("Repository", screenText);
        Assert.Contains("Repo owner/name", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Repo type", screenText);
        Assert.Contains("Issue state", screenText);
        Assert.Contains("Endpoint", screenText);
        Assert.Contains("Actions", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
        Assert.Contains("Organization", PicketTuiScanWorkspace.GitHubScopeLabels);
        Assert.Contains("My gists", PicketTuiScanWorkspace.GitHubScopeLabels);
        Assert.Contains("User gists", PicketTuiScanWorkspace.GitHubScopeLabels);
        Assert.Contains("forks", PicketTuiScanWorkspace.GitHubRepositoryTypes);
        Assert.Contains("sources", PicketTuiScanWorkspace.GitHubRepositoryTypes);
        Assert.Contains("owner", PicketTuiScanWorkspace.GitHubRepositoryTypes);
        Assert.Contains("member", PicketTuiScanWorkspace.GitHubRepositoryTypes);
    }

    /// <summary>
    /// Verifies that GitLab source scan controls expose issue and release scopes.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersGitLabIssueAndReleaseControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode(3);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 140, height: 42);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Release assets"), TimeSpan.FromSeconds(5), "GitLab controls to render")
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
        Assert.Contains("Issues", screenText);
        Assert.Contains("Issue state", screenText);
        Assert.Contains("Releases", screenText);
        Assert.Contains("Release assets", screenText);
        Assert.Contains("opened", PicketTuiScanWorkspace.GitLabIssueStates);
        Assert.Contains("closed", PicketTuiScanWorkspace.GitLabIssueStates);
    }

    /// <summary>
    /// Verifies that Hugging Face source controls expose resource, revision, discussion, and endpoint settings.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersHuggingFaceSourceControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode((int)PicketTuiScanTargetMode.HuggingFace);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 140, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Discussions"), TimeSpan.FromSeconds(5), "Hugging Face controls to render")
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
        Assert.Contains("Hugging Face", screenText);
        Assert.Contains("Resource", screenText);
        Assert.Contains("Model", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Revision", screenText);
        Assert.Contains("Pull request", screenText);
        Assert.Contains("Discussions", screenText);
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
        Assert.Contains("Feed", screenText);
        Assert.Contains("Package", screenText);
        Assert.Contains("Version", screenText);
        Assert.Contains("Artifact MB", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
    }

    /// <summary>
    /// Verifies that Bitbucket Data Center source controls expose the required server, scope, and credential fields.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersBitbucketDataCenterSourceControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode(12);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 150, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Project key"), TimeSpan.FromSeconds(5), "Bitbucket Data Center controls to render")
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
        bool providerRowVisible = screenText
            .Split(Environment.NewLine)
            .Any(static line => line.Contains("Provider", StringComparison.Ordinal)
                && line.Contains("Bitbucket Data Center", StringComparison.Ordinal));

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(providerRowVisible);
        Assert.Contains("Bitbucket Data Center", screenText);
        Assert.Contains("API endpoint", screenText);
        Assert.Contains("Project key", screenText);
        Assert.Contains("Repository", screenText);
        Assert.Contains("Pull request", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Username env", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
    }

    /// <summary>
    /// Verifies that remote container-registry controls expose image, platform, and credential settings.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRendersContainerRegistryControls()
    {
        PicketTuiState state = CreateState();
        state.SetView(PicketTuiView.Scan);
        state.ScanWorkspace.SetTargetMode((int)PicketTuiScanTargetMode.RegistryImage);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 160, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Auth endpoint"), TimeSpan.FromSeconds(5), "container registry controls to render")
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
        Assert.Contains("Registry", screenText);
        Assert.Contains("Image", screenText);
        Assert.Contains("Endpoint", screenText);
        Assert.Contains("Auth endpoint", screenText);
        Assert.Contains("Platform", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Username env", screenText);
        Assert.Contains("Password env", screenText);
        Assert.Contains("Non-public", screenText);
        Assert.Contains("HTTP", screenText);
    }

    /// <summary>
    /// Verifies that repository and token values entered through Hex1b produce one GitHub repository target.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleBuildsGitHubRepositoryScanFromEnteredFields()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor();
        PicketTuiState state = CreateState(executor);
        PicketTuiScanWorkspace scan = state.ScanWorkspace;
        state.SetView(PicketTuiView.Scan);
        scan.SetTargetMode((int)PicketTuiScanTargetMode.GitHub);
        scan.SetGitHubOrganization("retained-organization");
        scan.SetGitHubScopeByIndex((int)PicketTuiGitHubScope.Repository);
        scan.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 140, height: 38);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot initialSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(s => s.ContainsText("Repo owner/name"), TimeSpan.FromSeconds(5), "GitHub repository field to render")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        (int repositoryLine, int repositoryColumn) = initialSnapshot.FindText("Repo owner/name").Single();
        Hex1bTerminalSnapshot repositorySnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .ClickAt(repositoryColumn + 18, repositoryLine)
            .Type("willibrandon/picket")
            .WaitUntil(_ => scan.GitHubRepository == "willibrandon/picket", TimeSpan.FromSeconds(5), "repository input to update")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        (int tokenLine, int tokenColumn) = repositorySnapshot.FindText("Token env").Single();
        Hex1bTerminalSnapshot completedSnapshot = await new Hex1bTerminalInputSequenceBuilder()
            .ClickAt(tokenColumn + 18, tokenLine)
            .Type("PICKET_GITHUB_SECRET_SCANNING_PAT")
            .WaitUntil(_ => scan.GitHubTokenEnvironmentVariable == "PICKET_GITHUB_SECRET_SCANNING_PAT", TimeSpan.FromSeconds(5), "token environment input to update")
            .Ctrl().Key(Hex1bKey.R)
            .WaitUntil(s => s.ContainsText("Scan completed: findings reported"), TimeSpan.FromSeconds(5), "GitHub scan to complete")
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, TestContext.CancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string screenText = completedSnapshot.GetScreenText();

        Assert.AreEqual(0, exitCode);
        Assert.Contains("GitHub willibrandon/picket", screenText);
        Assert.Contains("--github-repository", executor.CapturedArguments);
        Assert.Contains("willibrandon/picket", executor.CapturedArguments);
        Assert.Contains("--github-token-env", executor.CapturedArguments);
        Assert.Contains("PICKET_GITHUB_SECRET_SCANNING_PAT", executor.CapturedArguments);
        Assert.DoesNotContain("--github-organization", executor.CapturedArguments);
    }

    /// <summary>
    /// Verifies that the full-screen console presents an empty exit-one report as a retained partial result.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleRetainsEmptyPartialReport()
    {
        using TempDirectory temp = TempDirectory.Create();
        var executor = new PicketTuiFakeScanExecutor
        {
            ReportContent = string.Empty,
            StandardError = "GitHub request failed",
            StandardOutput = string.Empty,
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
            .WaitUntil(s => s.ContainsText("Scan incomplete: 0 findings"), TimeSpan.FromSeconds(5), "partial scan to render")
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
        Assert.Contains("Scan incomplete: 0 findings", screenText);
        Assert.Contains("partial report retained", screenText);
        Assert.DoesNotContain("Scan completed: findings reported", screenText);
        Assert.IsEmpty(state.Rows);
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
        Assert.Contains("Completed ", screenText);
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
        using TempDirectory temp = TempDirectory.Create();
        PicketTuiState state = CreateState(new PicketTuiProcessScanExecutor("picket-missing-for-test"));
        state.ScanWorkspace.SetReportPath(Path.Combine(temp.Path, "picket.jsonl"));

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
        CliResult result = await RunTuiCliAsync(["--help"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket-tui [<report>] [options]", result.Stdout);
        Assert.Contains("--flow", result.Stdout);
        Assert.Contains("--scan", result.Stdout);
        Assert.Contains("-t, --tab <1-6>", result.Stdout);
        Assert.Contains("--version", result.Stdout);
    }

    /// <summary>
    /// Verifies that package validators can invoke the companion without arguments and without an interactive terminal.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompanionWithoutArgumentsPrintsHelpWhenTerminalIsRedirected()
    {
        CliResult result = await RunTuiCliAsync([], TestContext.CancellationToken).ConfigureAwait(false);
        string output = string.Concat(result.Stdout, result.Stderr);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket-tui [<report>] [options]", result.Stdout);
        Assert.DoesNotContain("Unhandled exception", output);
        Assert.DoesNotContain("WindowsConsoleDriver", output);
    }

    /// <summary>
    /// Verifies that the companion rejects startup tab numbers outside the visible range.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompanionRejectsStartupTabOutsideVisibleRange()
    {
        CliResult result = await RunTuiCliAsync(["--tab", "7"], TestContext.CancellationToken).ConfigureAwait(false);
        string output = string.Concat(result.Stdout, result.Stderr);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("--tab requires a value from 1 through 6.", output);
        Assert.DoesNotContain("Unhandled exception", output);
    }

    /// <summary>
    /// Verifies that a missing report path reports a CLI error instead of an unhandled exception.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task CompanionReportsMissingReportWithoutStackTrace()
    {
        CliResult result = await RunTuiCliAsync(["missing-report.json"], TestContext.CancellationToken).ConfigureAwait(false);
        string output = string.Concat(result.Stdout, result.Stderr);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("report not found: missing-report.json", output);
        Assert.DoesNotContain("Unhandled exception", output);
        Assert.DoesNotContain(" at ", output);
    }

    private static PicketTuiState CreateState(
        IPicketTuiScanExecutor? executor = null,
        IPicketTuiFileLauncher? fileLauncher = null)
    {
        var summary = new ReportSummary(
            "picket-json",
            [
                new ReportFindingSummary(
                    "github-token",
                    "src/auth.cs",
                    12,
                    "fp-auth-1",
                    7,
                    randomnessScore: 0.902542,
                    randomnessClassification: "likely-random",
                    randomnessModel: "picket-random-v1",
                    severity: "critical",
                    confidence: "high",
                    validationState: "active",
                    commit: "0123456789abcdef",
                    author: "Ada Lovelace"),
                new ReportFindingSummary(
                    "github-token",
                    "src/auth.cs",
                    18,
                    "fp-auth-2",
                    8,
                    severity: "medium",
                    confidence: "medium",
                    validationState: "unknown"),
                new ReportFindingSummary(
                    "aws-key",
                    "infra/main.tf",
                    4,
                    "fp-infra-1",
                    3,
                    severity: "low",
                    confidence: "high",
                    validationState: "inactive"),
            ]);

        return new PicketTuiState(new PicketTuiReport("report.json", summary, DateTimeOffset.UnixEpoch), executor, fileLauncher);
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

    private static Hex1bTerminal CreateHeadlessTerminal(
        PicketTuiState state,
        int width,
        int height,
        Action<Hex1bApp>? appCreated = null)
    {
        return PicketTuiRunner.CreateTerminalBuilder(state, appCreated)
            .WithHeadless(TerminalCapabilities.Minimal with { SupportsMouse = true })
            .WithDimensions(width, height)
            .Build();
    }

    private static async Task AssertCountTableYankFlashAsync(
        PicketTuiView view,
        string rowText,
        CancellationToken cancellationToken)
    {
        PicketTuiState state = CreateState();
        state.SetView(view);
        if (view == PicketTuiView.Rules)
        {
            state.FocusRule(rowText);
        }
        else
        {
            state.FocusFile(rowText);
        }

        using var flashCancellation = new CancellationTokenSource();
        flashCancellation.Cancel();
        state.ShowYankNotification(
            state.GetYankText(),
            static () => { },
            flashCancellation.Token);
        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using Hex1bTerminal terminal = CreateHeadlessTerminal(state, width: 120, height: 32);

        Task<int> runTask = terminal.RunAsync(cancellationTokenSource.Token);
        Hex1bTerminalSnapshot snapshot = await new Hex1bTerminalInputSequenceBuilder()
            .WaitUntil(
                s => HasRowColors(
                    s,
                    rowText,
                    PicketTuiPalette.YankFlashForeground,
                    PicketTuiPalette.YankFlashBackground),
                TimeSpan.FromSeconds(5),
                "count row yank flash to render")
            .Build()
            .ApplyAsync(terminal, cancellationToken)
            .ConfigureAwait(false);
        await new Hex1bTerminalInputSequenceBuilder()
            .Ctrl().Key(Hex1bKey.Q)
            .Build()
            .ApplyAsync(terminal, cancellationToken)
            .ConfigureAwait(false);

        int exitCode = await runTask.ConfigureAwait(false);
        string[] lines = snapshot.GetScreenText().Split('\n');
        int rowY = Array.FindIndex(lines, line => line.Contains(rowText, StringComparison.Ordinal));
        Assert.AreEqual(0, exitCode);
        Assert.IsGreaterThanOrEqualTo(0, rowY);
        int rowX = lines[rowY].IndexOf(rowText, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, rowX);
        Assert.AreEqual(PicketTuiPalette.YankFlashBackground, snapshot.GetCell(rowX, rowY).Background);
        Assert.AreEqual(PicketTuiPalette.YankFlashForeground, snapshot.GetCell(rowX, rowY).Foreground);
    }

    private static bool HasRowColors(
        Hex1bTerminalSnapshot snapshot,
        string rowText,
        Hex1bColor foreground,
        Hex1bColor background)
    {
        string[] lines = snapshot.GetScreenText().Split('\n');
        int rowY = Array.FindIndex(lines, line => line.Contains(rowText, StringComparison.Ordinal));
        if (rowY < 0)
        {
            return false;
        }

        int rowX = lines[rowY].IndexOf(rowText, StringComparison.Ordinal);
        TerminalCell cell = snapshot.GetCell(rowX, rowY);
        return cell.Foreground.Equals(foreground) && cell.Background.Equals(background);
    }

    private static int FindFindingDetailsHandleColumn(Hex1bTerminalSnapshot snapshot)
    {
        string[] lines = snapshot.GetScreenText().Split('\n');
        int detailsLine = Array.FindIndex(lines, static line => line.Contains("Rule: github-token", StringComparison.Ordinal));
        if (detailsLine < 0)
        {
            return -1;
        }

        int detailsText = lines[detailsLine].IndexOf("Rule: github-token", StringComparison.Ordinal);
        return lines[detailsLine].LastIndexOf('│', detailsText - 1);
    }

    private static async Task WaitUntilAsync(Func<bool> predicate, CancellationToken cancellationToken)
    {
        while (!predicate())
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
        }
    }

    private static bool ContainsSpinnerFrame(Hex1bTerminalSnapshot snapshot)
    {
        for (int y = 0; y < snapshot.Height; y++)
        {
            for (int x = 0; x < snapshot.Width; x++)
            {
                if (s_spinnerFrames.Contains(snapshot.GetCell(x, y).Character))
                {
                    return true;
                }
            }
        }

        return false;
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

    private static async Task<CliResult> RunTuiCliAsync(string[] arguments, CancellationToken cancellationToken)
    {
        string repositoryRoot = FindRepositoryRoot();
        string configuration = GetBuildConfiguration();
        List<string> runArguments =
        [
            "run",
            "--project",
            Path.Combine("src", "Picket.Tui.Cli", "Picket.Tui.Cli.csproj"),
            "--no-build",
            "--configuration",
            configuration,
            "--",
        ];
        runArguments.AddRange(arguments);

        return await RunProcessAsync("dotnet", [.. runArguments], repositoryRoot, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunProcessAsync(
        string fileName,
        string[] arguments,
        string workingDirectory,
        CancellationToken cancellationToken)
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
        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
    }

    private static string GetBuildConfiguration()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory.Parent is not null)
        {
            if (string.Equals(directory.Parent.Name, "bin", StringComparison.OrdinalIgnoreCase))
            {
                return directory.Name;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not determine the active build configuration.");
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
