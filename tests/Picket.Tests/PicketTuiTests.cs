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
    private static readonly Lock s_editorEnvironmentLock = new();

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
    /// Verifies that selected read-only editor text is yankable and gets an editor-local flash.
    /// </summary>
    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public async Task StateYanksSelectedReadOnlyEditorTextWithFlash()
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

        Assert.IsNotNull(provider.HighlightRange);
        Assert.IsFalse(state.YankFlashRow);
        Assert.IsNotNull(state.YankNotification);

        while (provider.HighlightRange is not null)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(25), TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsTrue(invalidated.IsSet);
        Assert.IsNull(provider.HighlightRange);
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
    /// Verifies that each top-level tab publishes a deterministic primary focus target.
    /// </summary>
    [TestMethod]
    public void StateQueuesExpectedFocusTargetForEachTab()
    {
        PicketTuiState state = CreateState();

        Assert.AreEqual(PicketTuiFocusTarget.FindingsTable, state.ConsumePendingFocusTarget());
        Assert.IsNull(state.ConsumePendingFocusTarget());

        state.SetView(PicketTuiView.Dashboard);
        Assert.AreEqual(PicketTuiFocusTarget.DashboardEditor, state.ConsumePendingFocusTarget());

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
    /// Verifies that the scan workspace groups targets so the TUI selector stays readable.
    /// </summary>
    [TestMethod]
    public void ScanWorkspaceGroupsTargetModesByCategory()
    {
        PicketTuiState state = CreateState();
        PicketTuiScanWorkspace scan = state.ScanWorkspace;

        Assert.AreEqual(PicketTuiScanTargetCategory.Local, scan.TargetCategory);
        Assert.HasCount(4, PicketTuiScanWorkspace.TargetCategoryLabels);
        Assert.HasCount(1, scan.ActiveTargetModeLabels);

        scan.SetTargetCategoryByIndex((int)PicketTuiScanTargetCategory.ObjectStore);

        Assert.AreEqual(PicketTuiScanTargetMode.S3, scan.TargetMode);
        Assert.AreEqual(0, scan.TargetModeIndex);
        Assert.HasCount(3, scan.ActiveTargetModeLabels);
        Assert.Contains("Azure Blob", scan.ActiveTargetModeLabels);

        scan.SetTargetModeByCategoryIndex(2);

        Assert.AreEqual(PicketTuiScanTargetMode.AzureBlob, scan.TargetMode);
        Assert.AreEqual(PicketTuiScanTargetCategory.ObjectStore, scan.TargetCategory);
        Assert.AreEqual(2, scan.TargetModeIndex);

        scan.SetTargetCategoryByIndex((int)PicketTuiScanTargetCategory.Archive);

        Assert.AreEqual(PicketTuiScanTargetMode.DockerArchive, scan.TargetMode);
        Assert.HasCount(2, scan.ActiveTargetModeLabels);
        Assert.Contains("OCI", scan.ActiveTargetModeLabels);
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
        scan.SetGitLabMergeRequest("42");
        scan.SetGitLabPipelineId("123");
        scan.SetGitLabTokenEnvironmentVariable("PICKET_GITLAB_SOURCE_TOKEN");
        scan.SetGitLabApiEndpoint("https://gitlab.example/api/v4");
        scan.SetIncludeGitLabSnippets(true);
        scan.SetIncludeGitLabJobArtifacts(true);
        scan.SetIncludeGitLabJobLogs(true);
        scan.SetIncludeGitLabPackages(true);
        scan.SetAllowNonPublicSourceEndpoints(true);
        scan.SetAllowInsecureSourceEndpoints(true);

        bool built = scan.TryBuildArguments(out List<string> arguments, out string error);

        Assert.IsTrue(built, error);
        Assert.Contains("--gitlab-project", arguments);
        Assert.Contains("group/project", arguments);
        Assert.Contains("--gitlab-ref", arguments);
        Assert.Contains("main", arguments);
        Assert.Contains("--gitlab-merge-request", arguments);
        Assert.Contains("42", arguments);
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
        AssertTextContrast(PicketTuiPalette.Foreground, PicketTuiPalette.EditorSelectionBackground);
        AssertTextContrast(PicketTuiPalette.YankFlashForeground, PicketTuiPalette.YankFlashBackground);
        AssertUiContrast(PicketTuiPalette.Border, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.FocusedRowBackground, PicketTuiPalette.Background);
        AssertUiContrast(PicketTuiPalette.EditorSelectionBackground, PicketTuiPalette.Background);
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
        Assert.AreEqual(PicketTuiPalette.EditorSelectionBackground, theme.Get(EditorTheme.SelectionBackgroundColor));
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
    /// Verifies that the selected finding row uses the Picket table focus color.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleKeepsSelectedRowChromeConsistent()
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
        Assert.IsGreaterThanOrEqualTo(0, textX);
        Assert.IsGreaterThanOrEqualTo(0, locationX);
        Assert.IsGreaterThanOrEqualTo(0, nextRowY);

        TerminalCell textCell = snapshot.GetCell(textX, rowY);
        TerminalCell locationCell = snapshot.GetCell(locationX, rowY);
        TerminalCell nextRowCell = snapshot.GetCell(lines[nextRowY].IndexOf("github-token", StringComparison.Ordinal), nextRowY);

        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, textCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, textCell.Background);
        Assert.AreEqual(PicketTuiPalette.FocusedRowForeground, locationCell.Foreground);
        Assert.AreEqual(PicketTuiPalette.FocusedRowBackground, locationCell.Background);
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
        Assert.Contains("Not run", screenText);
        Assert.DoesNotContain("Latest results", screenText);
        Assert.DoesNotContain("g s scan", screenText);
    }

    /// <summary>
    /// Verifies that returning to the findings tab gives keyboard focus back to the table.
    /// </summary>
    [TestMethod]
    [Timeout(10000, CooperativeCancellation = true)]
    public async Task Hex1bFullScreenConsoleFocusesFindingsTableAfterTabSwitch()
    {
        PicketTuiState state = CreateState();
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
        Assert.Contains("Result value", screenText);
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
        Assert.Contains("Repository", screenText);
        Assert.Contains("Token env", screenText);
        Assert.Contains("Gist", screenText);
        Assert.Contains("Repo type", screenText);
        Assert.Contains("forks", screenText);
        Assert.Contains("sources", screenText);
        Assert.Contains("owner", screenText);
        Assert.Contains("member", screenText);
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
        Assert.Contains("Completed:", screenText);
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
        CliResult result = await RunTuiCliAsync(["--help"], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket-tui [<report>] [options]", result.Stdout);
        Assert.Contains("--flow", result.Stdout);
        Assert.Contains("--scan", result.Stdout);
        Assert.Contains("--version", result.Stdout);
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
                new ReportFindingSummary("github-token", "src/auth.cs", 12, "fp-auth-1", 7),
                new ReportFindingSummary("github-token", "src/auth.cs", 18, "fp-auth-2", 8),
                new ReportFindingSummary("aws-key", "infra/main.tf", 4, "fp-infra-1", 3),
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

    private static Hex1bTerminal CreateHeadlessTerminal(PicketTuiState state, int width, int height)
    {
        return Hex1bTerminal.CreateBuilder()
            .WithHex1bApp(
                options =>
                {
                    options.EnableMouse = true;
                    options.Theme = PicketTuiPalette.CreateTheme();
                },
                app => ctx => PicketTuiApp.Build(ctx, state, app))
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
