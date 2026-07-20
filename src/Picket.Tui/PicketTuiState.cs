using Hex1b.Documents;
using Hex1b.Widgets;
using Picket.Report;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Picket.Tui;

/// <summary>
/// Holds mutable scanner-console state for a loaded report.
/// </summary>
internal sealed class PicketTuiState
{
    private const int TopListLimit = 8;

    private static readonly PicketTuiView[] s_navigationItems =
    [
        PicketTuiView.Dashboard,
        PicketTuiView.Scan,
        PicketTuiView.Findings,
        PicketTuiView.Rules,
        PicketTuiView.Files,
        PicketTuiView.Logs,
    ];

    private readonly Dictionary<string, PicketTuiFindingRow> _rowsByKey;
    private readonly List<PicketTuiFindingRow> _rows;
    private readonly IPicketTuiFileLauncher _fileLauncher;
    private readonly Lock _scanLock = new();
    private EditorState? _dashboardEditorState;
    private string? _dashboardEditorText;
    private EditorState? _findingDetailsEditorState;
    private string? _findingDetailsEditorText;
    private EditorState? _logsEditorState;
    private string? _logsEditorText;
    private long _yankGeneration;
    private PicketTuiFocusTarget? _pendingFocusTarget;
    private PicketTuiOpenFileRequest? _pendingOpenFileRequest;
    private CancellationTokenSource? _scanCancellation;
    private Task? _scanTask;
    private List<PicketTuiFindingRow>? _visibleRows;

    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiState" /> class.
    /// </summary>
    /// <param name="report">The report loaded into the TUI.</param>
    /// <param name="scanExecutor">The optional scan executor for the scan workspace.</param>
    /// <param name="fileLauncher">The optional local file launcher for finding and file rows.</param>
    internal PicketTuiState(
        PicketTuiReport report,
        IPicketTuiScanExecutor? scanExecutor = null,
        IPicketTuiFileLauncher? fileLauncher = null)
    {
        _rows = [];
        _rowsByKey = new Dictionary<string, PicketTuiFindingRow>(StringComparer.Ordinal);
        _fileLauncher = fileLauncher ?? new PicketTuiProcessFileLauncher();
        Report = report;
        LoadReport(report);
        ScanWorkspace = new PicketTuiScanWorkspace(scanExecutor ?? PicketTuiProcessScanExecutor.CreateDefault());
        CurrentView = _rows.Count == 0 ? PicketTuiView.Dashboard : PicketTuiView.Findings;
        QueueFocusForView(CurrentView);
    }

    /// <summary>
    /// Gets the report loaded into the TUI.
    /// </summary>
    internal PicketTuiReport Report { get; private set; }

    /// <summary>
    /// Gets the native scan workspace state.
    /// </summary>
    internal PicketTuiScanWorkspace ScanWorkspace { get; }

    /// <summary>
    /// Gets the current scanner-console view.
    /// </summary>
    internal PicketTuiView CurrentView { get; private set; } = PicketTuiView.Dashboard;

    /// <summary>
    /// Gets the current finding filter text.
    /// </summary>
    internal string SearchText { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the current scanner-output filter text.
    /// </summary>
    internal string LogSearchText { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the current status message.
    /// </summary>
    internal string StatusMessage { get; private set; } = "Ready";

    /// <summary>
    /// Gets the transient yank notification text.
    /// </summary>
    internal string? YankNotification { get; private set; }

    /// <summary>
    /// Gets the yank flash provider for the dashboard editor.
    /// </summary>
    internal PicketTuiYankDecorationProvider DashboardYankProvider { get; } = new();

    /// <summary>
    /// Gets the yank flash provider for the focused-finding details editor.
    /// </summary>
    internal PicketTuiYankDecorationProvider FindingDetailsYankProvider { get; } = new();

    /// <summary>
    /// Gets the yank flash provider for the logs editor.
    /// </summary>
    internal PicketTuiYankDecorationProvider LogsYankProvider { get; } = new();

    /// <summary>
    /// Gets a value indicating whether the focused finding row should render its transient yank flash.
    /// </summary>
    internal bool YankFlashRow { get; private set; }

    /// <summary>
    /// Gets a value indicating whether the current view has contextual text that can be yanked.
    /// </summary>
    internal bool HasYankText
    {
        get
        {
            return CurrentView switch
            {
                PicketTuiView.Scan => true,
                PicketTuiView.Findings => FocusedFinding is not null,
                PicketTuiView.Dashboard => true,
                PicketTuiView.Rules => _rows.Count != 0,
                PicketTuiView.Files => _rows.Count != 0,
                PicketTuiView.Logs => true,
                _ => false,
            };
        }
    }

    /// <summary>
    /// Gets the currently focused finding key.
    /// </summary>
    internal string? FocusedFindingKey { get; private set; }

    /// <summary>
    /// Gets the focused rule row key.
    /// </summary>
    internal string? FocusedRuleKey { get; private set; }

    /// <summary>
    /// Gets the focused file row key.
    /// </summary>
    internal string? FocusedFileKey { get; private set; }

    /// <summary>
    /// Gets all report finding rows.
    /// </summary>
    internal IReadOnlyList<PicketTuiFindingRow> Rows => _rows;

    /// <summary>
    /// Gets the rows visible after applying the current filter.
    /// </summary>
    internal IReadOnlyList<PicketTuiFindingRow> VisibleRows => _visibleRows ??= CreateVisibleRows();

    /// <summary>
    /// Gets the currently focused finding row.
    /// </summary>
    internal PicketTuiFindingRow? FocusedFinding
    {
        get
        {
            return FocusedFindingKey is not null && _rowsByKey.TryGetValue(FocusedFindingKey, out PicketTuiFindingRow? row)
                ? row
                : null;
        }
    }

    /// <summary>
    /// Gets the selected navigation item index.
    /// </summary>
    internal int CurrentNavigationIndex
    {
        get
        {
            for (int i = 0; i < s_navigationItems.Length; i++)
            {
                if (s_navigationItems[i] == CurrentView)
                {
                    return i;
                }
            }

            return 0;
        }
    }

    /// <summary>
    /// Gets the available scanner-console navigation items.
    /// </summary>
    internal static IReadOnlyList<PicketTuiView> NavigationItems => s_navigationItems;

    /// <summary>
    /// Switches the scanner-console view.
    /// </summary>
    /// <param name="view">The view to display.</param>
    internal void SetView(PicketTuiView view)
    {
        if (CurrentView != view)
        {
            ClearYankFlash();
        }

        CurrentView = view;
        QueueFocusForView(view);
    }

    /// <summary>
    /// Runs the current scan workspace request and loads the written report when available.
    /// </summary>
    /// <param name="cancellationToken">A token that can cancel the scan process.</param>
    /// <returns>A task that completes after the scan request has finished.</returns>
    internal async ValueTask RunScanAsync(CancellationToken cancellationToken)
    {
        await RunScanAsync(null, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask RunScanAsync(Action? outputChanged, CancellationToken cancellationToken)
    {
        PicketTuiScanExecutionResult? result = await ScanWorkspace.RunAsync(outputChanged, cancellationToken).ConfigureAwait(false);
        if (result is null || !ScanWorkspace.LastRunReportAvailable)
        {
            StatusMessage = ScanWorkspace.Status;
            return;
        }

        LoadReport(result.ReportPath);
        SetView(PicketTuiView.Scan);
        StatusMessage = ScanWorkspace.Status;
    }

    /// <summary>
    /// Starts the current scan workspace request without blocking the terminal input loop.
    /// </summary>
    /// <param name="invalidate">The UI invalidation callback to request a redraw.</param>
    /// <param name="cancellationToken">A token that can cancel the scan process.</param>
    internal void StartScanInBackground(Action invalidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invalidate);

        lock (_scanLock)
        {
            if (_scanTask is { IsCompleted: false } || ScanWorkspace.IsRunning)
            {
                StatusMessage = "Scan already running";
                invalidate();
                return;
            }

            SetView(PicketTuiView.Scan);
            StatusMessage = "Scan starting";
            CancellationTokenSource scanCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _scanCancellation = scanCancellation;
            _scanTask = RunScanInBackgroundAsync(invalidate, scanCancellation);
        }

        invalidate();
    }

    /// <summary>
    /// Requests cancellation of the current background scan.
    /// </summary>
    /// <param name="invalidate">The UI invalidation callback to request a redraw.</param>
    internal void CancelScan(Action invalidate)
    {
        ArgumentNullException.ThrowIfNull(invalidate);

        CancellationTokenSource? scanCancellation = null;
        lock (_scanLock)
        {
            if (_scanCancellation is null || _scanTask is not { IsCompleted: false } || !ScanWorkspace.IsRunning)
            {
                StatusMessage = "No scan is running";
            }
            else
            {
                StatusMessage = "Cancelling scan";
                ScanWorkspace.MarkCancellationRequested();
                scanCancellation = _scanCancellation;
            }
        }

        try
        {
            scanCancellation?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }

        invalidate();
    }

    /// <summary>
    /// Loads a report from a path into the current TUI state.
    /// </summary>
    /// <param name="reportPath">The report path.</param>
    internal void LoadReport(string reportPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);

        string resolvedPath = Path.GetFullPath(reportPath);
        LoadReport(new PicketTuiReport(
            resolvedPath,
            ReportSummaryReader.Read(resolvedPath),
            DateTimeOffset.UtcNow));
    }

    /// <summary>
    /// Loads the scan workspace report if it already exists on disk.
    /// </summary>
    /// <returns><see langword="true" /> when a previous scan report was loaded.</returns>
    internal bool TryLoadPreviousScanReport()
    {
        string reportPath = ScanWorkspace.ReportPath;
        if (!File.Exists(reportPath))
        {
            StatusMessage = "Ready";
            return false;
        }

        try
        {
            LoadReport(reportPath);
            SetView(PicketTuiView.Scan);
            ScanWorkspace.MarkReportLoaded(Report.Path, Report.Summary.FindingCount);
            StatusMessage = ScanWorkspace.Status;
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            StatusMessage = string.Concat("Previous scan report could not be loaded: ", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Gets the text that should be copied by a contextual yank.
    /// </summary>
    /// <returns>The current view's yank text, or an empty string when nothing is yankable.</returns>
    internal string GetYankText()
    {
        return CurrentView switch
        {
            PicketTuiView.Scan => GetScanYankText(),
            PicketTuiView.Findings => GetFindingYankText(),
            PicketTuiView.Dashboard => GetDashboardText(),
            PicketTuiView.Rules => GetRuleYankText(),
            PicketTuiView.Files => GetFileYankText(),
            PicketTuiView.Logs => FormatLogsYank(),
            _ => string.Empty,
        };
    }

    /// <summary>
    /// Shows a transient yank notification.
    /// </summary>
    /// <param name="text">The yanked text.</param>
    /// <param name="invalidate">The UI invalidation callback.</param>
    /// <param name="cancellationToken">A token that cancels notification clearing.</param>
    internal void ShowYankNotification(string text, Action invalidate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(invalidate);

        long generation = Interlocked.Increment(ref _yankGeneration);
        YankNotification = CreateYankNotification(text);
        YankFlashRow = true;
        _ = ClearYankFlashAsync(generation, invalidate, cancellationToken);
        _ = ClearYankNotificationAsync(generation, invalidate, cancellationToken);
    }

    /// <summary>
    /// Shows a transient yank notification and flashes the selected editor range.
    /// </summary>
    /// <param name="text">The yanked text.</param>
    /// <param name="editorState">The editor state that owns the yanked range.</param>
    /// <param name="provider">The decoration provider for the editor.</param>
    /// <param name="range">The yanked document range.</param>
    /// <param name="invalidate">The UI invalidation callback.</param>
    /// <param name="cancellationToken">A token that cancels notification clearing.</param>
    internal void ShowEditorYankNotification(
        string text,
        EditorState editorState,
        PicketTuiYankDecorationProvider provider,
        DocumentRange range,
        Action invalidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(editorState);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(invalidate);

        long generation = Interlocked.Increment(ref _yankGeneration);
        YankNotification = CreateYankNotification(text);
        provider.HighlightRange = (
            editorState.Document.OffsetToPosition(range.Start),
            editorState.Document.OffsetToPosition(range.End));
        _ = ClearEditorYankFlashAsync(provider, generation, invalidate, cancellationToken);
        _ = ClearYankNotificationAsync(generation, invalidate, cancellationToken);
    }

    /// <summary>
    /// Attempts to get selected text from the active read-only editor pane.
    /// </summary>
    /// <param name="focusedEditor">The currently focused editor, when one is focused.</param>
    /// <param name="text">The selected text.</param>
    /// <param name="editorState">The editor state that owns the selection.</param>
    /// <param name="provider">The matching yank flash provider.</param>
    /// <param name="range">The selected document range.</param>
    /// <returns><see langword="true" /> when a non-empty editor selection exists.</returns>
    internal bool TryGetSelectedEditorText(
        EditorState? focusedEditor,
        out string text,
        out EditorState editorState,
        out PicketTuiYankDecorationProvider provider,
        out DocumentRange range)
    {
        if (focusedEditor is not null
            && TryGetSelectedCandidateEditorText(focusedEditor, out text, out editorState, out provider, out range))
        {
            return true;
        }

        return CurrentView switch
        {
            PicketTuiView.Dashboard => TryGetSelectedCandidateEditorText(
                _dashboardEditorState,
                out text,
                out editorState,
                out provider,
                out range),
            PicketTuiView.Findings => TryGetSelectedCandidateEditorText(
                _findingDetailsEditorState,
                out text,
                out editorState,
                out provider,
                out range),
            PicketTuiView.Logs => TryGetSelectedCandidateEditorText(
                _logsEditorState,
                out text,
                out editorState,
                out provider,
                out range),
            _ => NoSelectedEditorText(out text, out editorState, out provider, out range),
        };
    }

    /// <summary>
    /// Gets or creates the read-only dashboard editor state.
    /// </summary>
    /// <returns>The dashboard editor state.</returns>
    internal EditorState GetDashboardEditorState()
    {
        string text = GetDashboardText();
        return GetOrCreateEditorState(ref _dashboardEditorState, ref _dashboardEditorText, text);
    }

    /// <summary>
    /// Gets or creates the read-only focused-finding details editor state.
    /// </summary>
    /// <returns>The focused-finding details editor state.</returns>
    internal EditorState GetFindingDetailsEditorState()
    {
        string text = FocusedFinding is { } row
            ? FormatFindingDetails(row)
            : "No finding selected.\n\nRun a scan or adjust the filter.";
        return GetOrCreateEditorState(ref _findingDetailsEditorState, ref _findingDetailsEditorText, text);
    }

    /// <summary>
    /// Gets or creates the read-only logs editor state.
    /// </summary>
    /// <returns>The logs editor state.</returns>
    internal EditorState GetLogsEditorState()
    {
        string text = GetLogsText();
        return GetOrCreateEditorState(ref _logsEditorState, ref _logsEditorText, text);
    }

    private async Task RunScanInBackgroundAsync(Action invalidate, CancellationTokenSource scanCancellation)
    {
        CancellationToken cancellationToken = scanCancellation.Token;
        try
        {
            await RunScanAsync(invalidate, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            StatusMessage = ScanWorkspace.Status;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            StatusMessage = string.Concat("Scan failed: ", ex.Message);
        }
        catch (Exception ex)
        {
            StatusMessage = string.Concat("Scan failed: ", ex.Message);
        }
        finally
        {
            lock (_scanLock)
            {
                if (ReferenceEquals(_scanCancellation, scanCancellation))
                {
                    _scanCancellation = null;
                }
            }

            scanCancellation.Dispose();
            invalidate();
        }
    }

    /// <summary>
    /// Switches the scanner-console view by navigation index.
    /// </summary>
    /// <param name="index">The zero-based navigation item index.</param>
    internal void SetViewByIndex(int index)
    {
        if ((uint)index < (uint)s_navigationItems.Length)
        {
            SetView(s_navigationItems[index]);
        }
    }

    /// <summary>
    /// Sets the focused finding from a table key.
    /// </summary>
    /// <param name="key">The finding key.</param>
    internal void FocusFinding(object? key)
    {
        FocusedFindingKey = key?.ToString();
    }

    /// <summary>
    /// Sets the focused rule row.
    /// </summary>
    /// <param name="key">The rule row key.</param>
    internal void FocusRule(object? key)
    {
        FocusedRuleKey = key?.ToString();
    }

    /// <summary>
    /// Sets the focused file row.
    /// </summary>
    /// <param name="key">The file row key.</param>
    internal void FocusFile(object? key)
    {
        FocusedFileKey = key?.ToString();
    }

    /// <summary>
    /// Applies a finding filter.
    /// </summary>
    /// <param name="searchText">The filter text.</param>
    internal void SetSearchText(string searchText)
    {
        SearchText = searchText;
        _visibleRows = null;
        IReadOnlyList<PicketTuiFindingRow> visibleRows = VisibleRows;
        FocusedFindingKey = visibleRows.Count == 0 ? null : visibleRows[0].Key;
        StatusMessage = searchText.Length == 0
            ? "Search cleared"
            : string.Concat("Filter: ", searchText);
    }

    /// <summary>
    /// Applies a scanner-output filter.
    /// </summary>
    /// <param name="searchText">The scanner-output filter text.</param>
    internal void SetLogSearchText(string searchText)
    {
        LogSearchText = searchText;
        _logsEditorState = null;
        _logsEditorText = null;
    }

    /// <summary>
    /// Clears the current finding filter.
    /// </summary>
    internal void ClearSearch()
    {
        SetSearchText(string.Empty);
    }

    /// <summary>
    /// Finds the visible index for a row key.
    /// </summary>
    /// <param name="key">The row key.</param>
    /// <returns>The zero-based visible row index, or -1 when the key is not visible.</returns>
    internal int IndexOfVisibleRowKey(object? key)
    {
        if (key is null)
        {
            return -1;
        }

        string text = key.ToString() ?? string.Empty;
        IReadOnlyList<PicketTuiFindingRow> visibleRows = VisibleRows;
        for (int i = 0; i < visibleRows.Count; i++)
        {
            if (visibleRows[i].Key.Equals(text, StringComparison.Ordinal))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Moves the focused finding within the visible finding rows.
    /// </summary>
    /// <param name="delta">The signed row delta.</param>
    internal void MoveFindingFocus(int delta)
    {
        IReadOnlyList<PicketTuiFindingRow> visibleRows = VisibleRows;
        if (visibleRows.Count == 0)
        {
            FocusedFindingKey = null;
            return;
        }

        int currentIndex = IndexOfVisibleRowKey(FocusedFindingKey);
        if (currentIndex < 0)
        {
            currentIndex = 0;
        }

        int nextIndex = Math.Clamp(currentIndex + delta, 0, visibleRows.Count - 1);
        FocusedFindingKey = visibleRows[nextIndex].Key;
        StatusMessage = string.Concat(
            "Finding ",
            (nextIndex + 1).ToString(CultureInfo.InvariantCulture),
            " of ",
            visibleRows.Count.ToString(CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Gets the most frequent rules in the report.
    /// </summary>
    /// <param name="limit">The maximum number of rows to return.</param>
    /// <returns>The top rules and finding counts.</returns>
    internal List<KeyValuePair<string, int>> GetTopRules(int limit)
    {
        return CountBy(row => row.RuleId, limit);
    }

    /// <summary>
    /// Gets the most frequent files in the report.
    /// </summary>
    /// <param name="limit">The maximum number of rows to return.</param>
    /// <returns>The top files and finding counts.</returns>
    internal List<KeyValuePair<string, int>> GetTopFiles(int limit)
    {
        return CountBy(row => row.Path, limit);
    }

    /// <summary>
    /// Requests opening the focused finding's local file after the full-screen terminal has stopped.
    /// </summary>
    /// <returns><see langword="true" /> when a file-open request was queued.</returns>
    internal bool RequestOpenFocusedFindingFile()
    {
        if (FocusedFinding is not { } row)
        {
            StatusMessage = "No finding selected";
            return false;
        }

        _pendingOpenFileRequest = new PicketTuiOpenFileRequest(
            row.Path,
            ParseLineNumber(row.Line),
            ToPositiveNullable(row.StartColumn),
            PicketTuiFocusTarget.FindingsTable);
        StatusMessage = CreateOpeningMessage(_pendingOpenFileRequest.GetValueOrDefault());
        return true;
    }

    /// <summary>
    /// Requests opening the focused file row after the full-screen terminal has stopped.
    /// </summary>
    /// <returns><see langword="true" /> when a file-open request was queued.</returns>
    internal bool RequestOpenFocusedFile()
    {
        if (FocusedFileKey is null)
        {
            StatusMessage = "No file selected";
            return false;
        }

        PicketTuiFindingRow? row = FindFirstRowForFile(FocusedFileKey);
        _pendingOpenFileRequest = new PicketTuiOpenFileRequest(
            FocusedFileKey,
            row is null ? null : ParseLineNumber(row.Line),
            row is null ? null : ToPositiveNullable(row.StartColumn),
            PicketTuiFocusTarget.FilesTable);
        StatusMessage = CreateOpeningMessage(_pendingOpenFileRequest.GetValueOrDefault());
        return true;
    }

    /// <summary>
    /// Opens and clears a queued file-open request.
    /// </summary>
    /// <returns><see langword="true" /> when a pending request was handled.</returns>
    internal bool TryOpenPendingFile()
    {
        if (_pendingOpenFileRequest is not { } request)
        {
            return false;
        }

        _pendingOpenFileRequest = null;
        _fileLauncher.TryOpen(request.Path, request.Line, request.Column, out string message);
        _pendingFocusTarget = request.ReturnFocusTarget;
        StatusMessage = message;
        return true;
    }

    /// <summary>
    /// Gets and clears the pending keyboard-focus target for the next rendered frame.
    /// </summary>
    /// <returns>The pending focus target, or <see langword="null" /> when focus should remain unchanged.</returns>
    internal PicketTuiFocusTarget? ConsumePendingFocusTarget()
    {
        PicketTuiFocusTarget? target = _pendingFocusTarget;
        _pendingFocusTarget = null;
        return target;
    }

    /// <summary>
    /// Filters findings to the focused rule row and opens the findings table.
    /// </summary>
    internal void FilterFindingsToFocusedRule()
    {
        if (FocusedRuleKey is null)
        {
            StatusMessage = "No rule selected";
            return;
        }

        SetSearchText(FocusedRuleKey);
        SetView(PicketTuiView.Findings);
    }

    /// <summary>
    /// Filters findings to the focused file row and opens the findings table.
    /// </summary>
    internal void FilterFindingsToFocusedFile()
    {
        if (FocusedFileKey is null)
        {
            StatusMessage = "No file selected";
            return;
        }

        SetSearchText(FocusedFileKey);
        SetView(PicketTuiView.Findings);
    }

    /// <summary>
    /// Gets a one-line report summary.
    /// </summary>
    /// <returns>A display-ready summary line.</returns>
    internal string GetSummaryLine()
    {
        return string.Concat(
            Report.Summary.FindingCount.ToString(CultureInfo.InvariantCulture),
            " findings across ",
            Report.Summary.FileCount.ToString(CultureInfo.InvariantCulture),
            " files in ",
            Report.Summary.Format);
    }

    /// <summary>
    /// Gets the display label for a scanner-console view.
    /// </summary>
    /// <param name="view">The view to describe.</param>
    /// <returns>The display label.</returns>
    internal static string GetViewLabel(PicketTuiView view)
    {
        return view switch
        {
            PicketTuiView.Dashboard => "Dashboard",
            PicketTuiView.Scan => "Scan",
            PicketTuiView.Findings => "Findings",
            PicketTuiView.Rules => "Rules",
            PicketTuiView.Files => "Files",
            PicketTuiView.Logs => "Logs",
            _ => view.ToString(),
        };
    }

    private static List<PicketTuiFindingRow> CreateRows(IReadOnlyList<ReportFindingSummary> findings)
    {
        var rows = new List<PicketTuiFindingRow>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            rows.Add(new PicketTuiFindingRow(findings[i], i + 1));
        }

        return rows;
    }

    private void LoadReport(PicketTuiReport report)
    {
        Report = report;
        _rows.Clear();
        _rowsByKey.Clear();
        List<PicketTuiFindingRow> rows = CreateRows(report.Summary.Findings);
        for (int i = 0; i < rows.Count; i++)
        {
            PicketTuiFindingRow row = rows[i];
            _rows.Add(row);
            _rowsByKey.Add(row.Key, row);
        }

        FocusedFindingKey = _rows.Count == 0 ? null : _rows[0].Key;
        FocusedRuleKey = null;
        FocusedFileKey = null;
        _visibleRows = null;
        ResetEditorStates();
    }

    private void QueueFocusForView(PicketTuiView view)
    {
        _pendingFocusTarget = view switch
        {
            PicketTuiView.Scan => PicketTuiFocusTarget.ScanPrimaryControl,
            PicketTuiView.Findings => PicketTuiFocusTarget.FindingsTable,
            PicketTuiView.Rules => PicketTuiFocusTarget.RulesTable,
            PicketTuiView.Files => PicketTuiFocusTarget.FilesTable,
            PicketTuiView.Logs => PicketTuiFocusTarget.LogsSearch,
            _ => PicketTuiFocusTarget.DashboardEditor,
        };
    }

    private List<PicketTuiFindingRow> CreateVisibleRows()
    {
        if (SearchText.Length == 0)
        {
            return [.. _rows];
        }

        var rows = new List<PicketTuiFindingRow>();
        for (int i = 0; i < _rows.Count; i++)
        {
            PicketTuiFindingRow row = _rows[i];
            if (Contains(row.RuleId, SearchText)
                || Contains(row.Path, SearchText)
                || Contains(row.Fingerprint, SearchText))
            {
                rows.Add(row);
            }
        }

        return rows;
    }

    private static bool Contains(string value, string filter)
    {
        return value.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }

    private static string CreateYankNotification(string text)
    {
        if (text.Contains('\n'))
        {
            return string.Concat(
                "Yanked ",
                text.Count(static character => character == '\n') + 1,
                " lines");
        }

        return text.Length > 48
            ? string.Concat("Yanked: ", text.AsSpan(0, 45), "...")
            : string.Concat("Yanked: ", text);
    }

    private static string FormatCountYank(string title, List<KeyValuePair<string, int>> rows)
    {
        if (rows.Count == 0)
        {
            return string.Empty;
        }

        return string.Join(
            Environment.NewLine,
            rows.Select(pair => string.Concat(pair.Value.ToString(CultureInfo.InvariantCulture), "\t", pair.Key)).Prepend(title));
    }

    private static string FormatCountRowYank(string label, KeyValuePair<string, int> row)
    {
        return string.Join(
            Environment.NewLine,
            string.Concat(label, ": ", row.Key),
            string.Concat("Findings: ", row.Value.ToString(CultureInfo.InvariantCulture)));
    }

    private static string FormatFindingYank(PicketTuiFindingRow row, string reportPath)
    {
        List<string> lines = CreateFindingMetadataLines(row);
        lines.Add(string.Concat("Report: ", reportPath));
        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatFindingDetails(PicketTuiFindingRow row)
    {
        List<string> lines = CreateFindingMetadataLines(row);
        lines.Add(string.Empty);
        lines.Add("Secret evidence is intentionally not loaded in this summary view.");
        return string.Join(Environment.NewLine, lines);
    }

    private static List<string> CreateFindingMetadataLines(PicketTuiFindingRow row)
    {
        List<string> lines =
        [
            string.Concat("Rule: ", row.RuleId),
            string.Concat("Path: ", row.Path),
            string.Concat("Line: ", row.Line),
            string.Concat("Fingerprint: ", row.Fingerprint),
        ];
        if (row.Randomness.Length != 0)
        {
            lines.Add(string.Concat("Randomness: ", row.Randomness));
        }

        if (row.RandomnessModel.Length != 0)
        {
            lines.Add(string.Concat("Randomness model: ", row.RandomnessModel));
        }

        return lines;
    }

    private async Task ClearYankNotificationAsync(long generation, Action invalidate, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(1500), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (Interlocked.Read(ref _yankGeneration) == generation)
        {
            YankNotification = null;
            invalidate();
        }
    }

    private async Task ClearYankFlashAsync(long generation, Action invalidate, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (Interlocked.Read(ref _yankGeneration) == generation)
        {
            YankFlashRow = false;
            invalidate();
        }
    }

    private async Task ClearEditorYankFlashAsync(
        PicketTuiYankDecorationProvider provider,
        long generation,
        Action invalidate,
        CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        if (Interlocked.Read(ref _yankGeneration) == generation)
        {
            provider.HighlightRange = null;
            invalidate();
        }
    }

    private string FormatLogsYank()
    {
        return GetLogsText();
    }

    private string GetFindingYankText()
    {
        return FocusedFinding is { } row
            ? FormatFindingYank(row, Report.Path)
            : string.Empty;
    }

    private string GetScanYankText()
    {
        List<string> lines =
        [
            string.Concat("Command: ", ScanWorkspace.BuildCommandLinePreview()),
            string.Concat("Report: ", ScanWorkspace.ReportPath),
            string.Concat("Status: ", ScanWorkspace.Status),
            string.Concat("Timing: ", FormatScanTiming(ScanWorkspace)),
            string.Concat("Summary: ", GetSummaryLine()),
            string.Concat("Scanner output:", Environment.NewLine, ScanWorkspace.CapturedOutputText),
        ];

        return string.Join(Environment.NewLine, lines);
    }

    private string GetDashboardText()
    {
        var lines = new List<string>
        {
            "Report",
            string.Concat("  Findings: ", _rows.Count.ToString(CultureInfo.InvariantCulture)),
            string.Concat("  Files:    ", Report.Summary.FileCount.ToString(CultureInfo.InvariantCulture)),
            string.Concat("  Format:   ", Report.Summary.Format),
            string.Concat("  Loaded:   ", Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
            string.Concat("  Path:     ", Report.Path),
            string.Empty,
            "Scanner",
            string.Concat("  Status:   ", ScanWorkspace.Status),
            string.Concat("  Target:   ", FormatScanTargetForText(ScanWorkspace)),
            string.Concat("  Timing:   ", FormatScanTiming(ScanWorkspace)),
            string.Concat("  Output:   ", ScanWorkspace.CapturedOutputLines.Count == 0 ? "No captured output" : "Open Logs"),
            string.Empty,
            "Top rules by finding count",
        };

        AppendCountRows(lines, GetTopRules(TopListLimit), "Rule");
        lines.Add(string.Empty);
        lines.Add("Top files by finding count");
        AppendCountRows(lines, GetTopFiles(TopListLimit), "File");
        return string.Join(Environment.NewLine, lines);
    }

    private string GetLogsText()
    {
        List<string> filteredOutput = GetFilteredLogLines();
        int totalOutputLineCount = ScanWorkspace.CapturedOutputLines.Count;
        var lines = new List<string>
        {
            string.Concat("Loaded:      ", Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
            string.Concat("Report:      ", Report.Path),
            string.Concat("Status:      ", StatusMessage),
            string.Concat("Scan:        ", ScanWorkspace.Status),
            string.Concat("Scan timing: ", FormatScanTiming(ScanWorkspace)),
            string.Concat("Last run:    ", ScanWorkspace.LastMessage),
            string.Empty,
            LogSearchText.Length == 0
                ? string.Concat("Scanner output (", totalOutputLineCount.ToString(CultureInfo.InvariantCulture), " lines)")
                : string.Concat(
                    "Scanner output matching \"",
                    LogSearchText,
                    "\" (",
                    filteredOutput.Count.ToString(CultureInfo.InvariantCulture),
                    "/",
                    totalOutputLineCount.ToString(CultureInfo.InvariantCulture),
                    " lines)"),
        };

        if (filteredOutput.Count == 0)
        {
            lines.Add(totalOutputLineCount == 0
                ? "No scanner output captured."
                : "No scanner output lines match the current search.");
            return string.Join(Environment.NewLine, lines);
        }

        lines.AddRange(filteredOutput);
        return string.Join(Environment.NewLine, lines);
    }

    private List<string> GetFilteredLogLines()
    {
        IReadOnlyList<string> lines = ScanWorkspace.CapturedOutputLines;
        if (LogSearchText.Length == 0)
        {
            return [.. lines];
        }

        var filtered = new List<string>();
        for (int i = 0; i < lines.Count; i++)
        {
            if (lines[i].Contains(LogSearchText, StringComparison.OrdinalIgnoreCase))
            {
                filtered.Add(lines[i]);
            }
        }

        return filtered;
    }

    private string GetRuleYankText()
    {
        return TryFindCountRow(GetTopRules(_rows.Count), FocusedRuleKey, out KeyValuePair<string, int> row)
            ? FormatCountRowYank("Rule", row)
            : FormatCountYank("Rules", GetTopRules(50));
    }

    private string GetFileYankText()
    {
        return TryFindCountRow(GetTopFiles(_rows.Count), FocusedFileKey, out KeyValuePair<string, int> row)
            ? FormatCountRowYank("File", row)
            : FormatCountYank("Files", GetTopFiles(50));
    }

    private static string FormatScanTiming(PicketTuiScanWorkspace scan)
    {
        if (!scan.LastStartedAt.HasValue)
        {
            return "not run yet";
        }

        if (!scan.LastCompletedAt.HasValue)
        {
            return string.Concat("started ", FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()), ", still running");
        }

        return string.Concat(
            "started ",
            FormatTimestamp(scan.LastStartedAt.GetValueOrDefault()),
            ", completed ",
            FormatTimestamp(scan.LastCompletedAt.GetValueOrDefault()),
            ", elapsed ",
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

    private List<KeyValuePair<string, int>> CountBy(Func<PicketTuiFindingRow, string> keySelector, int limit)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < _rows.Count; i++)
        {
            string key = keySelector(_rows[i]);
            ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(counts, key, out _);
            count++;
        }

        return
        [
            .. counts
                .OrderByDescending(pair => pair.Value)
                .ThenBy(pair => pair.Key, StringComparer.Ordinal)
                .Take(limit),
        ];
    }

    private static void AppendCountRows(List<string> lines, List<KeyValuePair<string, int>> rows, string label)
    {
        if (rows.Count == 0)
        {
            lines.Add("  No findings.");
            return;
        }

        lines.Add(string.Concat("  Findings  ", label));
        for (int i = 0; i < rows.Count; i++)
        {
            KeyValuePair<string, int> row = rows[i];
            lines.Add(string.Concat(
                "  ",
                row.Value.ToString(CultureInfo.InvariantCulture).PadLeft(8),
                "  ",
                row.Key));
        }
    }

    private static EditorState GetOrCreateEditorState(ref EditorState? editorState, ref string? editorText, string text)
    {
        if (editorState is null || !string.Equals(editorText, text, StringComparison.Ordinal))
        {
            editorText = text;
            editorState = new EditorState(new Hex1bDocument(text)) { IsReadOnly = true };
        }

        return editorState;
    }

    private bool TryGetSelectedCandidateEditorText(
        EditorState? candidate,
        out string text,
        out EditorState editorState,
        out PicketTuiYankDecorationProvider provider,
        out DocumentRange range)
    {
        if (candidate is not null
            && candidate.Cursor.HasSelection
            && TryFindYankProvider(candidate, out provider))
        {
            range = candidate.Cursor.SelectionRange;
            text = candidate.Document.GetText(range);
            if (text.Length != 0)
            {
                editorState = candidate;
                return true;
            }
        }

        return NoSelectedEditorText(out text, out editorState, out provider, out range);
    }

    private bool TryFindYankProvider(EditorState editorState, out PicketTuiYankDecorationProvider provider)
    {
        if (ReferenceEquals(editorState, _dashboardEditorState))
        {
            provider = DashboardYankProvider;
            return true;
        }

        if (ReferenceEquals(editorState, _findingDetailsEditorState))
        {
            provider = FindingDetailsYankProvider;
            return true;
        }

        if (ReferenceEquals(editorState, _logsEditorState))
        {
            provider = LogsYankProvider;
            return true;
        }

        provider = null!;
        return false;
    }

    private static bool NoSelectedEditorText(
        out string text,
        out EditorState editorState,
        out PicketTuiYankDecorationProvider provider,
        out DocumentRange range)
    {
        text = string.Empty;
        editorState = null!;
        provider = null!;
        range = default;
        return false;
    }

    private static string FormatScanTargetForText(PicketTuiScanWorkspace scan)
    {
        return scan.TargetMode switch
        {
            PicketTuiScanTargetMode.GitHub => scan.GitHubTargetDisplayValue,
            PicketTuiScanTargetMode.AzureDevOps => FirstNonEmpty(
                scan.AzureDevOpsRepository,
                scan.AzureDevOpsProject,
                scan.AzureDevOpsOrganization,
                "Azure DevOps target not selected"),
            PicketTuiScanTargetMode.GitLab => FirstNonEmpty(
                scan.GitLabProject,
                scan.GitLabGroup,
                string.Empty,
                "GitLab target not selected"),
            PicketTuiScanTargetMode.Gitea => FirstNonEmpty(
                scan.GiteaRepository,
                scan.GiteaOrganization,
                scan.GiteaUser,
                scan.GiteaGenericPackageOwner,
                "Gitea target not selected"),
            PicketTuiScanTargetMode.Bitbucket => FirstNonEmpty(
                scan.BitbucketRepository,
                scan.BitbucketWorkspace,
                string.Empty,
                "Bitbucket target not selected"),
            PicketTuiScanTargetMode.BitbucketDataCenter => FirstNonEmpty(
                scan.BitbucketDataCenterRepository,
                scan.BitbucketDataCenterProject,
                scan.BitbucketDataCenterApiEndpoint,
                "Bitbucket Data Center target not selected"),
            PicketTuiScanTargetMode.S3 => FirstNonEmpty(
                scan.S3Bucket,
                scan.S3Prefix,
                scan.S3Endpoint,
                "S3 target not selected"),
            PicketTuiScanTargetMode.Gcs => FirstNonEmpty(
                scan.GcsBucket,
                scan.GcsPrefix,
                scan.GcsEndpoint,
                "GCS target not selected"),
            PicketTuiScanTargetMode.AzureBlob => FirstNonEmpty(
                scan.AzureBlobContainer,
                scan.AzureBlobPrefix,
                scan.AzureBlobEndpoint,
                "Azure Blob target not selected"),
            PicketTuiScanTargetMode.DockerArchive => string.IsNullOrWhiteSpace(scan.DockerArchivePath)
                ? "Docker archive not selected"
                : scan.DockerArchivePath,
            PicketTuiScanTargetMode.OciArchive => string.IsNullOrWhiteSpace(scan.OciArchivePath)
                ? "OCI archive not selected"
                : scan.OciArchivePath,
            PicketTuiScanTargetMode.RegistryImage => string.IsNullOrWhiteSpace(scan.RegistryImage)
                ? "Registry image not selected"
                : scan.RegistryImage,
            _ => string.IsNullOrWhiteSpace(scan.LocalPath) ? "." : scan.LocalPath,
        };
    }

    private static bool TryFindCountRow(
        List<KeyValuePair<string, int>> rows,
        string? key,
        out KeyValuePair<string, int> row)
    {
        if (key is not null)
        {
            for (int i = 0; i < rows.Count; i++)
            {
                if (string.Equals(rows[i].Key, key, StringComparison.Ordinal))
                {
                    row = rows[i];
                    return true;
                }
            }
        }

        row = default;
        return false;
    }

    private static int? ParseLineNumber(string value)
    {
        return int.TryParse(value, CultureInfo.InvariantCulture, out int line) && line > 0
            ? line
            : null;
    }

    private static int? ToPositiveNullable(int value)
    {
        return value > 0 ? value : null;
    }

    private static string CreateOpeningMessage(PicketTuiOpenFileRequest request)
    {
        if (request.Line.HasValue && request.Column.HasValue)
        {
            return string.Concat(
                "Opening ",
                request.Path,
                ":",
                request.Line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture),
                ":",
                request.Column.GetValueOrDefault().ToString(CultureInfo.InvariantCulture));
        }

        if (request.Line.HasValue)
        {
            return string.Concat(
                "Opening ",
                request.Path,
                ":",
                request.Line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture));
        }

        return string.Concat("Opening ", request.Path);
    }

    private PicketTuiFindingRow? FindFirstRowForFile(string path)
    {
        for (int i = 0; i < _rows.Count; i++)
        {
            if (string.Equals(_rows[i].Path, path, StringComparison.Ordinal))
            {
                return _rows[i];
            }
        }

        return null;
    }

    private void ResetEditorStates()
    {
        _dashboardEditorState = null;
        _dashboardEditorText = null;
        _findingDetailsEditorState = null;
        _findingDetailsEditorText = null;
        _logsEditorState = null;
        _logsEditorText = null;
    }

    private void ClearYankFlash()
    {
        YankFlashRow = false;
        DashboardYankProvider.HighlightRange = null;
        FindingDetailsYankProvider.HighlightRange = null;
        LogsYankProvider.HighlightRange = null;
    }
}
