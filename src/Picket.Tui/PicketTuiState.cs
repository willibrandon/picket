using Picket.Report;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Picket.Tui;

/// <summary>
/// Holds mutable scanner-console state for a loaded report.
/// </summary>
internal sealed class PicketTuiState
{
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
    private readonly Lock _scanLock = new();
    private long _yankGeneration;
    private CancellationTokenSource? _scanCancellation;
    private Task? _scanTask;
    private List<PicketTuiFindingRow>? _visibleRows;

    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiState" /> class.
    /// </summary>
    /// <param name="report">The report loaded into the TUI.</param>
    /// <param name="scanExecutor">The optional scan executor for the scan workspace.</param>
    internal PicketTuiState(PicketTuiReport report, IPicketTuiScanExecutor? scanExecutor = null)
    {
        _rows = [];
        _rowsByKey = new Dictionary<string, PicketTuiFindingRow>(StringComparer.Ordinal);
        Report = report;
        LoadReport(report);
        ScanWorkspace = new PicketTuiScanWorkspace(scanExecutor ?? PicketTuiProcessScanExecutor.CreateDefault());
        FindingDataSource = new PicketTuiFindingTableDataSource(this);
        CurrentView = _rows.Count == 0 ? PicketTuiView.Dashboard : PicketTuiView.Findings;
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
    /// Gets the virtualized table data source for visible findings.
    /// </summary>
    internal PicketTuiFindingTableDataSource FindingDataSource { get; }

    /// <summary>
    /// Gets the current scanner-console view.
    /// </summary>
    internal PicketTuiView CurrentView { get; private set; } = PicketTuiView.Dashboard;

    /// <summary>
    /// Gets the current finding filter text.
    /// </summary>
    internal string SearchText { get; private set; } = string.Empty;

    /// <summary>
    /// Gets the current status message.
    /// </summary>
    internal string StatusMessage { get; private set; } = "Ready";

    /// <summary>
    /// Gets the transient yank notification text.
    /// </summary>
    internal string? YankNotification { get; private set; }

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
        CurrentView = view;
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
        if (result is null || !File.Exists(result.ReportPath))
        {
            StatusMessage = ScanWorkspace.Status;
            return;
        }

        LoadReport(result.ReportPath);
        SetView(PicketTuiView.Scan);
        StatusMessage = Report.Summary.FindingCount == 0
            ? string.Concat(ScanWorkspace.Status, "; no findings")
            : string.Concat(ScanWorkspace.Status, "; findings loaded");
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
            PicketTuiView.Dashboard => string.Concat(GetSummaryLine(), Environment.NewLine, "Report: ", Report.Path),
            PicketTuiView.Rules => FormatCountYank("Rules", GetTopRules(50)),
            PicketTuiView.Files => FormatCountYank("Files", GetTopFiles(50)),
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

    private async Task RunScanInBackgroundAsync(Action invalidate, CancellationTokenSource scanCancellation)
    {
        CancellationToken cancellationToken = scanCancellation.Token;
        try
        {
            await RunScanAsync(invalidate, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            StatusMessage = "Scan cancelled";
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
    /// Applies a finding filter.
    /// </summary>
    /// <param name="searchText">The filter text.</param>
    internal void SetSearchText(string searchText)
    {
        SearchText = searchText;
        _visibleRows = null;
        FindingDataSource.Refresh();
        StatusMessage = searchText.Length == 0
            ? "Search cleared"
            : string.Concat("Filter: ", searchText);
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
        _visibleRows = null;
    }

    private List<PicketTuiFindingRow> CreateVisibleRows()
    {
        if (SearchText.Length == 0)
        {
            return _rows;
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

    private static string FormatFindingYank(PicketTuiFindingRow row, string reportPath)
    {
        return string.Join(
            Environment.NewLine,
            string.Concat("Rule: ", row.RuleId),
            string.Concat("Path: ", row.Path),
            string.Concat("Line: ", row.Line),
            string.Concat("Fingerprint: ", row.Fingerprint),
            string.Concat("Report: ", reportPath));
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

    private string FormatLogsYank()
    {
        return string.Join(
            Environment.NewLine,
            string.Concat("Loaded: ", Report.LoadedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
            string.Concat("Report: ", Report.Path),
            string.Concat("Status: ", StatusMessage),
            string.Concat("Scan: ", ScanWorkspace.Status),
            string.Concat("Scan timing: ", FormatScanTiming(ScanWorkspace)),
            string.Concat("Last run: ", ScanWorkspace.LastMessage),
            string.Concat("Scanner output:", Environment.NewLine, ScanWorkspace.CapturedOutputText),
            string.Concat("Filter: ", SearchText.Length == 0 ? "none" : SearchText));
    }

    private string GetFindingYankText()
    {
        return FocusedFinding is { } row
            ? FormatFindingYank(row, Report.Path)
            : string.Empty;
    }

    private string GetScanYankText()
    {
        var lines = new List<string>
        {
            string.Concat("Command: ", ScanWorkspace.BuildCommandLinePreview()),
            string.Concat("Report: ", ScanWorkspace.ReportPath),
            string.Concat("Status: ", ScanWorkspace.Status),
            string.Concat("Timing: ", FormatScanTiming(ScanWorkspace)),
            string.Concat("Summary: ", GetSummaryLine()),
        };

        lines.Add(string.Concat("Scanner output:", Environment.NewLine, ScanWorkspace.CapturedOutputText));
        return string.Join(Environment.NewLine, lines);
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
}
