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
        PicketTuiView.Findings,
        PicketTuiView.Rules,
        PicketTuiView.Files,
        PicketTuiView.Accessibility,
        PicketTuiView.Logs,
    ];

    private readonly Dictionary<string, PicketTuiFindingRow> _rowsByKey;
    private readonly List<PicketTuiFindingRow> _rows;
    private List<PicketTuiFindingRow>? _visibleRows;

    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiState" /> class.
    /// </summary>
    /// <param name="report">The report loaded into the TUI.</param>
    internal PicketTuiState(PicketTuiReport report)
    {
        Report = report;
        _rows = CreateRows(report.Summary.Findings);
        _rowsByKey = _rows.ToDictionary(row => row.Key, StringComparer.Ordinal);
        FocusedFindingKey = _rows.Count == 0 ? null : _rows[0].Key;
        FindingDataSource = new PicketTuiFindingTableDataSource(this);
    }

    /// <summary>
    /// Gets the report loaded into the TUI.
    /// </summary>
    internal PicketTuiReport Report { get; }

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
        StatusMessage = string.Concat("View: ", GetViewLabel(view));
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
            PicketTuiView.Findings => "Findings",
            PicketTuiView.Rules => "Rules",
            PicketTuiView.Files => "Files",
            PicketTuiView.Accessibility => "Accessibility",
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
