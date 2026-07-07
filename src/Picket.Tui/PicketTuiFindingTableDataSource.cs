using Hex1b.Data;
using System.Collections.Specialized;

namespace Picket.Tui;

/// <summary>
/// Provides virtualized finding rows for the Hex1b findings table.
/// </summary>
/// <param name="state">The owning TUI state.</param>
internal sealed class PicketTuiFindingTableDataSource(PicketTuiState state) : ITableDataSource<PicketTuiFindingRow>
{
    /// <summary>
    /// Occurs when the visible row set changes.
    /// </summary>
    public event NotifyCollectionChangedEventHandler? CollectionChanged;

    /// <summary>
    /// Notifies the table that visible rows should be refreshed.
    /// </summary>
    internal void Refresh()
    {
        CollectionChanged?.Invoke(this, new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }

    /// <summary>
    /// Gets the number of visible finding rows.
    /// </summary>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The visible row count.</returns>
    public ValueTask<int> GetItemCountAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(state.VisibleRows.Count);
    }

    /// <summary>
    /// Gets a page of visible finding rows.
    /// </summary>
    /// <param name="startIndex">The zero-based first row index.</param>
    /// <param name="count">The maximum number of rows to return.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The requested visible row page.</returns>
    public ValueTask<IReadOnlyList<PicketTuiFindingRow>> GetItemsAsync(
        int startIndex,
        int count,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        IReadOnlyList<PicketTuiFindingRow> visibleRows = state.VisibleRows;
        if (startIndex >= visibleRows.Count)
        {
            return ValueTask.FromResult<IReadOnlyList<PicketTuiFindingRow>>([]);
        }

        int actualCount = Math.Min(count, visibleRows.Count - startIndex);
        var rows = new PicketTuiFindingRow[actualCount];
        for (int i = 0; i < actualCount; i++)
        {
            rows[i] = visibleRows[startIndex + i];
        }

        return ValueTask.FromResult<IReadOnlyList<PicketTuiFindingRow>>(rows);
    }

    /// <summary>
    /// Gets the current visible index for a row key.
    /// </summary>
    /// <param name="key">The row key.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The zero-based visible row index, or <see langword="null" /> when the key is not visible.</returns>
    public ValueTask<int?> GetIndexForKeyAsync(object? key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int index = state.IndexOfVisibleRowKey(key);
        return ValueTask.FromResult<int?>(index < 0 ? null : index);
    }
}
