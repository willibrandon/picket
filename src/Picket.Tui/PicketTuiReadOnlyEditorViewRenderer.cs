using Hex1b;
using Hex1b.Documents;
using Hex1b.Layout;
using Hex1b.Theming;
using Hex1b.Widgets;

namespace Picket.Tui;

/// <summary>
/// Renders selectable read-only text without editor filler markers below the document.
/// </summary>
internal sealed class PicketTuiReadOnlyEditorViewRenderer : IEditorViewRenderer
{
    private static readonly PicketTuiReadOnlyEditorViewRenderer s_instance = new();

    /// <summary>
    /// Gets the shared stateless renderer.
    /// </summary>
    internal static PicketTuiReadOnlyEditorViewRenderer Instance => s_instance;

    /// <inheritdoc />
    public void Render(
        Hex1bRenderContext context,
        EditorState state,
        Rect viewport,
        int scrollOffset,
        int horizontalScrollOffset,
        bool isFocused,
        char? pendingNibble = null,
        IReadOnlyList<ITextDecorationProvider>? decorationProviders = null,
        IReadOnlyList<InlineHint>? inlineHints = null,
        bool wordWrap = false,
        IReadOnlyList<FoldingRegion>? foldingRegions = null)
    {
        TextEditorViewRenderer.Instance.Render(
            context,
            state,
            viewport,
            scrollOffset,
            horizontalScrollOffset,
            isFocused,
            pendingNibble,
            decorationProviders,
            inlineHints,
            wordWrap,
            foldingRegions);

        int firstEmptyViewLine = Math.Max(0, state.Document.LineCount - scrollOffset + 1);
        Hex1bColor background = context.Theme.Get(EditorTheme.BackgroundColor);
        string backgroundAnsi = background.IsDefault ? string.Empty : background.ToBackgroundAnsi();
        string resetAnsi = backgroundAnsi.Length == 0 ? string.Empty : "\x1b[0m";
        string blankLine = new(' ', viewport.Width);
        for (int viewLine = firstEmptyViewLine; viewLine < viewport.Height; viewLine++)
        {
            context.WriteClipped(
                viewport.X,
                viewport.Y + viewLine,
                string.Concat(backgroundAnsi, blankLine, resetAnsi));
        }
    }

    /// <inheritdoc />
    public DocumentOffset? HitTest(
        int localX,
        int localY,
        EditorState state,
        int viewportColumns,
        int viewportLines,
        int scrollOffset,
        int horizontalScrollOffset)
    {
        return TextEditorViewRenderer.Instance.HitTest(
            localX,
            localY,
            state,
            viewportColumns,
            viewportLines,
            scrollOffset,
            horizontalScrollOffset);
    }

    /// <inheritdoc />
    public int GetTotalLines(IHex1bDocument document, int viewportColumns)
    {
        return TextEditorViewRenderer.Instance.GetTotalLines(document, viewportColumns);
    }

    /// <inheritdoc />
    public int GetMaxLineWidth(
        IHex1bDocument document,
        int scrollOffset,
        int viewportLines,
        int viewportColumns)
    {
        return TextEditorViewRenderer.Instance.GetMaxLineWidth(
            document,
            scrollOffset,
            viewportLines,
            viewportColumns);
    }
}
