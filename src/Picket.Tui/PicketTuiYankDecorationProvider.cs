using Hex1b.Documents;

namespace Picket.Tui;

/// <summary>
/// Provides a short highlight over text yanked from a read-only editor pane.
/// </summary>
internal sealed class PicketTuiYankDecorationProvider : ITextDecorationProvider
{
    private static readonly TextDecoration s_yankDecoration = new()
    {
        Background = PicketTuiPalette.YankFlashBackground,
        Foreground = PicketTuiPalette.YankFlashForeground,
    };

    /// <summary>
    /// Gets or sets the highlighted range.
    /// </summary>
    internal (DocumentPosition Start, DocumentPosition End)? HighlightRange { get; set; }

    /// <inheritdoc />
    public IReadOnlyList<TextDecorationSpan> GetDecorations(
        int startLine,
        int endLine,
        IHex1bDocument document)
    {
        if (HighlightRange is not { } range)
        {
            return [];
        }

        if (range.End.Line < startLine || range.Start.Line > endLine)
        {
            return [];
        }

        int firstLine = Math.Max(range.Start.Line, startLine);
        int lastLine = Math.Min(Math.Min(range.End.Line, endLine), document.LineCount);
        if (firstLine > lastLine)
        {
            return [];
        }

        var spans = new List<TextDecorationSpan>(lastLine - firstLine + 1);

        for (int line = firstLine; line <= lastLine; line++)
        {
            int lineEndColumn = document.GetLineLength(line) + 1;
            int spanStartColumn = line == range.Start.Line
                ? Math.Min(range.Start.Column, lineEndColumn)
                : 1;
            int spanEndColumn = line == range.End.Line
                ? Math.Min(range.End.Column, lineEndColumn)
                : lineEndColumn;

            if (spanStartColumn >= spanEndColumn)
            {
                continue;
            }

            spans.Add(new TextDecorationSpan(
                new DocumentPosition(line, spanStartColumn),
                new DocumentPosition(line, spanEndColumn),
                s_yankDecoration,
                Priority: 30));
        }

        return spans;
    }
}
