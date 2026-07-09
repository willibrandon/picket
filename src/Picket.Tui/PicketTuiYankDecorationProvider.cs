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

        return [new TextDecorationSpan(range.Start, range.End, s_yankDecoration, Priority: 30)];
    }
}
