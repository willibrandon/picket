using Hex1b.Documents;

namespace Picket.Tui;

/// <summary>
/// Colors scanner warnings and errors and highlights active log-search matches.
/// </summary>
internal sealed class PicketTuiLogDecorationProvider : ITextDecorationProvider
{
    private static readonly string[] s_errorTerms = ["error", "failed", "fatal", "exception"];
    private static readonly string[] s_warningTerms = ["warning", "warn", "limit reached", "skipped"];

    private readonly TextDecoration _errorDecoration = new()
    {
        Foreground = PicketTuiPalette.ErrorForeground,
    };
    private readonly TextDecoration _searchDecoration = new()
    {
        Background = PicketTuiPalette.EditorSelectionBackground,
        Foreground = PicketTuiPalette.FocusedRowForeground,
    };
    private readonly TextDecoration _warningDecoration = new()
    {
        Foreground = PicketTuiPalette.WarningForeground,
    };

    /// <summary>
    /// Gets or sets the case-insensitive search query to highlight.
    /// </summary>
    internal string Query { get; set; } = string.Empty;

    /// <inheritdoc />
    public IReadOnlyList<TextDecorationSpan> GetDecorations(
        int startLine,
        int endLine,
        IHex1bDocument document)
    {
        var spans = new List<TextDecorationSpan>();
        for (int line = startLine; line <= endLine && line <= document.LineCount; line++)
        {
            string text = document.GetLineText(line);
            if (text.Length == 0)
            {
                continue;
            }

            TextDecoration? levelDecoration = GetLevelDecoration(text);
            if (levelDecoration is not null)
            {
                spans.Add(new TextDecorationSpan(
                    new DocumentPosition(line, 1),
                    new DocumentPosition(line, text.Length + 1),
                    levelDecoration,
                    Priority: 10));
            }

            AddSearchDecorations(spans, line, text);
        }

        return spans;
    }

    private TextDecoration? GetLevelDecoration(string text)
    {
        if (ContainsAny(text, s_errorTerms))
        {
            return _errorDecoration;
        }

        return ContainsAny(text, s_warningTerms)
            ? _warningDecoration
            : null;
    }

    private void AddSearchDecorations(List<TextDecorationSpan> spans, int line, string text)
    {
        if (Query.Length == 0)
        {
            return;
        }

        int searchIndex = 0;
        while (searchIndex < text.Length)
        {
            int matchIndex = text.IndexOf(Query, searchIndex, StringComparison.OrdinalIgnoreCase);
            if (matchIndex < 0)
            {
                break;
            }

            spans.Add(new TextDecorationSpan(
                new DocumentPosition(line, matchIndex + 1),
                new DocumentPosition(line, matchIndex + Query.Length + 1),
                _searchDecoration,
                Priority: 20));
            searchIndex = matchIndex + Query.Length;
        }
    }

    private static bool ContainsAny(string text, ReadOnlySpan<string> candidates)
    {
        for (int i = 0; i < candidates.Length; i++)
        {
            if (text.Contains(candidates[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
