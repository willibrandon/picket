using Hex1b.Documents;
using Hex1b.Theming;

namespace Picket.Tui;

/// <summary>
/// Colors section headings, metadata labels, severity counts, and validation counts in read-only panes.
/// </summary>
internal sealed class PicketTuiMetadataDecorationProvider : ITextDecorationProvider
{
    private readonly TextDecoration _labelDecoration = new()
    {
        Foreground = PicketTuiPalette.MutedForeground,
    };
    private readonly TextDecoration _sectionDecoration = new()
    {
        Bold = true,
        Foreground = PicketTuiPalette.InfoForeground,
    };

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

            int colon = text.IndexOf(':');
            if (colon < 0)
            {
                if (IsSectionHeading(text))
                {
                    spans.Add(CreateSpan(line, 0, text.Length, _sectionDecoration, priority: 5));
                }

                continue;
            }

            int labelStart = 0;
            while (labelStart < colon && char.IsWhiteSpace(text[labelStart]))
            {
                labelStart++;
            }

            spans.Add(CreateSpan(line, labelStart, colon + 1, _labelDecoration, priority: 5));
            AddSemanticValueDecorations(spans, line, text, colon + 1);
        }

        return spans;
    }

    private static bool IsSectionHeading(string text)
    {
        return text.Equals("Report", StringComparison.Ordinal)
            || text.Equals("Scanner", StringComparison.Ordinal)
            || text.StartsWith("Scanner output", StringComparison.Ordinal);
    }

    private static void AddSemanticValueDecorations(
        List<TextDecorationSpan> spans,
        int line,
        string text,
        int valueStart)
    {
        ReadOnlySpan<char> label = text.AsSpan(0, valueStart);
        if (label.Trim().Equals("Severity:", StringComparison.OrdinalIgnoreCase))
        {
            AddSegments(spans, line, text, valueStart, PicketTuiSemanticColors.GetSeverity);
            return;
        }

        if (label.Trim().Equals("Validation:", StringComparison.OrdinalIgnoreCase))
        {
            AddSegments(spans, line, text, valueStart, PicketTuiSemanticColors.GetValidation);
        }
    }

    private static void AddSegments(
        List<TextDecorationSpan> spans,
        int line,
        string text,
        int valueStart,
        Func<string, Hex1bColor> getColor)
    {
        int segmentStart = valueStart;
        while (segmentStart < text.Length)
        {
            while (segmentStart < text.Length
                && (char.IsWhiteSpace(text[segmentStart]) || text[segmentStart] == '|'))
            {
                segmentStart++;
            }

            if (segmentStart >= text.Length)
            {
                break;
            }

            int separator = text.IndexOf('|', segmentStart);
            int segmentEnd = separator < 0 ? text.Length : separator;
            while (segmentEnd > segmentStart && char.IsWhiteSpace(text[segmentEnd - 1]))
            {
                segmentEnd--;
            }

            string semanticValue = GetSemanticValue(text.AsSpan(segmentStart, segmentEnd - segmentStart));
            var decoration = new TextDecoration
            {
                Foreground = getColor(semanticValue),
            };
            spans.Add(CreateSpan(line, segmentStart, segmentEnd, decoration, priority: 10));
            segmentStart = separator < 0 ? text.Length : separator + 1;
        }
    }

    private static string GetSemanticValue(ReadOnlySpan<char> segment)
    {
        int space = segment.LastIndexOf(' ');
        return space < 0 ? segment.ToString() : segment[(space + 1)..].ToString();
    }

    private static TextDecorationSpan CreateSpan(
        int line,
        int start,
        int end,
        TextDecoration decoration,
        int priority)
    {
        return new TextDecorationSpan(
            new DocumentPosition(line, start + 1),
            new DocumentPosition(line, end + 1),
            decoration,
            priority);
    }
}
