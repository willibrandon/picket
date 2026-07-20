using Scout.Text.Regex;
using System.Text;

namespace Picket.Engine;

internal static class GitleaksRegexCompiler
{
    internal const string DialectVersion = "gitleaks-go-regexp-v2";

    private const string AsciiDigitClass = "[0-9]";
    private const string AsciiDigitClassContent = "0-9";
    private const string AsciiNotDigitClass = "[\\x{0}-\\x{2f}\\x{3a}-\\x{10ffff}]";
    private const string AsciiNotDigitClassContent = "\\x{0}-\\x{2f}\\x{3a}-\\x{10ffff}";
    private const string AsciiNotWhitespaceClass = "[\\x{0}-\\x{8}\\x{b}\\x{e}-\\x{1f}\\x{21}-\\x{10ffff}]";
    private const string AsciiNotWhitespaceClassContent = "\\x{0}-\\x{8}\\x{b}\\x{e}-\\x{1f}\\x{21}-\\x{10ffff}";
    private const string AsciiNotWordClass = "[\\x{0}-\\x{2f}\\x{3a}-\\x{40}\\x{5b}-\\x{5e}\\x{60}\\x{7b}-\\x{10ffff}]";
    private const string AsciiNotWordClassContent = "\\x{0}-\\x{2f}\\x{3a}-\\x{40}\\x{5b}-\\x{5e}\\x{60}\\x{7b}-\\x{10ffff}";
    private const string AsciiWhitespaceClass = "[\\t\\n\\f\\r ]";
    private const string AsciiWhitespaceClassContent = "\\t\\n\\f\\r ";
    private const string AsciiWordBoundary = "(?u:\\b|\\B)(?-u:\\b)";
    private const string AsciiNotWordBoundary = "(?u:\\b|\\B)(?-u:\\B)";
    private const string AsciiWordClass = "[0-9A-Z_a-z]";
    private const string AsciiWordClassContent = "0-9A-Z_a-z";

    private static readonly ByteRegexOptions s_options = new()
    {
        EngineMode = ByteRegexEngineMode.General,
    };

    internal static ByteRegex Compile(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);

        return ByteRegex.Compile(TranslatePattern(pattern), s_options);
    }

    private static string TranslatePattern(string pattern)
    {
        StringBuilder? builder = null;
        int copyStart = 0;
        bool inClass = false;
        int classElementCount = 0;
        for (int index = 0; index < pattern.Length; index++)
        {
            char value = pattern[index];
            if (value == '\\' && index + 1 < pattern.Length)
            {
                string? replacement = GetReplacement(pattern[index + 1], inClass);
                if (replacement is not null)
                {
                    builder ??= new StringBuilder(pattern.Length + 32);
                    builder.Append(pattern, copyStart, index - copyStart);
                    builder.Append(replacement);
                    index++;
                    copyStart = index + 1;
                    if (inClass)
                    {
                        classElementCount++;
                    }

                    continue;
                }

                if (IsBracedEscape(pattern, index))
                {
                    index += 2;
                    if (inClass)
                    {
                        classElementCount++;
                    }

                    continue;
                }

                index++;
                if (inClass)
                {
                    classElementCount++;
                }

                continue;
            }

            if (!inClass && value == '{' && !IsCountedRepetition(pattern, index))
            {
                builder ??= new StringBuilder(pattern.Length + 32);
                builder.Append(pattern, copyStart, index - copyStart);
                builder.Append(@"\{");
                copyStart = index + 1;
                continue;
            }

            if (!inClass)
            {
                inClass = value == '[';
                if (inClass)
                {
                    classElementCount = 0;
                }

                continue;
            }

            if (value == '^' && classElementCount == 0)
            {
                continue;
            }

            if (value == '[' &&
                index + 1 < pattern.Length &&
                pattern[index + 1] == ':' &&
                TryFindPosixClassEnd(pattern, index + 2, out int posixClassEnd))
            {
                index = posixClassEnd;
                classElementCount++;
                continue;
            }

            if (value == ']' && classElementCount != 0)
            {
                inClass = false;
                continue;
            }


            classElementCount++;
        }

        if (builder is null)
        {
            return pattern;
        }

        builder.Append(pattern, copyStart, pattern.Length - copyStart);
        return builder.ToString();
    }

    private static bool IsCountedRepetition(string pattern, int start)
    {
        int index = start + 1;
        if (!TrySkipRepeatCount(pattern, ref index) || index >= pattern.Length)
        {
            return false;
        }

        if (pattern[index] == '}')
        {
            return true;
        }

        if (pattern[index] != ',')
        {
            return false;
        }

        index++;
        if (index >= pattern.Length)
        {
            return false;
        }

        if (pattern[index] == '}')
        {
            return true;
        }

        return TrySkipRepeatCount(pattern, ref index) &&
            index < pattern.Length &&
            pattern[index] == '}';
    }

    private static bool TrySkipRepeatCount(string pattern, ref int index)
    {
        if (index >= pattern.Length || !IsAsciiDigit(pattern[index]))
        {
            return false;
        }

        if (pattern[index] == '0' &&
            index + 1 < pattern.Length &&
            IsAsciiDigit(pattern[index + 1]))
        {
            return false;
        }

        do
        {
            index++;
        }
        while (index < pattern.Length && IsAsciiDigit(pattern[index]));

        return true;
    }

    private static bool IsAsciiDigit(char value) => value is >= '0' and <= '9';

    private static bool IsBracedEscape(string pattern, int escapeStart) =>
        escapeStart + 2 < pattern.Length &&
        pattern[escapeStart + 1] is 'p' or 'P' or 'x' &&
        pattern[escapeStart + 2] == '{';

    private static string? GetReplacement(char escaped, bool inClass)
    {
        if (inClass)
        {
            return escaped switch
            {
                'd' => AsciiDigitClassContent,
                'D' => AsciiNotDigitClassContent,
                's' => AsciiWhitespaceClassContent,
                'S' => AsciiNotWhitespaceClassContent,
                'w' => AsciiWordClassContent,
                'W' => AsciiNotWordClassContent,
                _ => null,
            };
        }

        return escaped switch
        {
            'b' => AsciiWordBoundary,
            'B' => AsciiNotWordBoundary,
            'd' => AsciiDigitClass,
            'D' => AsciiNotDigitClass,
            's' => AsciiWhitespaceClass,
            'S' => AsciiNotWhitespaceClass,
            'w' => AsciiWordClass,
            'W' => AsciiNotWordClass,
            _ => null,
        };
    }

    private static bool TryFindPosixClassEnd(string pattern, int start, out int end)
    {
        for (int index = start; index + 1 < pattern.Length; index++)
        {
            if (pattern[index] == ':' && pattern[index + 1] == ']')
            {
                end = index + 1;
                return true;
            }
        }

        end = -1;
        return false;
    }
}
