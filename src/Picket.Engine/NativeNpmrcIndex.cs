using System.Text;

namespace Picket.Engine;

/// <summary>
/// Parses bounded npm configuration assignments without interpolation.
/// </summary>
internal sealed class NativeNpmrcIndex
{
    private const int MaxLineLength = 64 * 1024;
    private readonly List<NativeNpmrcProperty> _properties;

    private NativeNpmrcIndex(List<NativeNpmrcProperty> properties)
    {
        _properties = properties;
    }

    internal IReadOnlyList<NativeNpmrcProperty> Properties => _properties;

    internal static NativeNpmrcIndex Create(ReadOnlySpan<byte> input, Func<bool>? isCancellationRequested)
    {
        var properties = new List<NativeNpmrcProperty>();
        int lineStart = 0;
        while (lineStart < input.Length)
        {
            if (IsCancellationRequested(isCancellationRequested))
            {
                break;
            }

            int relativeLineEnd = input[lineStart..].IndexOf((byte)'\n');
            int lineEnd = relativeLineEnd < 0 ? input.Length : lineStart + relativeLineEnd;
            int contentEnd = lineEnd > lineStart && input[lineEnd - 1] == (byte)'\r' ? lineEnd - 1 : lineEnd;
            if (contentEnd - lineStart <= MaxLineLength)
            {
                TryAddProperty(input, lineStart, contentEnd, properties);
            }

            lineStart = lineEnd == input.Length ? input.Length : lineEnd + 1;
        }

        return new NativeNpmrcIndex(properties);
    }

    internal bool HasUsername(string scope)
    {
        for (int i = 0; i < _properties.Count; i++)
        {
            NativeNpmrcProperty property = _properties[i];
            if (property.Scope.Equals(scope, StringComparison.Ordinal)
                && property.Name.Equals("username", StringComparison.OrdinalIgnoreCase)
                && property.Value.Length != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static void TryAddProperty(
        ReadOnlySpan<byte> input,
        int lineStart,
        int lineEnd,
        List<NativeNpmrcProperty> properties)
    {
        int contentStart = lineStart;
        while (contentStart < lineEnd && IsHorizontalWhitespace(input[contentStart]))
        {
            contentStart++;
        }

        if (contentStart >= lineEnd || input[contentStart] is (byte)'#' or (byte)';')
        {
            return;
        }

        int relativeEquals = input[contentStart..lineEnd].IndexOf((byte)'=');
        if (relativeEquals <= 0)
        {
            return;
        }

        int equals = contentStart + relativeEquals;
        int keyEnd = equals;
        while (keyEnd > contentStart && IsHorizontalWhitespace(input[keyEnd - 1]))
        {
            keyEnd--;
        }

        int valueStart = equals + 1;
        while (valueStart < lineEnd && IsHorizontalWhitespace(input[valueStart]))
        {
            valueStart++;
        }

        int valueEnd = lineEnd;
        while (valueEnd > valueStart && IsHorizontalWhitespace(input[valueEnd - 1]))
        {
            valueEnd--;
        }

        if (valueEnd - valueStart >= 2
            && input[valueStart] is (byte)'\'' or (byte)'"'
            && input[valueEnd - 1] == input[valueStart])
        {
            valueStart++;
            valueEnd--;
        }

        if (valueStart >= valueEnd)
        {
            return;
        }

        string key = Encoding.UTF8.GetString(input[contentStart..keyEnd]);
        SplitKey(key, out string scope, out string name);
        properties.Add(new NativeNpmrcProperty(
            scope,
            name,
            Encoding.UTF8.GetString(input[valueStart..valueEnd]),
            valueStart,
            valueEnd));
    }

    private static void SplitKey(string key, out string scope, out string name)
    {
        int separator = key.LastIndexOf(':');
        if (separator < 0)
        {
            scope = string.Empty;
            name = key;
            return;
        }

        scope = key[..(separator + 1)];
        name = key[(separator + 1)..];
    }

    private static bool IsHorizontalWhitespace(byte value)
    {
        return value is (byte)' ' or (byte)'\t';
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }
}
