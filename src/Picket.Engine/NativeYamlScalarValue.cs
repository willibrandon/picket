namespace Picket.Engine;

/// <summary>
/// Represents one scalar mapping value and its UTF-8 source span.
/// </summary>
internal sealed class NativeYamlScalarValue(
    string key,
    string value,
    int valueStart,
    int valueEnd,
    bool valueIsTransformed)
{
    internal string Key { get; } = key;

    internal string Value { get; } = value;

    internal int ValueStart { get; } = valueStart;

    internal int ValueEnd { get; } = valueEnd;

    internal bool ValueIsTransformed { get; } = valueIsTransformed;
}
