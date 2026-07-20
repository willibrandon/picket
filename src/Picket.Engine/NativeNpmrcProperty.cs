namespace Picket.Engine;

/// <summary>
/// Represents one bounded npm configuration assignment.
/// </summary>
internal sealed class NativeNpmrcProperty(
    string scope,
    string name,
    string value,
    int valueStart,
    int valueEnd)
{
    internal string Scope { get; } = scope;

    internal string Name { get; } = name;

    internal string Value { get; } = value;

    internal int ValueStart { get; } = valueStart;

    internal int ValueEnd { get; } = valueEnd;
}
