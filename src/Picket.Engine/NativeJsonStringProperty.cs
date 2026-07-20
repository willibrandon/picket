namespace Picket.Engine;

/// <summary>
/// Represents an indexed JSON string property and its source span.
/// </summary>
internal sealed class NativeJsonStringProperty(
    string name,
    string value,
    int valueStart,
    int valueEnd,
    int objectId,
    string[] path,
    bool valueIsEscaped)
{
    internal string Name { get; } = name;

    internal string Value { get; } = value;

    internal int ValueStart { get; } = valueStart;

    internal int ValueEnd { get; } = valueEnd;

    internal int ObjectId { get; } = objectId;

    internal string[] Path { get; } = path;

    internal bool ValueIsEscaped { get; } = valueIsEscaped;
}
