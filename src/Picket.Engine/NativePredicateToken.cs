namespace Picket.Engine;

internal readonly struct NativePredicateToken(
    NativePredicateTokenKind kind,
    string text,
    int position)
{
    internal NativePredicateTokenKind Kind { get; } = kind;

    internal string Text { get; } = text;

    internal int Position { get; } = position;
}
