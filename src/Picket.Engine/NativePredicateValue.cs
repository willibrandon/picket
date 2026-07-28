namespace Picket.Engine;

internal readonly struct NativePredicateValue
{
    private NativePredicateValue(
        NativePredicateValueKind kind,
        bool boolean,
        double number,
        string? text,
        IReadOnlyList<string>? strings)
    {
        Kind = kind;
        Boolean = boolean;
        Number = number;
        Text = text;
        Strings = strings;
    }

    internal NativePredicateValueKind Kind { get; }

    internal bool Boolean { get; }

    internal double Number { get; }

    internal string? Text { get; }

    internal IReadOnlyList<string>? Strings { get; }

    internal static NativePredicateValue FromBoolean(bool value)
    {
        return new NativePredicateValue(
            NativePredicateValueKind.Boolean,
            value,
            0,
            null,
            null);
    }

    internal static NativePredicateValue FromNumber(double value)
    {
        return new NativePredicateValue(
            NativePredicateValueKind.Number,
            false,
            value,
            null,
            null);
    }

    internal static NativePredicateValue FromString(string value)
    {
        return new NativePredicateValue(
            NativePredicateValueKind.String,
            false,
            0,
            value,
            null);
    }

    internal static NativePredicateValue FromStringList(IReadOnlyList<string> value)
    {
        return new NativePredicateValue(
            NativePredicateValueKind.StringList,
            false,
            0,
            null,
            value);
    }
}
