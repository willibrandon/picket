namespace Picket.Engine;

/// <summary>
/// Describes a structured detector match in the current scan-pass input.
/// </summary>
internal readonly struct NativeDetectorMatch(
    int matchStart,
    int matchEnd,
    int secretStart,
    int secretEnd,
    string matchText,
    string secretText,
    IReadOnlyList<string>? tags = null,
    IReadOnlyList<string>? decodePath = null)
{
    internal int MatchStart { get; } = matchStart;

    internal int MatchEnd { get; } = matchEnd;

    internal int SecretStart { get; } = secretStart;

    internal int SecretEnd { get; } = secretEnd;

    internal string MatchText { get; } = matchText ?? throw new ArgumentNullException(nameof(matchText));

    internal string SecretText { get; } = secretText ?? throw new ArgumentNullException(nameof(secretText));

    internal IReadOnlyList<string> Tags { get; } = tags ?? [];

    internal IReadOnlyList<string> DecodePath { get; } = decodePath ?? [];
}
