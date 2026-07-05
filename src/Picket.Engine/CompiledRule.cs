using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledRule(
    SecretRule rule,
    ByteRegex? regex,
    ByteRegex? pathRegex,
    List<CompiledAllowlist> allowlists,
    KeywordPrefilter prefilter,
    bool usesGenericApiKeyMatcher,
    bool deferRegexCompilation,
    string regexContext,
    string pathRegexContext)
{
    private readonly string _pattern = rule.Pattern;
    private readonly string _pathPattern = rule.PathPattern;
    private readonly bool _deferRegexCompilation = deferRegexCompilation;
    private ByteRegex? _regex = regex;
    private ByteRegex? _pathRegex = pathRegex;

    internal SecretRule Rule { get; } = rule ?? throw new ArgumentNullException(nameof(rule));

    internal ByteRegex? Regex => UsesGenericApiKeyMatcher ? null : GetRegex(ref _regex, _pattern, regexContext);

    internal ByteRegex? PathRegex => GetRegex(ref _pathRegex, _pathPattern, pathRegexContext);

    internal bool HasContentPattern => _pattern.Length != 0 || UsesGenericApiKeyMatcher;

    internal List<CompiledAllowlist> Allowlists { get; } = allowlists ?? throw new ArgumentNullException(nameof(allowlists));

    internal KeywordPrefilter Prefilter { get; } = prefilter ?? throw new ArgumentNullException(nameof(prefilter));

    internal bool UsesGenericApiKeyMatcher { get; } = usesGenericApiKeyMatcher;

    private ByteRegex? GetRegex(ref ByteRegex? regex, string pattern, string context)
    {
        if (pattern.Length == 0)
        {
            return null;
        }

        if (regex is not null || !_deferRegexCompilation)
        {
            return regex;
        }

        try
        {
            regex = ByteRegex.Compile(pattern);
        }
        catch (ByteRegexParseException exception)
        {
            throw new InvalidDataException($"{context} pattern '{pattern}': {exception.Message}", exception);
        }

        return regex;
    }
}
