using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledRule(SecretRule rule, ByteRegex? regex, ByteRegex? pathRegex, KeywordPrefilter prefilter)
{
    internal SecretRule Rule { get; } = rule ?? throw new ArgumentNullException(nameof(rule));

    internal ByteRegex? Regex { get; } = regex;

    internal ByteRegex? PathRegex { get; } = pathRegex;

    internal KeywordPrefilter Prefilter { get; } = prefilter ?? throw new ArgumentNullException(nameof(prefilter));
}
