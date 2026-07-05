using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledRule(SecretRule rule, ByteRegex regex, KeywordPrefilter prefilter)
{
    internal SecretRule Rule { get; } = rule ?? throw new ArgumentNullException(nameof(rule));

    internal ByteRegex Regex { get; } = regex ?? throw new ArgumentNullException(nameof(regex));

    internal KeywordPrefilter Prefilter { get; } = prefilter ?? throw new ArgumentNullException(nameof(prefilter));
}
