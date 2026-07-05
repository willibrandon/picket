using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledAllowlist(SecretAllowlist allowlist)
{
    internal SecretAllowlist Allowlist { get; } = allowlist ?? throw new ArgumentNullException(nameof(allowlist));

    internal List<ByteRegex> PathRegexes { get; } = CompileRegexes(allowlist.PathPatterns);

    internal List<ByteRegex> Regexes { get; } = CompileRegexes(allowlist.RegexPatterns);

    internal static List<CompiledAllowlist> Compile(IReadOnlyList<SecretAllowlist> allowlists)
    {
        ArgumentNullException.ThrowIfNull(allowlists);

        var compiled = new List<CompiledAllowlist>(allowlists.Count);
        foreach (SecretAllowlist allowlist in allowlists)
        {
            compiled.Add(new CompiledAllowlist(allowlist));
        }

        return compiled;
    }

    private static List<ByteRegex> CompileRegexes(IReadOnlyList<string> patterns)
    {
        var regexes = new List<ByteRegex>(patterns.Count);
        foreach (string pattern in patterns)
        {
            regexes.Add(ByteRegex.Compile(pattern));
        }

        return regexes;
    }
}
