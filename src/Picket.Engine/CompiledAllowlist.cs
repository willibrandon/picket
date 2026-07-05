using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledAllowlist(SecretAllowlist allowlist, bool deferRegexCompilation)
{
    private List<ByteRegex>? _pathRegexes = deferRegexCompilation ? null : CompileRegexes(allowlist.PathPatterns);
    private List<ByteRegex>? _regexes = deferRegexCompilation ? null : CompileRegexes(allowlist.RegexPatterns);

    internal SecretAllowlist Allowlist { get; } = allowlist ?? throw new ArgumentNullException(nameof(allowlist));

    internal List<ByteRegex> PathRegexes => _pathRegexes ??= CompileRegexes(Allowlist.PathPatterns);

    internal List<ByteRegex> Regexes => _regexes ??= CompileRegexes(Allowlist.RegexPatterns);

    internal static List<CompiledAllowlist> Compile(IReadOnlyList<SecretAllowlist> allowlists, bool deferRegexCompilation)
    {
        ArgumentNullException.ThrowIfNull(allowlists);

        var compiled = new List<CompiledAllowlist>(allowlists.Count);
        foreach (SecretAllowlist allowlist in allowlists)
        {
            compiled.Add(new CompiledAllowlist(allowlist, deferRegexCompilation));
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
