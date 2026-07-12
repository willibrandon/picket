using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledAllowlist(SecretAllowlist allowlist, bool deferRegexCompilation, string context)
{
    private List<ByteRegex>? _pathRegexes = deferRegexCompilation ? null : CompileRegexes(allowlist.PathPatterns, context, "path");
    private List<ByteRegex>? _regexes = deferRegexCompilation ? null : CompileRegexes(allowlist.RegexPatterns, context, "regex");

    internal SecretAllowlist Allowlist { get; } = allowlist ?? throw new ArgumentNullException(nameof(allowlist));

    internal List<ByteRegex> PathRegexes => _pathRegexes ??= CompileRegexes(Allowlist.PathPatterns, context, "path");

    internal List<ByteRegex> Regexes => _regexes ??= CompileRegexes(Allowlist.RegexPatterns, context, "regex");

    internal static List<CompiledAllowlist> Compile(IReadOnlyList<SecretAllowlist> allowlists, bool deferRegexCompilation, string context)
    {
        ArgumentNullException.ThrowIfNull(allowlists);

        var compiled = new List<CompiledAllowlist>(allowlists.Count);
        foreach (SecretAllowlist allowlist in allowlists)
        {
            compiled.Add(new CompiledAllowlist(allowlist, deferRegexCompilation, context));
        }

        return compiled;
    }

    private static List<ByteRegex> CompileRegexes(IReadOnlyList<string> patterns, string context, string kind)
    {
        var regexes = new List<ByteRegex>(patterns.Count);
        foreach (string pattern in patterns)
        {
            try
            {
                regexes.Add(GitleaksRegexCompiler.Compile(pattern));
            }
            catch (ByteRegexParseException exception)
            {
                throw new InvalidDataException($"{context}: invalid allowlist {kind} pattern '{pattern}': {exception.Message}", exception);
            }
        }

        return regexes;
    }
}
