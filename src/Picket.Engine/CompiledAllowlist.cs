using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

internal sealed class CompiledAllowlist(SecretAllowlist allowlist, bool deferRegexCompilation, string context)
{
    private readonly Lock _regexCompilationLock = new();
    private List<ByteRegex>? _pathRegexes = deferRegexCompilation ? null : CompileRegexes(allowlist.PathPatterns, context, "path");
    private List<ByteRegex>? _regexes = deferRegexCompilation ? null : CompileRegexes(allowlist.RegexPatterns, context, "regex");

    internal SecretAllowlist Allowlist { get; } = allowlist ?? throw new ArgumentNullException(nameof(allowlist));

    internal List<ByteRegex> PathRegexes => GetRegexes(ref _pathRegexes, Allowlist.PathPatterns, context, "path");

    internal List<ByteRegex> Regexes => GetRegexes(ref _regexes, Allowlist.RegexPatterns, context, "regex");

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

    private List<ByteRegex> GetRegexes(
        ref List<ByteRegex>? regexes,
        IReadOnlyList<string> patterns,
        string regexContext,
        string kind)
    {
        List<ByteRegex>? compiledRegexes = Volatile.Read(ref regexes);
        if (compiledRegexes is not null)
        {
            return compiledRegexes;
        }

        lock (_regexCompilationLock)
        {
            compiledRegexes = regexes;
            if (compiledRegexes is null)
            {
                compiledRegexes = CompileRegexes(patterns, regexContext, kind);
                Volatile.Write(ref regexes, compiledRegexes);
            }
        }

        return compiledRegexes;
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
