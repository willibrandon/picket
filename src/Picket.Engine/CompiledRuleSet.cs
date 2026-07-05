using System.Text;
using Picket.Rules;
using Scout.Text.Regex;

namespace Picket.Engine;

/// <summary>
/// Represents a rule set with precompiled Scout regexes and keyword prefilters.
/// </summary>
/// <param name="rules">The source rules in deterministic evaluation order.</param>
public sealed class CompiledRuleSet(RuleSet rules)
{
    /// <summary>
    /// Gets the source rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = RequireRules(rules).Rules;

    internal List<CompiledRule> CompiledRules { get; } = CompileRules(rules);

    internal List<CompiledAllowlist> Allowlists { get; } = CompiledAllowlist.Compile(
        rules.Allowlists,
        rules.RegexesPrevalidated,
        "[[allowlists]]");

    /// <summary>
    /// Returns a value indicating whether a global Gitleaks path allowlist matches the supplied path.
    /// </summary>
    /// <param name="path">The normalized source path to test.</param>
    /// <returns><see langword="true" /> when any global path allowlist matches the path.</returns>
    public bool IsGlobalPathAllowed(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        byte[] pathBytes = Encoding.UTF8.GetBytes(path);
        if (AnyPathRegexMatches(pathBytes))
        {
            return true;
        }

        byte[] windowsPathBytes = CreateWindowsPathBytes(path);
        return windowsPathBytes.Length != 0 && AnyPathRegexMatches(windowsPathBytes);
    }

    /// <summary>
    /// Compiles a source rule set.
    /// </summary>
    /// <param name="rules">The source rules in deterministic evaluation order.</param>
    /// <returns>The compiled rule set.</returns>
    public static CompiledRuleSet Compile(RuleSet rules)
    {
        return new CompiledRuleSet(rules);
    }

    private static RuleSet RequireRules(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        return rules;
    }

    private static List<CompiledRule> CompileRules(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var compiledRules = new List<CompiledRule>(rules.Rules.Count);
        foreach (SecretRule rule in rules.Rules)
        {
            bool usesGenericApiKeyMatcher = GenericApiKeyMatcher.CanHandle(rule);
            bool deferRegexCompilation = rules.RegexesPrevalidated;
            string regexContext = $"{rule.Id}: invalid regex";
            string pathRegexContext = $"{rule.Id}: invalid path";
            compiledRules.Add(new CompiledRule(
                rule,
                usesGenericApiKeyMatcher || deferRegexCompilation ? null : CompileOptionalRegex(rule.Pattern, regexContext),
                deferRegexCompilation ? null : CompileOptionalRegex(rule.PathPattern, pathRegexContext),
                CompiledAllowlist.Compile(rule.Allowlists, deferRegexCompilation, $"{rule.Id}: [[rules.allowlists]]"),
                KeywordPrefilter.Create(rule.Keywords),
                usesGenericApiKeyMatcher,
                deferRegexCompilation,
                regexContext,
                pathRegexContext));
        }

        return compiledRules;
    }

    private static ByteRegex? CompileOptionalRegex(string pattern, string context)
    {
        if (pattern.Length == 0)
        {
            return null;
        }

        try
        {
            return ByteRegex.Compile(pattern);
        }
        catch (ByteRegexParseException exception)
        {
            throw new InvalidDataException($"{context} pattern '{pattern}': {exception.Message}", exception);
        }
    }

    private bool AnyPathRegexMatches(ReadOnlySpan<byte> pathBytes)
    {
        foreach (CompiledAllowlist allowlist in Allowlists)
        {
            foreach (ByteRegex regex in allowlist.PathRegexes)
            {
                if (regex.FindCaptures(pathBytes, 0) is not null)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static byte[] CreateWindowsPathBytes(string path)
    {
        return path.Contains('/')
            ? Encoding.UTF8.GetBytes(path.Replace('/', '\\'))
            : [];
    }
}
