using Picket.Rules;
using Scout.Text.Regex;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Engine;

/// <summary>
/// Represents a rule set with precompiled Scout regexes and keyword prefilters.
/// </summary>
/// <param name="rules">The source rules in deterministic evaluation order.</param>
public sealed class CompiledRuleSet(RuleSet rules)
{
    private const string LowerHex = "0123456789abcdef";
    private readonly Dictionary<string, double>? _randomnessThresholds = CreateRandomnessThresholds(rules);

    /// <summary>
    /// Gets the source rules in deterministic evaluation order.
    /// </summary>
    public IReadOnlyList<SecretRule> Rules { get; } = RequireRules(rules).Rules;

    /// <summary>
    /// Gets a stable fingerprint for the rules, allowlists, and rule compilation inputs.
    /// </summary>
    public string Fingerprint { get; } = CreateFingerprint(rules);

    /// <summary>
    /// Gets a value indicating whether rule evaluation can depend on the logical source path.
    /// </summary>
    public bool UsesPathSensitiveMatching { get; } = CreateUsesPathSensitiveMatching(rules);

    internal List<CompiledRule> CompiledRules { get; } = CompileRules(rules);

    internal List<CompiledAllowlist> Allowlists { get; } = CompiledAllowlist.Compile(
        rules.Allowlists,
        rules.RegexesPrevalidated,
        "[[allowlists]]");

    internal bool HasRandomnessThresholds => _randomnessThresholds is not null;

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

    internal bool TryGetRandomnessThreshold(string ruleId, out double threshold)
    {
        if (_randomnessThresholds is null)
        {
            threshold = 0;
            return false;
        }

        return _randomnessThresholds.TryGetValue(ruleId, out threshold);
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
            bool usesAwsCredentialPairMatcher = AwsCredentialPairMatcher.CanHandle(rule);
            bool usesGenericApiKeyMatcher = GenericApiKeyMatcher.CanHandle(rule);
            bool usesGcpServiceAccountKeyMatcher = GcpServiceAccountKeyMatcher.CanHandle(rule);
            bool deferRegexCompilation = rules.RegexesPrevalidated;
            string regexContext = $"{rule.Id}: invalid regex";
            string pathRegexContext = $"{rule.Id}: invalid path";
            compiledRules.Add(new CompiledRule(
                rule,
                usesAwsCredentialPairMatcher || usesGenericApiKeyMatcher || usesGcpServiceAccountKeyMatcher || deferRegexCompilation ? null : CompileOptionalRegex(rule.Pattern, regexContext),
                deferRegexCompilation ? null : CompileOptionalRegex(rule.PathPattern, pathRegexContext),
                CompiledAllowlist.Compile(rule.Allowlists, deferRegexCompilation, $"{rule.Id}: [[rules.allowlists]]"),
                KeywordPrefilter.Create(rule.Keywords),
                usesAwsCredentialPairMatcher,
                usesGenericApiKeyMatcher,
                usesGcpServiceAccountKeyMatcher,
                appliesGlobalAllowlists: !IsPicketNativeRulePack(rule.RulePack),
                deferRegexCompilation,
                regexContext,
                pathRegexContext));
        }

        return compiledRules;
    }

    private static Dictionary<string, double>? CreateRandomnessThresholds(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        Dictionary<string, double>? thresholds = null;
        for (int i = 0; i < rules.Rules.Count; i++)
        {
            SecretRule rule = rules.Rules[i];
            if (rule.RandomnessThreshold == 0)
            {
                continue;
            }

            thresholds ??= new Dictionary<string, double>(StringComparer.Ordinal);
            thresholds.TryAdd(rule.Id, rule.RandomnessThreshold);
        }

        return thresholds;
    }

    private static bool IsPicketNativeRulePack(string rulePack)
    {
        return rulePack.StartsWith("picket-", StringComparison.Ordinal);
    }

    private static bool CreateUsesPathSensitiveMatching(RuleSet rules)
    {
        if (HasPathAllowlist(rules.Allowlists))
        {
            return true;
        }

        foreach (SecretRule rule in rules.Rules)
        {
            if (rule.PathPattern.Length != 0 || HasPathAllowlist(rule.Allowlists))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasPathAllowlist(IReadOnlyList<SecretAllowlist> allowlists)
    {
        foreach (SecretAllowlist allowlist in allowlists)
        {
            if (allowlist.PathPatterns.Count != 0)
            {
                return true;
            }
        }

        return false;
    }

    private static string CreateFingerprint(RuleSet rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var builder = new StringBuilder();
        AppendValue(builder, "picket.ruleset.v1");
        AppendValue(builder, rules.RegexesPrevalidated ? "prevalidated" : "compile");
        AppendAllowlists(builder, rules.Allowlists);
        for (int i = 0; i < rules.Rules.Count; i++)
        {
            SecretRule rule = rules.Rules[i];
            AppendValue(builder, rule.Id);
            AppendValue(builder, rule.Description);
            AppendValue(builder, rule.Pattern);
            AppendValue(builder, rule.SecretGroup.ToString(CultureInfo.InvariantCulture));
            AppendValue(builder, rule.Entropy.ToString("G17", CultureInfo.InvariantCulture));
            AppendValue(builder, rule.RandomnessThreshold.ToString("G17", CultureInfo.InvariantCulture));
            AppendValue(builder, rule.PathPattern);
            AppendValues(builder, rule.Keywords);
            AppendValues(builder, rule.Tags);
            AppendValue(builder, rule.SkipReport ? "true" : "false");
            AppendValue(builder, rule.Severity);
            AppendValue(builder, rule.Confidence);
            AppendValue(builder, rule.RulePack);
            AppendValue(builder, rule.Provider);
            AppendValue(builder, rule.DocumentationUrl);
            AppendValues(builder, rule.Validation);
            AppendValues(builder, rule.Revocation);
            AppendValue(builder, rule.Deprecated ? "true" : "false");
            AppendValues(builder, rule.Examples);
            AppendValues(builder, rule.NegativeExamples);
            AppendAllowlists(builder, rule.Allowlists);
            AppendRequiredRules(builder, rule.RequiredRules);
        }

        return ComputeSha256Hex(builder.ToString());
    }

    private static void AppendAllowlists(StringBuilder builder, IReadOnlyList<SecretAllowlist> allowlists)
    {
        AppendValue(builder, allowlists.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < allowlists.Count; i++)
        {
            SecretAllowlist allowlist = allowlists[i];
            AppendValue(builder, allowlist.Description);
            AppendValue(builder, allowlist.Condition.ToString());
            AppendValues(builder, allowlist.Commits);
            AppendValues(builder, allowlist.PathPatterns);
            AppendValue(builder, allowlist.RegexTarget.ToString());
            AppendValues(builder, allowlist.RegexPatterns);
            AppendValues(builder, allowlist.StopWords);
        }
    }

    private static void AppendRequiredRules(StringBuilder builder, IReadOnlyList<SecretRequiredRule> requiredRules)
    {
        AppendValue(builder, requiredRules.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < requiredRules.Count; i++)
        {
            SecretRequiredRule requiredRule = requiredRules[i];
            AppendValue(builder, requiredRule.Id);
            AppendValue(builder, requiredRule.WithinLines?.ToString(CultureInfo.InvariantCulture) ?? string.Empty);
            AppendValue(builder, requiredRule.WithinColumns?.ToString(CultureInfo.InvariantCulture) ?? string.Empty);
        }
    }

    private static void AppendValues(StringBuilder builder, IReadOnlyList<string> values)
    {
        AppendValue(builder, values.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < values.Count; i++)
        {
            AppendValue(builder, values[i]);
        }
    }

    private static void AppendValue(StringBuilder builder, string value)
    {
        builder.Append(value.Length.ToString(CultureInfo.InvariantCulture));
        builder.Append(':');
        builder.Append(value);
        builder.Append(';');
    }

    private static string ComputeSha256Hex(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return string.Create(hash.Length * 2, hash, static (chars, bytes) =>
        {
            for (int i = 0; i < bytes.Length; i++)
            {
                byte value = bytes[i];
                chars[i * 2] = LowerHex[value >> 4];
                chars[(i * 2) + 1] = LowerHex[value & 0x0F];
            }
        });
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
