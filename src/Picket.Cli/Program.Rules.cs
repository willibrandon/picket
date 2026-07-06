using System.Text;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static int RunRules(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteRulesHelp();
            return 0;
        }

        string subcommand = args[0];
        if (subcommand.Equals("check", StringComparison.OrdinalIgnoreCase))
        {
            return RunRulesCheck(args[1..]);
        }

        if (subcommand.Equals("test", StringComparison.OrdinalIgnoreCase))
        {
            return RunRulesTest(args[1..]);
        }

        Console.Error.WriteLine($"unknown rules command: {subcommand}");
        return UnknownFlagExitCode;
    }

    static int RunRulesCheck(string[] args)
    {
        if (!TryResolveNativeProfile(args, defaultNativeProfile: true, out bool nativeMode))
        {
            return UnknownFlagExitCode;
        }

        string? configPath = null;
        string source = ".";
        bool printConfig = false;
        bool sourceSet = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteRulesCheckHelp();
                return 0;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsProfileFlag(arg))
            {
                if (!TryReadProfileFlag(args, ref i, out _))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsPrintConfigFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--print-config", out printConfig))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }

            if (sourceSet)
            {
                Console.Error.WriteLine($"unexpected argument: {arg}");
                return UnknownFlagExitCode;
            }

            source = arg;
            sourceSet = true;
        }

        try
        {
            RuleSet ruleSet = nativeMode
                ? PicketConfigLoader.LoadRuleSet(configPath, source)
                : GitleaksConfigLoader.LoadRuleSet(configPath, source);
            ValidateRulesWithScout(ruleSet);
            if (printConfig)
            {
                Console.Out.Write(GitleaksConfigWriter.Write(ruleSet));
                return 0;
            }

            int ruleCount = ruleSet.Rules.Count;
            string noun = ruleCount == 1 ? "rule" : "rules";
            Console.Out.WriteLine($"rules ok: {ruleCount} {noun}");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    static int RunRulesTest(string[] args)
    {
        if (!TryResolveNativeProfile(args, defaultNativeProfile: true, out bool nativeMode))
        {
            return UnknownFlagExitCode;
        }

        string? configPath = null;
        string fileName = "rules-test.txt";
        string? reportFormat = null;
        string? reportPath = null;
        var reportPaths = new List<string>();
        string source = ".";
        int maxDecodeDepth = 5;
        long? maxTargetBytes = null;
        bool ignoreGitleaksAllow = false;
        bool printConfig = false;
        int redactionPercent = 0;
        var positional = new List<string>(2);
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteRulesTestHelp();
                return 0;
            }

            if (arg.Equals("--", StringComparison.Ordinal))
            {
                while (++i < args.Length)
                {
                    if (positional.Count == 2)
                    {
                        Console.Error.WriteLine($"unexpected argument: {args[i]}");
                        return UnknownFlagExitCode;
                    }

                    positional.Add(args[i]);
                }

                break;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsProfileFlag(arg))
            {
                if (!TryReadProfileFlag(args, ref i, out _))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsReportFormatFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--report-format", out reportFormat))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
            {
                if (!TryReadStringFlag(args, ref i, "--report-path", out string? value))
                {
                    return UnknownFlagExitCode;
                }

                reportPath = value;
                if (nativeMode)
                {
                    reportPaths.Add(value);
                }

                continue;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsRulesTestPathFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--path", out string? pathValue))
                {
                    return UnknownFlagExitCode;
                }

                fileName = pathValue;
                continue;
            }

            if (IsPrintConfigFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--print-config", out printConfig))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsIgnoreGitleaksAllowFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--ignore-gitleaks-allow", out ignoreGitleaksAllow))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsMaxDecodeDepthFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsMaxTargetMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, out maxTargetBytes))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsRedactFlag(arg))
            {
                if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }

            if (positional.Count == 2)
            {
                Console.Error.WriteLine($"unexpected argument: {arg}");
                return UnknownFlagExitCode;
            }

            positional.Add(arg);
        }

        if (positional.Count != 2)
        {
            Console.Error.WriteLine("rules test requires a rule ID and input");
            return UnknownFlagExitCode;
        }

        string ruleId = positional[0];
        string input = positional[1];
        try
        {
            RuleSet ruleSet = nativeMode
                ? PicketConfigLoader.LoadRuleSet(configPath, source)
                : GitleaksConfigLoader.LoadRuleSet(configPath, source);
            ValidateRulesWithScout(ruleSet);
            RuleSet selectedRuleSet = FilterEnabledRules(ruleSet, [ruleId]);
            if (printConfig)
            {
                Console.Out.Write(GitleaksConfigWriter.Write(selectedRuleSet));
                return 0;
            }

            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
                inputBytes,
                fileName,
                CompiledRuleSet.Compile(selectedRuleSet),
                ignoreGitleaksAllow,
                maxDecodeDepth: maxDecodeDepth,
                maxTargetBytes: maxTargetBytes,
                enableCSharpStringConcatenation: nativeMode));
            if (nativeMode)
            {
                findings = OfflineSecretValidator.AnnotateAll(findings);
            }

            if (redactionPercent > 0)
            {
                findings = GitleaksFindingRedactor.Redact(findings, redactionPercent);
            }

            if (!TryWriteReports(findings, selectedRuleSet.Rules, reportPath, reportPaths, reportFormat, reportTemplatePath: null, nativeMode))
            {
                return 1;
            }

            return 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    static RuleSet FilterEnabledRules(RuleSet ruleSet, IReadOnlyList<string> enabledRuleIds)
    {
        if (enabledRuleIds.Count == 0)
        {
            return ruleSet;
        }

        var requestedRuleIds = new HashSet<string>(enabledRuleIds, StringComparer.Ordinal);
        var enabledRules = new List<SecretRule>();
        foreach (SecretRule rule in ruleSet.Rules)
        {
            if (requestedRuleIds.Remove(rule.Id))
            {
                enabledRules.Add(rule);
            }
        }

        if (requestedRuleIds.Count != 0)
        {
            string missingRuleId = requestedRuleIds.First();
            throw new InvalidDataException($"Requested rule {missingRuleId} not found in rules");
        }

        return new RuleSet(enabledRules, ruleSet.Allowlists, ruleSet.RegexesPrevalidated);
    }

    static void ValidateRulesWithScout(RuleSet ruleSet)
    {
        ValidateUniqueRuleIds(ruleSet.Rules);
        ValidateRuleQuality(ruleSet);
        CompiledRuleSet compiledRuleSet = CompiledRuleSet.Compile(new RuleSet(ruleSet.Rules, ruleSet.Allowlists));
        ValidateRuleExamples(ruleSet.Rules, compiledRuleSet);
    }

    static void ValidateRuleQuality(RuleSet ruleSet)
    {
        ValidateAllowlists("global allowlist", ruleSet.Allowlists);
        foreach (SecretRule rule in ruleSet.Rules)
        {
            ValidateTextEntries(rule.Id, "keyword", rule.Keywords, StringComparer.OrdinalIgnoreCase);
            ValidateTextEntries(rule.Id, "tag", rule.Tags, StringComparer.Ordinal);
            ValidateTextEntries(rule.Id, "example", rule.Examples, StringComparer.Ordinal);
            ValidateTextEntries(rule.Id, "negative example", rule.NegativeExamples, StringComparer.Ordinal);
            ValidateNativeRuleExamples(rule);
            ValidateRequiredRules(rule);
            ValidateAllowlists($"rule {rule.Id} allowlist", rule.Allowlists);
        }
    }

    static void ValidateNativeRuleExamples(SecretRule rule)
    {
        if (!IsPicketNativeRule(rule))
        {
            return;
        }

        if (rule.Examples.Count == 0)
        {
            throw new InvalidDataException($"rule {rule.Id}: native rules require at least one positive example");
        }

        if (rule.NegativeExamples.Count == 0)
        {
            throw new InvalidDataException($"rule {rule.Id}: native rules require at least one negative example");
        }
    }

    static bool IsPicketNativeRule(SecretRule rule)
    {
        return rule.Id.StartsWith("picket-", StringComparison.Ordinal)
            || rule.RulePack.StartsWith("picket-", StringComparison.Ordinal);
    }

    static void ValidateRuleExamples(IReadOnlyList<SecretRule> rules, CompiledRuleSet compiledRuleSet)
    {
        foreach (SecretRule rule in rules)
        {
            for (int i = 0; i < rule.Examples.Count; i++)
            {
                if (!RuleMatchesExample(rule, rule.Examples[i], compiledRuleSet))
                {
                    throw new InvalidDataException($"rule {rule.Id}: example {i + 1} did not produce a finding");
                }
            }

            for (int i = 0; i < rule.NegativeExamples.Count; i++)
            {
                if (RuleMatchesExample(rule, rule.NegativeExamples[i], compiledRuleSet))
                {
                    throw new InvalidDataException($"rule {rule.Id}: negative example {i + 1} produced a finding");
                }
            }
        }
    }

    static bool RuleMatchesExample(SecretRule rule, string example, CompiledRuleSet compiledRuleSet)
    {
        byte[] input;
        string fileName;
        if (rule.Pattern.Length == 0)
        {
            input = [];
            fileName = example;
        }
        else
        {
            input = Encoding.UTF8.GetBytes(example);
            fileName = "rules-example.txt";
        }

        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, fileName, compiledRuleSet));
        foreach (Finding finding in findings)
        {
            if (finding.RuleID.Equals(rule.Id, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    static void ValidateUniqueRuleIds(IReadOnlyList<SecretRule> rules)
    {
        var ruleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretRule rule in rules)
        {
            if (!ruleIds.Add(rule.Id))
            {
                throw new InvalidDataException($"duplicate rule ID: {rule.Id}");
            }
        }
    }

    static void ValidateRequiredRules(SecretRule rule)
    {
        var requiredRuleIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (SecretRequiredRule requiredRule in rule.RequiredRules)
        {
            if (requiredRule.Id.Equals(rule.Id, StringComparison.Ordinal))
            {
                throw new InvalidDataException($"rule {rule.Id}: required rule must not reference itself");
            }

            if (!requiredRuleIds.Add(requiredRule.Id))
            {
                throw new InvalidDataException($"rule {rule.Id}: duplicate required rule: {requiredRule.Id}");
            }
        }
    }

    static void ValidateAllowlists(string scope, IReadOnlyList<SecretAllowlist> allowlists)
    {
        for (int i = 0; i < allowlists.Count; i++)
        {
            SecretAllowlist allowlist = allowlists[i];
            ValidatePatternEntries(scope, "path allowlist pattern", allowlist.PathPatterns);
            ValidatePatternEntries(scope, "regex allowlist pattern", allowlist.RegexPatterns);
        }
    }

    static void ValidatePatternEntries(string scope, string field, IReadOnlyList<string> values)
    {
        for (int i = 0; i < values.Count; i++)
        {
            if (string.IsNullOrWhiteSpace(values[i]))
            {
                throw new InvalidDataException($"{scope}: {field} entries must not be empty");
            }
        }
    }

    static void ValidateTextEntries(string ruleId, string field, IReadOnlyList<string> values, StringComparer comparer)
    {
        var seen = new HashSet<string>(comparer);
        for (int i = 0; i < values.Count; i++)
        {
            string value = values[i];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidDataException($"rule {ruleId}: {field} entries must not be empty");
            }

            if (!seen.Add(value))
            {
                throw new InvalidDataException($"rule {ruleId}: duplicate {field}: {value}");
            }
        }
    }
}
