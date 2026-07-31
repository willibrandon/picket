using Picket.Engine;
using Picket.Rules;
using System.Collections;
using System.Reflection;

namespace Picket.Tests;

/// <summary>
/// Tests compatibility scan preparation boundaries.
/// </summary>
[TestClass]
public sealed class CompatibilityScanPreparationTests
{
    /// <summary>
    /// Verifies directory timing restarts after rule loading and before detector setup without measuring elapsed time.
    /// </summary>
    [TestMethod]
    public void DirectoryScanStartsCompatibilityTimerAfterPreparationAndBeforeScanWork()
    {
        string directorySource = ReadRepositoryFile("src/Picket.Cli/Program.Directory.cs");
        string optionsSource = ReadRepositoryFile("src/Picket.Cli/CompatibilityConsoleOptions.cs");

        int timerStart = FindRequiredMarker(directorySource, "consoleOptions.RestartTiming();");
        int prefilterStart = FindRequiredMarker(directorySource, "rules.PrepareKeywordPrefilter();", timerStart);
        int scanStart = FindRequiredMarker(directorySource, "ScanSourceFiles(", timerStart);
        string constructor = ReadMethodBlock(optionsSource, "internal CompatibilityConsoleOptions()");
        string restartTiming = ReadMethodBlock(optionsSource, "internal void RestartTiming()");

        Assert.IsLessThan(scanStart, timerStart, "The compatibility timer must start before detector/scan work.");
        Assert.IsLessThan(prefilterStart, timerStart, "The compatibility timer must include detector prefilter construction.");
        Assert.IsGreaterThan(
            FindRequiredMarker(directorySource, "if (string.IsNullOrEmpty(root))"),
            timerStart,
            "The compatibility timer must start after argument parsing.");
        Assert.IsGreaterThan(
            FindRequiredMarker(directorySource, "TryLoadRules("),
            timerStart,
            "The compatibility timer must start after config and rule loading.");
        Assert.IsLessThan(
            FindRequiredMarker(directorySource, "TryEnumerateDirectorySource("),
            timerStart,
            "The compatibility timer must include local source traversal.");
        Assert.IsLessThan(
            FindRequiredMarker(directorySource, "files = RemoteScanManifest.OrderFiles("),
            timerStart,
            "The compatibility timer must include remote source traversal.");
        Assert.IsLessThan(
            FindRequiredMarker(directorySource, "GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore("),
            timerStart,
            "The compatibility timer must include ignore loading.");
        Assert.IsLessThan(
            FindRequiredMarker(directorySource, "if (!TryLoadBaseline(baselinePath, baselineComparisonMode, out GitleaksBaseline? baseline))"),
            timerStart,
            "The compatibility timer must include baseline loading.");
        Assert.Contains("StartTimestamp = Stopwatch.GetTimestamp();", constructor);
        Assert.Contains("StartTimestamp = Stopwatch.GetTimestamp();", restartTiming);
    }

    /// <summary>
    /// Verifies parallel directory scans finish deferred-regex warmup before starting workers.
    /// </summary>
    [TestMethod]
    public void ParallelDirectoryScanWarmsAllDeferredRegexesBeforeWorkerExecution()
    {
        string source = ReadRepositoryFile("src/Picket.Cli/Program.ParallelScanning.cs");

        int warmup = FindRequiredMarker(source, "rules.PrepareForScanning();");
        int workerStart = FindRequiredMarker(source, "Parallel.For(", warmup);

        Assert.IsLessThan(workerStart, warmup);
        Assert.DoesNotContain("rules.CompileUnconditionalDeferredRegexes();", source);
    }

    /// <summary>
    /// Verifies complete warmup compiles keyword-gated rule, path, and allowlist regexes.
    /// </summary>
    [TestMethod]
    public void CompileDeferredRegexesWarmsKeywordGatedRuleAndRelevantAllowlists()
    {
        SecretAllowlist ruleAllowlist = SecretAllowlist.Create(
            pathPatterns: ["^excluded/"],
            regexPatterns: ["rule-allowed"]);
        SecretAllowlist globalAllowlist = SecretAllowlist.Create(
            pathPatterns: ["^generated/"],
            regexPatterns: ["global-allowed"]);
        SecretRule rule = SecretRule.Create(
            "keyword-gated",
            "Keyword-gated rule",
            "token-[0-9]+",
            pathPattern: "[.]txt$",
            keywords: ["token"],
            allowlists: [ruleAllowlist]);
        CompiledRuleSet rules = CompiledRuleSet.Compile(new RuleSet(
            [rule],
            [globalAllowlist],
            regexesPrevalidated: true));
        object compiledRule = GetSingleItem(GetRequiredPropertyValue(rules, "CompiledRules"));
        object compiledRuleAllowlist = GetSingleItem(GetRequiredPropertyValue(compiledRule, "Allowlists"));
        object compiledGlobalAllowlist = GetSingleItem(GetRequiredPropertyValue(rules, "Allowlists"));

        Assert.IsNull(GetFieldValue(compiledRule, "_regex"));
        Assert.IsNull(GetFieldValue(compiledRule, "_pathRegex"));
        AssertAllowlistIsDeferred(compiledRuleAllowlist);
        AssertAllowlistIsDeferred(compiledGlobalAllowlist);

        InvokeRequiredMethod(rules, "CompileDeferredRegexes");

        Assert.IsNotNull(GetFieldValue(compiledRule, "_regex"));
        Assert.IsNotNull(GetFieldValue(compiledRule, "_pathRegex"));
        AssertAllowlistIsCompiled(compiledRuleAllowlist);
        AssertAllowlistIsCompiled(compiledGlobalAllowlist);
    }

    private static void AssertAllowlistIsCompiled(object compiledAllowlist)
    {
        Assert.IsNotNull(GetFieldValue(compiledAllowlist, "_pathRegexes"));
        Assert.IsNotNull(GetFieldValue(compiledAllowlist, "_regexes"));
    }

    private static void AssertAllowlistIsDeferred(object compiledAllowlist)
    {
        Assert.IsNull(GetFieldValue(compiledAllowlist, "_pathRegexes"));
        Assert.IsNull(GetFieldValue(compiledAllowlist, "_regexes"));
    }

    private static int FindRequiredMarker(string source, string marker, int startIndex = 0)
    {
        int index = source.IndexOf(marker, startIndex, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, index, $"Missing source marker: {marker}");
        return index;
    }

    private static object? GetFieldValue(object target, string fieldName)
    {
        FieldInfo field = target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new AssertFailedException($"Missing field {target.GetType().FullName}.{fieldName}.");
        return field.GetValue(target);
    }

    private static object GetRequiredPropertyValue(object target, string propertyName)
    {
        PropertyInfo property = target.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new AssertFailedException($"Missing property {target.GetType().FullName}.{propertyName}.");
        return property.GetValue(target)
            ?? throw new AssertFailedException($"Property {target.GetType().FullName}.{propertyName} returned null.");
    }

    private static object GetSingleItem(object value)
    {
        IList items = value as IList
            ?? throw new AssertFailedException($"Expected {value.GetType().FullName} to implement IList.");
        Assert.HasCount(1, items);
        return items[0]
            ?? throw new AssertFailedException("Expected a non-null compiled item.");
    }

    private static void InvokeRequiredMethod(object target, string methodName)
    {
        MethodInfo method = target.GetType().GetMethod(methodName, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new AssertFailedException($"Missing method {target.GetType().FullName}.{methodName}.");
        method.Invoke(target, null);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        return File.ReadAllText(Path.Combine(FindRepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string ReadMethodBlock(string source, string signature)
    {
        int start = FindRequiredMarker(source, signature);
        int end = source.IndexOf("\n    }", start, StringComparison.Ordinal);
        Assert.IsGreaterThan(start, end, $"Could not find the end of method: {signature}");
        return source[start..end];
    }

    private static string FindRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory, "Picket.slnx")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
