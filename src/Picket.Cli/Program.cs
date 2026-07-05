using System.Diagnostics.CodeAnalysis;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Sources;

const int UnknownFlagExitCode = 126;
const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";

if (args.Length == 0 || IsHelp(args[0]))
{
    WriteHelp();
    return 0;
}

string command = args[0];
if (command.Equals("version", StringComparison.OrdinalIgnoreCase))
{
    Console.Out.WriteLine("picket dev");
    return 0;
}

if (command.Equals("stdin", StringComparison.OrdinalIgnoreCase))
{
    return await RunStdinAsync(args[1..]).ConfigureAwait(false);
}

if (command.Equals("detect", StringComparison.OrdinalIgnoreCase))
{
    return await RunDetectAsync(args[1..]).ConfigureAwait(false);
}

if (command.Equals("protect", StringComparison.OrdinalIgnoreCase))
{
    return RunProtect(args[1..]);
}

if (command.Equals("git", StringComparison.OrdinalIgnoreCase))
{
    return RunGit(args[1..]);
}

if (IsDirectoryCommand(command))
{
    return RunDirectory(args[1..]);
}

Console.Error.WriteLine($"unknown command: {command}");
return UnknownFlagExitCode;

static async Task<int> RunStdinAsync(string[] args, string configSource = "stdin")
{
    string? baselinePath = null;
    string? configPath = null;
    string? reportPath = null;
    string? reportFormat = null;
    string? reportTemplatePath = null;
    List<string> enabledRuleIds = [];
    int exitCode = 1;
    int maxDecodeDepth = 5;
    bool ignoreGitleaksAllow = false;
    int redactionPercent = 0;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsBaselinePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--baseline-path", out baselinePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsConfigFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--config", out configPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
        {
            if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsEnableRuleFlag(arg))
        {
            if (!TryReadRuleIdFlag(args, ref i, enabledRuleIds))
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

        if (IsReportTemplateFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--report-template", out reportTemplatePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
        {
            if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
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

        if (IsRedactFlag(arg))
        {
            if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
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

        if (!TryHandleCommonCompatibilityFlag(args, ref i, out bool handledCommonFlag))
        {
            return UnknownFlagExitCode;
        }

        if (handledCommonFlag)
        {
            continue;
        }

        Console.Error.WriteLine($"unknown flag: {arg}");
        return UnknownFlagExitCode;
    }

    using var stream = new MemoryStream();
    await Console.OpenStandardInput().CopyToAsync(stream).ConfigureAwait(false);
    byte[] input = stream.ToArray();
    if (!TryLoadRules(configPath, configSource, enabledRuleIds, out CompiledRuleSet? rules))
    {
        return 1;
    }

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return 1;
    }

    IReadOnlyList<Finding> findings = baseline.Filter(
        SecretScanner.Scan(new ScanRequest(input, "stdin", rules, ignoreGitleaksAllow, maxDecodeDepth: maxDecodeDepth)),
        redactionPercent);
    if (redactionPercent > 0)
    {
        findings = GitleaksFindingRedactor.Redact(findings, redactionPercent);
    }

    if (!TryWriteReport(findings, rules.Rules, reportPath, reportFormat, reportTemplatePath))
    {
        return 1;
    }

    return findings.Count == 0 ? 0 : exitCode;
}

static int RunDirectory(string[] args)
{
    string? baselinePath = null;
    string? configPath = null;
    string? reportPath = null;
    string? reportFormat = null;
    string? reportTemplatePath = null;
    List<string> enabledRuleIds = [];
    string gitleaksIgnorePath = ".";
    int exitCode = 1;
    bool followSymlinks = false;
    bool ignoreGitleaksAllow = false;
    int maxDecodeDepth = 5;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    string? root = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsBaselinePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--baseline-path", out baselinePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsConfigFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--config", out configPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
        {
            if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsEnableRuleFlag(arg))
        {
            if (!TryReadRuleIdFlag(args, ref i, enabledRuleIds))
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

        if (IsReportTemplateFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--report-template", out reportTemplatePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
        {
            if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsGitleaksIgnorePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--gitleaks-ignore-path", out string? value))
            {
                return UnknownFlagExitCode;
            }

            gitleaksIgnorePath = value;
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

        if (IsFollowSymlinksFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--follow-symlinks", out followSymlinks))
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

        if (IsMaxDecodeDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (!TryHandleCommonCompatibilityFlag(args, ref i, out bool handledCommonFlag))
        {
            return UnknownFlagExitCode;
        }

        if (handledCommonFlag)
        {
            continue;
        }

        if (arg.StartsWith('-'))
        {
            Console.Error.WriteLine($"unknown flag: {arg}");
            return UnknownFlagExitCode;
        }

        if (root is not null)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return UnknownFlagExitCode;
        }

        root = arg;
    }

    if (root is null)
    {
        Console.Error.WriteLine("dir requires a path");
        return UnknownFlagExitCode;
    }

    IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxTargetBytes, followSymlinks));
    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    if (!TryLoadRules(configPath, root, enabledRuleIds, out CompiledRuleSet? rules))
    {
        return 1;
    }

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return 1;
    }

    string? baselineDisplayPath = CreateControlFileDisplayPath(root, baselinePath);
    string? configDisplayPath = CreateControlFileDisplayPath(root, ResolveConfigControlPath(configPath, root));
    string? reportDisplayPath = CreateControlFileDisplayPath(root, reportPath);
    var findings = new List<Finding>();
    bool hadScanError = false;
    foreach (SourceFile file in files)
    {
        if (IsControlFile(file, baselineDisplayPath, configDisplayPath, reportDisplayPath))
        {
            continue;
        }

        try
        {
            byte[] input = File.ReadAllBytes(file.FullPath);
            findings.AddRange(SecretScanner.Scan(new ScanRequest(input, file.DisplayPath, rules, ignoreGitleaksAllow, maxDecodeDepth: maxDecodeDepth)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            hadScanError = true;
        }
    }

    IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    if (!TryWriteReport(filteredFindings, rules.Rules, reportPath, reportFormat, reportTemplatePath))
    {
        return 1;
    }

    if (hadScanError)
    {
        return 1;
    }

    return filteredFindings.Count == 0 ? 0 : exitCode;
}

static int RunGit(string[] args)
{
    string? baselinePath = null;
    string? configPath = null;
    string? reportPath = null;
    string? reportFormat = null;
    string? reportTemplatePath = null;
    string? logOptions = null;
    string? platform = null;
    List<string> enabledRuleIds = [];
    string gitleaksIgnorePath = ".";
    string root = ".";
    int exitCode = 1;
    bool ignoreGitleaksAllow = false;
    int maxDecodeDepth = 5;
    bool preCommit = false;
    bool rootProvided = false;
    bool staged = false;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsBaselinePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--baseline-path", out baselinePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsConfigFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--config", out configPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
        {
            if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsEnableRuleFlag(arg))
        {
            if (!TryReadRuleIdFlag(args, ref i, enabledRuleIds))
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

        if (IsReportTemplateFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--report-template", out reportTemplatePath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
        {
            if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsGitleaksIgnorePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--gitleaks-ignore-path", out string? value))
            {
                return UnknownFlagExitCode;
            }

            gitleaksIgnorePath = value;
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

        if (IsLogOptionsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsPlatformFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--platform", out platform))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsPreCommitFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--pre-commit", out preCommit))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsStagedFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--staged", out staged))
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

        if (IsMaxDecodeDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (!TryHandleCommonCompatibilityFlag(args, ref i, out bool handledCommonFlag))
        {
            return UnknownFlagExitCode;
        }

        if (handledCommonFlag)
        {
            continue;
        }

        if (arg.StartsWith('-'))
        {
            Console.Error.WriteLine($"unknown flag: {arg}");
            return UnknownFlagExitCode;
        }

        if (rootProvided)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return UnknownFlagExitCode;
        }

        root = arg.Length == 0 ? "." : arg;
        rootProvided = true;
    }

    if (!staged && !preCommit && !TryValidatePlatform(platform))
    {
        return UnknownFlagExitCode;
    }

    if (!TryLoadRules(configPath, root, enabledRuleIds, out CompiledRuleSet? rules))
    {
        return 1;
    }

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return 1;
    }

    IReadOnlyList<GitPatchFragment> fragments;
    try
    {
        fragments = GitSource.Enumerate(new GitScanOptions(root, logOptions, staged, preCommit));
    }
    catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    List<Finding> findings = ScanGitFragments(fragments, rules, ignoreGitleaksAllow, maxTargetBytes, maxDecodeDepth);
    IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    if (!TryWriteReport(filteredFindings, rules.Rules, reportPath, reportFormat, reportTemplatePath))
    {
        return 1;
    }

    return filteredFindings.Count == 0 ? 0 : exitCode;
}

static async Task<int> RunDetectAsync(string[] args)
{
    var forwardedArgs = new List<string>();
    string? logOptions = null;
    string? platform = null;
    string source = ".";
    bool followSymlinks = false;
    bool noGit = false;
    bool pipe = false;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsSourceFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
            {
                return UnknownFlagExitCode;
            }

            source = sourceValue.Length == 0 ? "." : sourceValue;
            continue;
        }

        if (IsNoGitFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--no-git", out noGit))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsPipeFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--pipe", out pipe))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsFollowSymlinksFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--follow-symlinks", out followSymlinks))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsLogOptionsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsPlatformFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--platform", out platform))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        forwardedArgs.Add(arg);
    }

    if (noGit)
    {
        if (followSymlinks)
        {
            forwardedArgs.Add("--follow-symlinks");
        }

        forwardedArgs.Add(source);
        return RunDirectory([.. forwardedArgs]);
    }

    if (pipe)
    {
        return await RunStdinAsync([.. forwardedArgs], source).ConfigureAwait(false);
    }

    if (!string.IsNullOrEmpty(logOptions))
    {
        forwardedArgs.Add("--log-opts");
        forwardedArgs.Add(logOptions);
    }

    if (!string.IsNullOrEmpty(platform))
    {
        forwardedArgs.Add("--platform");
        forwardedArgs.Add(platform);
    }

    forwardedArgs.Add(source);
    return RunGit([.. forwardedArgs]);
}

static int RunProtect(string[] args)
{
    var forwardedArgs = new List<string>();
    string source = ".";
    bool staged = false;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsSourceFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
            {
                return UnknownFlagExitCode;
            }

            source = sourceValue.Length == 0 ? "." : sourceValue;
            continue;
        }

        if (IsStagedFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--staged", out staged))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsLogOptionsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--log-opts", out _))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        forwardedArgs.Add(arg);
    }

    forwardedArgs.Add("--pre-commit");
    if (staged)
    {
        forwardedArgs.Add("--staged");
    }

    forwardedArgs.Add(source);
    return RunGit([.. forwardedArgs]);
}

static bool IsHelp(string arg)
{
    return arg is "-h" or "--help" or "help";
}

static bool IsDirectoryCommand(string command)
{
    return command.Equals("dir", StringComparison.OrdinalIgnoreCase)
        || command.Equals("file", StringComparison.OrdinalIgnoreCase)
        || command.Equals("directory", StringComparison.OrdinalIgnoreCase);
}

static List<Finding> ScanGitFragments(
    IReadOnlyList<GitPatchFragment> fragments,
    CompiledRuleSet rules,
    bool ignoreGitleaksAllow,
    long? maxTargetBytes,
    int maxDecodeDepth)
{
    var findings = new List<Finding>();
    foreach (GitPatchFragment fragment in fragments)
    {
        if (maxTargetBytes.HasValue && fragment.Input.Length > maxTargetBytes.Value)
        {
            continue;
        }

        IReadOnlyList<Finding> fragmentFindings = SecretScanner.Scan(new ScanRequest(
            fragment.Input,
            fragment.FilePath,
            rules,
            ignoreGitleaksAllow,
            fragment.Commit,
            maxDecodeDepth));
        foreach (Finding finding in fragmentFindings)
        {
            findings.Add(MapGitFinding(finding, fragment));
        }
    }

    return findings;
}

static Finding MapGitFinding(Finding finding, GitPatchFragment fragment)
{
    int startLine = MapGitLine(fragment, finding.StartLine);
    int endLine = MapGitLine(fragment, finding.EndLine);
    return new Finding(
        finding.RuleID,
        finding.Description,
        startLine,
        endLine,
        finding.StartColumn,
        finding.EndColumn,
        finding.Match,
        finding.Secret,
        finding.File,
        finding.SymlinkFile,
        fragment.Commit,
        finding.Entropy,
        fragment.Author,
        fragment.Email,
        fragment.Date,
        fragment.Message,
        finding.Tags,
        CreateFingerprint(fragment.Commit, finding.File, finding.RuleID, startLine),
        finding.Line);
}

static int MapGitLine(GitPatchFragment fragment, int line)
{
    return line == 0 ? 0 : fragment.StartLine + line - 1;
}

static string CreateFingerprint(string commit, string fileName, string ruleId, int startLine)
{
    return commit.Length == 0
        ? $"{fileName}:{ruleId}:{startLine}"
        : $"{commit}:{fileName}:{ruleId}:{startLine}";
}

static bool TryParseMegabytes(string value, out long? bytes)
{
    if (!long.TryParse(value, out long megabytes) || megabytes < 0)
    {
        bytes = null;
        return false;
    }

    bytes = megabytes == 0 ? null : megabytes * 1_000_000;
    return true;
}

static bool TryReadMegabytesFlag(string[] args, ref int index, out long? maxTargetBytes)
{
    if (TryReadStringFlag(args, ref index, "--max-target-megabytes", out string? value)
        && TryParseMegabytes(value, out maxTargetBytes))
    {
        return true;
    }

    Console.Error.WriteLine("--max-target-megabytes requires a non-negative integer value");
    maxTargetBytes = null;
    return false;
}

static bool TryReadStringFlag(string[] args, ref int index, string longName, [NotNullWhen(true)] out string? value)
{
    string arg = args[index];
    string longNameWithEquals = string.Concat(longName, "=");
    if (arg.StartsWith(longNameWithEquals, StringComparison.Ordinal))
    {
        value = arg[longNameWithEquals.Length..];
        return true;
    }

    if (index + 1 >= args.Length)
    {
        Console.Error.WriteLine($"{arg} requires a value");
        value = null;
        return false;
    }

    value = args[++index];
    return true;
}

static bool TryReadIntFlag(string[] args, ref int index, string longName, out int value)
{
    if (TryReadStringFlag(args, ref index, longName, out string? text) && int.TryParse(text, out value))
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} requires an integer value");
    value = 0;
    return false;
}

static bool TryReadNonNegativeIntFlag(string[] args, ref int index, string longName, out int value)
{
    if (!TryReadIntFlag(args, ref index, longName, out value))
    {
        return false;
    }

    if (value >= 0)
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} requires a non-negative integer value");
    value = 0;
    return false;
}

static bool TryReadRuleIdFlag(string[] args, ref int index, List<string> enabledRuleIds)
{
    if (!TryReadStringFlag(args, ref index, "--enable-rule", out string? value))
    {
        return false;
    }

    foreach (string ruleId in value.Split(','))
    {
        string trimmedRuleId = ruleId.Trim();
        if (trimmedRuleId.Length != 0)
        {
            enabledRuleIds.Add(trimmedRuleId);
        }
    }

    return true;
}

static bool IsBaselinePathFlag(string arg)
{
    return arg is "-b" or "--baseline-path"
        || arg.StartsWith("--baseline-path=", StringComparison.Ordinal);
}

static bool IsConfigFlag(string arg)
{
    return arg is "-c" or "--config"
        || arg.StartsWith("--config=", StringComparison.Ordinal);
}

static bool IsGitleaksIgnorePathFlag(string arg)
{
    return arg is "-i" or "--gitleaks-ignore-path"
        || arg.StartsWith("--gitleaks-ignore-path=", StringComparison.Ordinal);
}

static bool IsIgnoreGitleaksAllowFlag(string arg)
{
    return arg.Equals("--ignore-gitleaks-allow", StringComparison.Ordinal)
        || arg.StartsWith("--ignore-gitleaks-allow=", StringComparison.Ordinal);
}

static bool IsMaxTargetMegabytesFlag(string arg)
{
    return arg.Equals("--max-target-megabytes", StringComparison.Ordinal)
        || arg.StartsWith("--max-target-megabytes=", StringComparison.Ordinal);
}

static bool IsReportFormatFlag(string arg)
{
    return arg is "-f" or "--report-format"
        || arg.StartsWith("--report-format=", StringComparison.Ordinal);
}

static bool IsReportTemplateFlag(string arg)
{
    return arg.Equals("--report-template", StringComparison.Ordinal)
        || arg.StartsWith("--report-template=", StringComparison.Ordinal);
}

static bool IsEnableRuleFlag(string arg)
{
    return arg.Equals("--enable-rule", StringComparison.Ordinal)
        || arg.StartsWith("--enable-rule=", StringComparison.Ordinal);
}

static bool IsLogLevelFlag(string arg)
{
    return arg is "-l" or "--log-level"
        || arg.StartsWith("--log-level=", StringComparison.Ordinal);
}

static bool IsVerboseFlag(string arg)
{
    return arg is "-v" or "--verbose"
        || arg.StartsWith("--verbose=", StringComparison.Ordinal);
}

static bool IsNoColorFlag(string arg)
{
    return arg.Equals("--no-color", StringComparison.Ordinal)
        || arg.StartsWith("--no-color=", StringComparison.Ordinal);
}

static bool IsNoBannerFlag(string arg)
{
    return arg.Equals("--no-banner", StringComparison.Ordinal)
        || arg.StartsWith("--no-banner=", StringComparison.Ordinal);
}

static bool IsMaxDecodeDepthFlag(string arg)
{
    return arg.Equals("--max-decode-depth", StringComparison.Ordinal)
        || arg.StartsWith("--max-decode-depth=", StringComparison.Ordinal);
}

static bool IsMaxArchiveDepthFlag(string arg)
{
    return arg.Equals("--max-archive-depth", StringComparison.Ordinal)
        || arg.StartsWith("--max-archive-depth=", StringComparison.Ordinal);
}

static bool IsTimeoutFlag(string arg)
{
    return arg.Equals("--timeout", StringComparison.Ordinal)
        || arg.StartsWith("--timeout=", StringComparison.Ordinal);
}

static bool IsDiagnosticsFlag(string arg)
{
    return arg.Equals("--diagnostics", StringComparison.Ordinal)
        || arg.StartsWith("--diagnostics=", StringComparison.Ordinal);
}

static bool IsDiagnosticsDirFlag(string arg)
{
    return arg.Equals("--diagnostics-dir", StringComparison.Ordinal)
        || arg.StartsWith("--diagnostics-dir=", StringComparison.Ordinal);
}

static bool IsSourceFlag(string arg)
{
    return arg is "-s" or "--source"
        || arg.StartsWith("--source=", StringComparison.Ordinal);
}

static bool IsNoGitFlag(string arg)
{
    return arg.Equals("--no-git", StringComparison.Ordinal)
        || arg.StartsWith("--no-git=", StringComparison.Ordinal);
}

static bool IsPipeFlag(string arg)
{
    return arg.Equals("--pipe", StringComparison.Ordinal)
        || arg.StartsWith("--pipe=", StringComparison.Ordinal);
}

static bool IsFollowSymlinksFlag(string arg)
{
    return arg.Equals("--follow-symlinks", StringComparison.Ordinal)
        || arg.StartsWith("--follow-symlinks=", StringComparison.Ordinal);
}

static bool IsLogOptionsFlag(string arg)
{
    return arg.Equals("--log-opts", StringComparison.Ordinal)
        || arg.StartsWith("--log-opts=", StringComparison.Ordinal);
}

static bool IsPlatformFlag(string arg)
{
    return arg.Equals("--platform", StringComparison.Ordinal)
        || arg.StartsWith("--platform=", StringComparison.Ordinal);
}

static bool IsPreCommitFlag(string arg)
{
    return arg.Equals("--pre-commit", StringComparison.Ordinal)
        || arg.StartsWith("--pre-commit=", StringComparison.Ordinal);
}

static bool IsStagedFlag(string arg)
{
    return arg.Equals("--staged", StringComparison.Ordinal)
        || arg.StartsWith("--staged=", StringComparison.Ordinal);
}

static bool TryReadBooleanFlag(string arg, string longName, out bool value)
{
    if (arg.Equals(longName, StringComparison.Ordinal))
    {
        value = true;
        return true;
    }

    string longNameWithEquals = string.Concat(longName, "=");
    string text = arg[longNameWithEquals.Length..];
    if (bool.TryParse(text, out value))
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} requires a boolean value");
    return false;
}

static bool TryReadBooleanFlagWithShort(string arg, string shortName, string longName, out bool value)
{
    if (arg.Equals(shortName, StringComparison.Ordinal))
    {
        value = true;
        return true;
    }

    return TryReadBooleanFlag(arg, longName, out value);
}

static bool TryHandleCommonCompatibilityFlag(string[] args, ref int index, out bool handled)
{
    string arg = args[index];
    handled = true;
    if (IsLogLevelFlag(arg))
    {
        return TryReadStringFlag(args, ref index, "--log-level", out _);
    }

    if (IsVerboseFlag(arg))
    {
        return TryReadBooleanFlagWithShort(arg, "-v", "--verbose", out _);
    }

    if (IsNoColorFlag(arg))
    {
        return TryReadBooleanFlag(arg, "--no-color", out _);
    }

    if (IsNoBannerFlag(arg))
    {
        return TryReadBooleanFlag(arg, "--no-banner", out _);
    }

    if (IsMaxArchiveDepthFlag(arg))
    {
        return TryReadUnsupportedPositiveIntFlag(args, ref index, "--max-archive-depth");
    }

    if (IsTimeoutFlag(arg))
    {
        return TryReadUnsupportedPositiveIntFlag(args, ref index, "--timeout");
    }

    if (IsDiagnosticsFlag(arg))
    {
        if (!TryReadStringFlag(args, ref index, "--diagnostics", out string? diagnostics))
        {
            return false;
        }

        if (diagnostics.Length == 0)
        {
            return true;
        }

        Console.Error.WriteLine("--diagnostics is not implemented yet");
        return false;
    }

    if (IsDiagnosticsDirFlag(arg))
    {
        return TryReadStringFlag(args, ref index, "--diagnostics-dir", out _);
    }

    handled = false;
    return true;
}

static bool TryReadUnsupportedPositiveIntFlag(string[] args, ref int index, string longName)
{
    if (!TryReadNonNegativeIntFlag(args, ref index, longName, out int value))
    {
        return false;
    }

    if (value == 0)
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} is not implemented yet");
    return false;
}

static bool IsRedactFlag(string arg)
{
    return arg.Equals("--redact", StringComparison.Ordinal)
        || arg.StartsWith("--redact=", StringComparison.Ordinal);
}

static bool TryReadRedactionPercent(string[] args, ref int index, out int redactionPercent)
{
    string arg = args[index];
    if (arg.Equals("--redact", StringComparison.Ordinal))
    {
        if (index + 1 < args.Length && int.TryParse(args[index + 1], out int parsedRedactionPercent))
        {
            if (!IsValidRedactionPercent(parsedRedactionPercent))
            {
                Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
                redactionPercent = 0;
                return false;
            }

            redactionPercent = parsedRedactionPercent;
            index++;
            return true;
        }

        redactionPercent = 100;
        return true;
    }

    string value = arg["--redact=".Length..];
    if (TryParseRedactionPercent(value, out redactionPercent))
    {
        return true;
    }

    Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
    return false;
}

static bool TryParseRedactionPercent(string value, out int redactionPercent)
{
    if (!int.TryParse(value, out redactionPercent) || !IsValidRedactionPercent(redactionPercent))
    {
        redactionPercent = 0;
        return false;
    }

    return true;
}

static bool IsValidRedactionPercent(int redactionPercent)
{
    return redactionPercent is >= 0 and <= 100;
}

static bool TryValidatePlatform(string? platform)
{
    if (string.IsNullOrWhiteSpace(platform))
    {
        return true;
    }

    string normalizedPlatform = platform.Trim().ToLowerInvariant();
    if (normalizedPlatform is "unknown" or "none" or "github" or "gitlab" or "azuredevops" or "gitea" or "bitbucket")
    {
        return true;
    }

    Console.Error.WriteLine($"invalid scm platform value: {platform}");
    return false;
}

static bool TryLoadRules(
    string? configPath,
    string source,
    IReadOnlyList<string> enabledRuleIds,
    [NotNullWhen(true)] out CompiledRuleSet? rules)
{
    try
    {
        RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(configPath, source);
        ruleSet = FilterEnabledRules(ruleSet, enabledRuleIds);
        rules = CompiledRuleSet.Compile(ruleSet);
        return true;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        rules = null;
        return false;
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

static bool TryLoadBaseline(string? baselinePath, [NotNullWhen(true)] out GitleaksBaseline? baseline)
{
    if (string.IsNullOrWhiteSpace(baselinePath))
    {
        baseline = GitleaksBaseline.Empty;
        return true;
    }

    try
    {
        baseline = GitleaksBaseline.Load(baselinePath);
        return true;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException)
    {
        Console.Error.WriteLine(ex.Message);
        baseline = null;
        return false;
    }
}

static bool TryWriteReport(
    IReadOnlyList<Finding> findings,
    IReadOnlyList<SecretRule> rules,
    string? reportPath,
    string? reportFormat,
    string? reportTemplatePath)
{
    if (!TryResolveReportFormat(reportPath, reportFormat, reportTemplatePath, out string? resolvedReportFormat))
    {
        return false;
    }

    string report;
    try
    {
        report = resolvedReportFormat switch
        {
            "csv" => GitleaksCsvReportWriter.Write(findings),
            "junit" => GitleaksJunitReportWriter.Write(findings),
            "json" => GitleaksJsonReportWriter.Write(findings),
            "sarif" => GitleaksSarifReportWriter.Write(findings, rules),
            "template" => GitleaksTemplateReportWriter.Write(findings, ReadReportTemplate(reportTemplatePath)),
            _ => throw new InvalidOperationException($"unsupported report format: {resolvedReportFormat}"),
        };
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"invalid report template: {ex.Message}");
        return false;
    }

    if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
    {
        Console.Out.Write(report);
        return true;
    }

    try
    {
        File.WriteAllText(reportPath, report);
        return true;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"failed to write report: {ex.Message}");
        return false;
    }
}

static string ReadReportTemplate(string? reportTemplatePath)
{
    if (string.IsNullOrWhiteSpace(reportTemplatePath))
    {
        throw new InvalidDataException("template path cannot be empty");
    }

    return File.ReadAllText(reportTemplatePath);
}

static bool TryResolveReportFormat(
    string? reportPath,
    string? reportFormat,
    string? reportTemplatePath,
    [NotNullWhen(true)] out string? resolvedReportFormat)
{
    if (!string.IsNullOrWhiteSpace(reportFormat))
    {
        if (!TryNormalizeReportFormat(reportFormat, out resolvedReportFormat))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(reportTemplatePath)
            && !resolvedReportFormat.Equals("template", StringComparison.Ordinal))
        {
            Console.Error.WriteLine("report format must be 'template' if --report-template is specified");
            resolvedReportFormat = null;
            return false;
        }

        return true;
    }

    if (!string.IsNullOrWhiteSpace(reportTemplatePath))
    {
        resolvedReportFormat = "template";
        return true;
    }

    if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
    {
        resolvedReportFormat = "json";
        return true;
    }

    string extension = Path.GetExtension(reportPath);
    if (extension.Equals(".csv", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "csv";
        return true;
    }

    if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "json";
        return true;
    }

    if (extension.Equals(".sarif", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "sarif";
        return true;
    }

    Console.Error.WriteLine($"unknown report format for report path: {reportPath}");
    resolvedReportFormat = null;
    return false;
}

static bool TryNormalizeReportFormat(string reportFormat, [NotNullWhen(true)] out string? resolvedReportFormat)
{
    string normalizedReportFormat = reportFormat.Trim().ToLowerInvariant();
    if (normalizedReportFormat is "csv" or "json" or "junit" or "sarif" or "template")
    {
        resolvedReportFormat = normalizedReportFormat;
        return true;
    }

    Console.Error.WriteLine($"unsupported report format: {reportFormat}");
    resolvedReportFormat = null;
    return false;
}

static GitleaksIgnore LoadGitleaksIgnore(string gitleaksIgnorePath, string source)
{
    return GitleaksIgnore.LoadExisting([
        gitleaksIgnorePath,
        Path.Combine(gitleaksIgnorePath, ".gitleaksignore"),
        Path.Combine(source, ".gitleaksignore"),
    ]);
}

static string? CreateControlFileDisplayPath(string root, string? path)
{
    if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(root))
    {
        return null;
    }

    string relativePath = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
    if (relativePath.Equals(".", StringComparison.Ordinal)
        || relativePath.StartsWith("..", StringComparison.Ordinal)
        || Path.IsPathRooted(relativePath))
    {
        return null;
    }

    return relativePath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
}

static string? ResolveConfigControlPath(string? configPath, string source)
{
    if (!string.IsNullOrWhiteSpace(configPath))
    {
        return configPath;
    }

    string? environmentPath = Environment.GetEnvironmentVariable(GitleaksConfigEnvironmentVariable);
    if (!string.IsNullOrWhiteSpace(environmentPath))
    {
        return environmentPath;
    }

    string? environmentToml = Environment.GetEnvironmentVariable(GitleaksConfigTomlEnvironmentVariable);
    return string.IsNullOrWhiteSpace(environmentToml) ? Path.Combine(source, ".gitleaks.toml") : null;
}

static bool IsControlFile(SourceFile file, params string?[] displayPaths)
{
    foreach (string? displayPath in displayPaths)
    {
        if (displayPath is not null && file.DisplayPath.Equals(displayPath, StringComparison.Ordinal))
        {
            return true;
        }
    }

    return false;
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket git [repo] [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--log-opts value] [--platform value] [--staged] [--pre-commit] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket dir <path> [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--follow-symlinks] [--ignore-gitleaks-allow] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket stdin [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-l level] [-v] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--redact[=n]]");
    Console.Out.WriteLine("  picket version");
}
