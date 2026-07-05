using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using Picket;
using Picket.Analyze;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Sources;
using Picket.Store;
using Picket.Verify;

const int UnknownFlagExitCode = 126;
const int BinaryProbeLength = 8192;
const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
const string ManagedHookMarker = "# managed by picket hooks install";
const string TimeoutErrorMessage = "context deadline exceeded";

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

if (command.Equals("scan", StringComparison.OrdinalIgnoreCase))
{
    return RunScan(args[1..]);
}

if (command.Equals("verify", StringComparison.OrdinalIgnoreCase))
{
    return RunVerify(args[1..]);
}

if (command.Equals("analyze", StringComparison.OrdinalIgnoreCase))
{
    return RunAnalyze(args[1..]);
}

if (command.Equals("baseline", StringComparison.OrdinalIgnoreCase))
{
    return RunBaseline(args[1..]);
}

if (command.Equals("cache", StringComparison.OrdinalIgnoreCase))
{
    return RunCache(args[1..]);
}

if (command.Equals("view", StringComparison.OrdinalIgnoreCase))
{
    return RunView(args[1..]);
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

if (command.Equals("rules", StringComparison.OrdinalIgnoreCase))
{
    return RunRules(args[1..]);
}

if (command.Equals("hooks", StringComparison.OrdinalIgnoreCase))
{
    return RunHooks(args[1..]);
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

static async Task<int> RunStdinAsync(string[] args, string configSource = ".")
{
    if (!TryResolveNativeProfile(args, defaultNativeProfile: false, out bool nativeMode))
    {
        return UnknownFlagExitCode;
    }

    string? baselinePath = null;
    string? configPath = null;
    string? diagnostics = null;
    string? diagnosticsDir = null;
    string? reportPath = null;
    string? reportFormat = null;
    string? reportTemplatePath = null;
    List<string> enabledRuleIds = [];
    string gitleaksIgnorePath = ".";
    int exitCode = 1;
    int maxDecodeDepth = 5;
    int timeoutSeconds = 0;
    bool ignoreGitleaksAllow = false;
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

        if (IsProfileFlag(arg))
        {
            if (!TryReadProfileFlag(args, ref i, out _))
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

        if (IsMaxArchiveDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out _))
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

        if (IsTimeoutFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics", out diagnostics))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics-dir", out diagnosticsDir))
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

    if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, "stdin", Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
    {
        return UnknownFlagExitCode;
    }

    long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
    using var stream = new MemoryStream();
    await Console.OpenStandardInput().CopyToAsync(stream).ConfigureAwait(false);
    byte[] input = stream.ToArray();
    if (!TryLoadRules(configPath, configSource, enabledRuleIds, nativeConfig: nativeMode, out CompiledRuleSet? rules))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, configSource);
    if (IsTimedOut(timeoutTimestamp))
    {
        Console.Error.WriteLine(TimeoutErrorMessage);
        if (!TryWriteReport([], rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
        {
            return CompleteRun(1, diagnosticsSession);
        }

        return CompleteRun(1, diagnosticsSession);
    }

    IReadOnlyList<Finding> findings = baseline.Filter(
        gitleaksIgnore.Filter(SecretScanner.Scan(new ScanRequest(input, "stdin", rules, ignoreGitleaksAllow, maxDecodeDepth: maxDecodeDepth, maxTargetBytes: maxTargetBytes))),
        redactionPercent);
    if (nativeMode)
    {
        findings = OfflineSecretValidator.AnnotateAll(findings);
    }

    if (redactionPercent > 0)
    {
        findings = GitleaksFindingRedactor.Redact(findings, redactionPercent);
    }

    if (!TryWriteReport(findings, rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    return CompleteRun(findings.Count == 0 ? 0 : exitCode, diagnosticsSession);
}

static int RunScan(string[] args)
{
    var forwardedArgs = new List<string>();
    string? source = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteScanHelp();
            return 0;
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

        forwardedArgs.Add(arg);
    }

    if (source is not null)
    {
        forwardedArgs.Add(source);
    }

    return RunDirectory(
        [.. forwardedArgs],
        nativeReportFormats: true,
        diagnosticsCommand: "scan",
        defaultRoot: ".");
}

static int RunCache(string[] args)
{
    if (args.Length == 0 || IsHelp(args[0]))
    {
        WriteCacheHelp();
        return 0;
    }

    string subcommand = args[0];
    if (subcommand.Equals("stats", StringComparison.OrdinalIgnoreCase))
    {
        return RunCacheStats(args[1..]);
    }

    if (subcommand.Equals("prune", StringComparison.OrdinalIgnoreCase))
    {
        return RunCachePrune(args[1..]);
    }

    Console.Error.WriteLine($"unknown cache command: {subcommand}");
    return UnknownFlagExitCode;
}

static int RunCacheStats(string[] args)
{
    if (ContainsHelp(args))
    {
        WriteCacheStatsHelp();
        return 0;
    }

    if (!TryReadCacheOptions(
        args,
        allowPruneOptions: false,
        out string? cacheDir,
        out string? configPath,
        out string source,
        out int maxDecodeDepth,
        out long? maxTargetBytes,
        out _,
        out _))
    {
        return UnknownFlagExitCode;
    }

    if (string.IsNullOrWhiteSpace(cacheDir))
    {
        Console.Error.WriteLine("cache stats requires --cache-dir");
        return UnknownFlagExitCode;
    }

    if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, out PicketScanCache? scanCache))
    {
        return 1;
    }

    PicketScanCacheStats stats = scanCache.GetStats();
    Console.Out.WriteLine($"cache: {stats.RootPath}");
    Console.Out.WriteLine($"entries: {stats.EntryCount.ToString(CultureInfo.InvariantCulture)}");
    Console.Out.WriteLine($"current-key entries: {stats.CurrentKeyEntryCount.ToString(CultureInfo.InvariantCulture)}");
    Console.Out.WriteLine($"bytes: {stats.TotalBytes.ToString(CultureInfo.InvariantCulture)}");
    return 0;
}

static int RunCachePrune(string[] args)
{
    if (ContainsHelp(args))
    {
        WriteCachePruneHelp();
        return 0;
    }

    if (!TryReadCacheOptions(
        args,
        allowPruneOptions: true,
        out string? cacheDir,
        out string? configPath,
        out string source,
        out int maxDecodeDepth,
        out long? maxTargetBytes,
        out bool pruneOtherKeys,
        out int? olderThanDays))
    {
        return UnknownFlagExitCode;
    }

    if (string.IsNullOrWhiteSpace(cacheDir))
    {
        Console.Error.WriteLine("cache prune requires --cache-dir");
        return UnknownFlagExitCode;
    }

    if (!pruneOtherKeys && !olderThanDays.HasValue)
    {
        Console.Error.WriteLine("cache prune requires --other-keys or --older-than-days");
        return UnknownFlagExitCode;
    }

    if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, out PicketScanCache? scanCache))
    {
        return 1;
    }

    int deleted = 0;
    if (pruneOtherKeys)
    {
        deleted += scanCache.PruneOtherKeys();
    }

    if (olderThanDays.HasValue)
    {
        deleted += scanCache.PruneOlderThan(TimeSpan.FromDays(olderThanDays.Value));
    }

    Console.Out.WriteLine($"deleted: {deleted.ToString(CultureInfo.InvariantCulture)}");
    return 0;
}

static int RunVerify(string[] args)
{
    var forwardedArgs = new List<string>();
    string? source = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteVerifyHelp();
            return 0;
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

        if (IsOfflineVerificationFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--offline", out bool offline) || !offline)
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsLiveVerificationFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--live", out bool live))
            {
                return UnknownFlagExitCode;
            }

            if (live)
            {
                Console.Error.WriteLine("live verification is not implemented yet; use --offline");
                return 1;
            }

            continue;
        }

        forwardedArgs.Add(arg);
    }

    if (source is not null)
    {
        forwardedArgs.Add(source);
    }

    return RunDirectory(
        [.. forwardedArgs],
        nativeReportFormats: true,
        diagnosticsCommand: "verify",
        defaultRoot: ".",
        allowValidationResultFilters: true);
}

static int RunAnalyze(string[] args)
{
    var forwardedArgs = new List<string>();
    string? source = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteAnalyzeHelp();
            return 0;
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

        if (IsOfflineVerificationFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--offline", out bool offline) || !offline)
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsLiveVerificationFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--live", out bool live))
            {
                return UnknownFlagExitCode;
            }

            if (live)
            {
                Console.Error.WriteLine("live access analysis is not implemented yet; use --offline");
                return 1;
            }

            continue;
        }

        forwardedArgs.Add(arg);
    }

    if (source is not null)
    {
        forwardedArgs.Add(source);
    }

    return RunDirectory(
        [.. forwardedArgs],
        nativeReportFormats: true,
        diagnosticsCommand: "analyze",
        defaultRoot: ".",
        allowValidationResultFilters: true,
        nativeResultWriter: TryWriteAnalysisReports);
}

static int RunBaseline(string[] args)
{
    if (args.Length == 0 || IsHelp(args[0]))
    {
        WriteBaselineHelp();
        return 0;
    }

    string subcommand = args[0];
    if (subcommand.Equals("create", StringComparison.OrdinalIgnoreCase))
    {
        return RunBaselineCreate(args[1..]);
    }

    Console.Error.WriteLine($"unknown baseline command: {subcommand}");
    return UnknownFlagExitCode;
}

static int RunBaselineCreate(string[] args)
{
    string? configPath = null;
    string? diagnostics = null;
    string? diagnosticsDir = null;
    string? reportPath = null;
    List<string> enabledRuleIds = [];
    string gitleaksIgnorePath = ".";
    var nativeIgnorePaths = new List<string>();
    bool followSymlinks = false;
    bool ignoreGitleaksAllow = false;
    bool respectNativeIgnoreFiles = true;
    int maxArchiveDepth = 0;
    int maxDecodeDepth = 5;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    int timeoutSeconds = 0;
    string? root = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteBaselineCreateHelp();
            return 0;
        }

        if (IsSourceFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
            {
                return UnknownFlagExitCode;
            }

            if (root is not null)
            {
                Console.Error.WriteLine($"unexpected argument: {sourceValue}");
                return UnknownFlagExitCode;
            }

            root = sourceValue.Length == 0 ? "." : sourceValue;
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
            if (!TryReadStringFlag(args, ref i, "--report-format", out string? reportFormat))
            {
                return UnknownFlagExitCode;
            }

            if (!reportFormat.Equals("json", StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("baseline create only supports json report format");
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsReportTemplateFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--report-template", out _))
            {
                return UnknownFlagExitCode;
            }

            Console.Error.WriteLine("baseline create does not support report templates");
            return UnknownFlagExitCode;
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

        if (IsNativeIgnorePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--ignore-path", out string? value))
            {
                return UnknownFlagExitCode;
            }

            nativeIgnorePaths.Add(value);
            continue;
        }

        if (IsNoIgnoreFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--no-ignore", out bool disableIgnore))
            {
                return UnknownFlagExitCode;
            }

            respectNativeIgnoreFiles = !disableIgnore;
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

        if (IsMaxArchiveDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out maxArchiveDepth))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsTimeoutFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics", out diagnostics))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics-dir", out diagnosticsDir))
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

        root = arg.Length == 0 ? "." : arg;
    }

    root ??= ".";
    if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, "baseline", Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
    {
        return UnknownFlagExitCode;
    }

    long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
    if (!TryLoadRules(configPath, root, enabledRuleIds, nativeConfig: true, out CompiledRuleSet? rules))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    if (!TryLoadPicketIgnore(root, nativeIgnorePaths, respectNativeIgnoreFiles, out PicketIgnore? picketIgnore))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
        root,
        maxTargetBytes,
        followSymlinks,
        maxArchiveDepth,
        rules.IsGlobalPathAllowed,
        readPicketIgnoreFiles: respectNativeIgnoreFiles,
        readIgnoreFiles: respectNativeIgnoreFiles,
        readGitIgnoreFiles: respectNativeIgnoreFiles,
        readGlobalGitIgnore: respectNativeIgnoreFiles,
        ignoreHidden: respectNativeIgnoreFiles,
        readParentIgnoreFiles: respectNativeIgnoreFiles,
        ignoreFilePaths: respectNativeIgnoreFiles ? nativeIgnorePaths : []));
    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    string? configDisplayPath = CreateControlFileDisplayPath(root, ResolveConfigControlPath(configPath, root));
    string? reportDisplayPath = CreateControlFileDisplayPath(root, reportPath);
    List<string?> nativeIgnoreDisplayPaths = respectNativeIgnoreFiles
        ? CreateControlFileDisplayPaths(root, reportPath: null, nativeIgnorePaths)
        : [];
    var findings = new List<Finding>();
    bool hadScanError = false;
    foreach (SourceFile file in files)
    {
        if (IsTimedOut(timeoutTimestamp))
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            hadScanError = true;
            break;
        }

        if (IsControlFile(file, [configDisplayPath, reportDisplayPath, .. nativeIgnoreDisplayPaths])
            || (respectNativeIgnoreFiles && IsNativeIgnoreFile(file)))
        {
            continue;
        }

        try
        {
            byte[] input = file.ReadAllBytes();
            if (picketIgnore.IsContentHashIgnored(input))
            {
                continue;
            }

            if (LooksBinary(input))
            {
                continue;
            }

            findings.AddRange(SecretScanner.Scan(new ScanRequest(
                input,
                file.DisplayPath,
                rules,
                ignoreGitleaksAllow,
                maxDecodeDepth: maxDecodeDepth,
                maxTargetBytes: maxTargetBytes,
                symlinkFile: file.SymlinkDisplayPath)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            hadScanError = true;
        }
    }

    IReadOnlyList<Finding> filteredFindings = gitleaksIgnore.Filter(findings);
    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    if (!TryWriteReport(filteredFindings, rules.Rules, reportPath, "json", reportTemplatePath: null))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    return CompleteRun(hadScanError ? 1 : 0, diagnosticsSession);
}

static int RunView(string[] args)
{
    if (args.Length == 0 || IsHelp(args[0]))
    {
        WriteViewHelp();
        return 0;
    }

    bool open = false;
    string? reportPath = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteViewHelp();
            return 0;
        }

        if (IsOpenFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--open", out open))
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

        if (reportPath is not null)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return UnknownFlagExitCode;
        }

        reportPath = arg;
    }

    if (string.IsNullOrWhiteSpace(reportPath))
    {
        Console.Error.WriteLine("view requires a report path");
        return UnknownFlagExitCode;
    }

    if (IsHtmlReportPath(reportPath))
    {
        if (!File.Exists(reportPath))
        {
            Console.Error.WriteLine($"could not open {reportPath}");
            return 1;
        }

        WriteHtmlViewSummary(reportPath);
        return open && !TryOpenReport(reportPath) ? 1 : 0;
    }

    ReportSummary summary;
    try
    {
        summary = ReportSummaryReader.Read(reportPath);
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    WriteReportViewSummary(reportPath, summary);
    return open && !TryOpenReport(reportPath) ? 1 : 0;
}

static int RunDirectory(
    string[] args,
    bool nativeReportFormats = false,
    string diagnosticsCommand = "dir",
    string? defaultRoot = null,
    bool allowValidationResultFilters = false,
    Func<IReadOnlyList<Finding>, string?, IReadOnlyList<string>, string?, string?, bool>? nativeResultWriter = null)
{
    if (!TryResolveNativeProfile(args, nativeReportFormats, out bool nativeMode))
    {
        return UnknownFlagExitCode;
    }

    string? baselinePath = null;
    string? cacheDir = null;
    string? configPath = null;
    string? diagnostics = null;
    string? diagnosticsDir = null;
    string? reportPath = null;
    string? reportFormat = null;
    string? reportTemplatePath = null;
    var reportPaths = new List<string>();
    var validationResults = new HashSet<string>(StringComparer.Ordinal);
    List<string> enabledRuleIds = [];
    string gitleaksIgnorePath = ".";
    var nativeIgnorePaths = new List<string>();
    int exitCode = 1;
    bool followSymlinks = false;
    bool ignoreGitleaksAllow = false;
    bool respectNativeIgnoreFiles = nativeMode;
    int maxArchiveDepth = 0;
    int maxDecodeDepth = 5;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    int timeoutSeconds = 0;
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

        if (IsProfileFlag(arg))
        {
            if (!TryReadProfileFlag(args, ref i, out _))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (nativeMode && IsCacheDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--cache-dir", out cacheDir))
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

        if (nativeMode && IsNativeIgnorePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--ignore-path", out string? value))
            {
                return UnknownFlagExitCode;
            }

            nativeIgnorePaths.Add(value);
            continue;
        }

        if (nativeMode && IsNoIgnoreFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--no-ignore", out bool disableIgnore))
            {
                return UnknownFlagExitCode;
            }

            respectNativeIgnoreFiles = !disableIgnore;
            continue;
        }

        if (allowValidationResultFilters && IsValidationResultsFlag(arg))
        {
            if (!TryReadValidationResultsFlag(args, ref i, validationResults))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (allowValidationResultFilters && IsOnlyVerifiedFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--only-verified", out bool onlyVerified))
            {
                return UnknownFlagExitCode;
            }

            if (onlyVerified)
            {
                validationResults.Clear();
                validationResults.Add("structurally-valid");
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

        if (IsMaxArchiveDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out maxArchiveDepth))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsTimeoutFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics", out diagnostics))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics-dir", out diagnosticsDir))
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
        if (defaultRoot is null)
        {
            Console.Error.WriteLine("dir requires a path");
            return UnknownFlagExitCode;
        }

        root = defaultRoot;
    }

    if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, diagnosticsCommand, Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
    {
        return UnknownFlagExitCode;
    }

    long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
    if (!TryLoadRules(configPath, root, enabledRuleIds, nativeConfig: nativeMode, out CompiledRuleSet? rules))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    PicketScanCache? scanCache = null;
    if (nativeMode && !string.IsNullOrWhiteSpace(cacheDir))
    {
        try
        {
            scanCache = PicketScanCache.Open(cacheDir, ScanCacheKey.Create(rules.Fingerprint, maxDecodeDepth, maxTargetBytes));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"failed to open cache: {ex.Message}");
            return CompleteRun(1, diagnosticsSession);
        }
    }

    if (!TryLoadPicketIgnore(root, nativeIgnorePaths, respectNativeIgnoreFiles, out PicketIgnore? picketIgnore))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(
        root,
        maxTargetBytes,
        followSymlinks,
        maxArchiveDepth,
        rules.IsGlobalPathAllowed,
        readPicketIgnoreFiles: respectNativeIgnoreFiles,
        readIgnoreFiles: respectNativeIgnoreFiles,
        readGitIgnoreFiles: respectNativeIgnoreFiles,
        readGlobalGitIgnore: respectNativeIgnoreFiles,
        ignoreHidden: respectNativeIgnoreFiles,
        readParentIgnoreFiles: respectNativeIgnoreFiles,
        ignoreFilePaths: respectNativeIgnoreFiles ? nativeIgnorePaths : []));
    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    string? baselineDisplayPath = CreateControlFileDisplayPath(root, baselinePath);
    string? configDisplayPath = CreateControlFileDisplayPath(root, ResolveConfigControlPath(configPath, root));
    List<string?> reportDisplayPaths = CreateControlFileDisplayPaths(root, reportPath, reportPaths);
    List<string?> nativeIgnoreDisplayPaths = respectNativeIgnoreFiles
        ? CreateControlFileDisplayPaths(root, reportPath: null, nativeIgnorePaths)
        : [];
    string? cacheDisplayPath = nativeMode ? CreateControlFileDisplayPath(root, cacheDir) : null;
    var findings = new List<Finding>();
    bool hadScanError = false;
    foreach (SourceFile file in files)
    {
        if (IsTimedOut(timeoutTimestamp))
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            hadScanError = true;
            break;
        }

        if (IsControlFile(file, [baselineDisplayPath, configDisplayPath, .. reportDisplayPaths, .. nativeIgnoreDisplayPaths])
            || IsControlDirectoryFile(file, cacheDisplayPath)
            || (respectNativeIgnoreFiles && IsNativeIgnoreFile(file)))
        {
            continue;
        }

        try
        {
            byte[] input = file.ReadAllBytes();
            if (picketIgnore.IsContentHashIgnored(input))
            {
                continue;
            }

            if (LooksBinary(input))
            {
                continue;
            }

            if (scanCache is not null && scanCache.TryRead(input, file.DisplayPath, file.SymlinkDisplayPath, out List<Finding>? cachedFindings))
            {
                findings.AddRange(cachedFindings);
                continue;
            }

            IReadOnlyList<Finding> scannedFindings = SecretScanner.Scan(new ScanRequest(
                input,
                file.DisplayPath,
                rules,
                ignoreGitleaksAllow,
                maxDecodeDepth: maxDecodeDepth,
                maxTargetBytes: maxTargetBytes,
                symlinkFile: file.SymlinkDisplayPath));
            findings.AddRange(scannedFindings);
            scanCache?.Write(input, file.DisplayPath, scannedFindings);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            hadScanError = true;
        }
    }

    IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
    if (nativeMode)
    {
        filteredFindings = OfflineSecretValidator.AnnotateAll(filteredFindings);
    }

    if (validationResults.Count != 0)
    {
        filteredFindings = FilterValidationResults(filteredFindings, validationResults);
    }

    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    bool wroteResults = nativeResultWriter is null
        ? TryWriteReports(filteredFindings, rules.Rules, reportPath, reportPaths, reportFormat, reportTemplatePath, nativeMode)
        : nativeResultWriter(filteredFindings, reportPath, reportPaths, reportFormat, reportTemplatePath);
    if (!wroteResults)
    {
        return CompleteRun(1, diagnosticsSession);
    }

    if (hadScanError)
    {
        return CompleteRun(1, diagnosticsSession);
    }

    return CompleteRun(filteredFindings.Count == 0 ? 0 : exitCode, diagnosticsSession);
}

static int RunGit(string[] args)
{
    if (!TryResolveNativeProfile(args, defaultNativeProfile: false, out bool nativeMode))
    {
        return UnknownFlagExitCode;
    }

    string? baselinePath = null;
    string? configPath = null;
    string? diagnostics = null;
    string? diagnosticsDir = null;
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
    int maxArchiveDepth = 0;
    int maxDecodeDepth = 5;
    bool preCommit = false;
    bool rootProvided = false;
    bool staged = false;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    int timeoutSeconds = 0;
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

        if (IsProfileFlag(arg))
        {
            if (!TryReadProfileFlag(args, ref i, out _))
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

        if (IsMaxArchiveDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out maxArchiveDepth))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsTimeoutFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics", out diagnostics))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsDiagnosticsDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--diagnostics-dir", out diagnosticsDir))
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

    if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, "git", Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
    {
        return UnknownFlagExitCode;
    }

    if (!TryLoadRules(configPath, root, enabledRuleIds, nativeConfig: nativeMode, out CompiledRuleSet? rules))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
    IReadOnlyList<GitPatchFragment> fragments;
    try
    {
        fragments = GitSource.Enumerate(new GitScanOptions(
            root,
            logOptions,
            staged,
            preCommit,
            maxArchiveDepth,
            maxTargetBytes,
            rules.IsGlobalPathAllowed));
    }
    catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        return CompleteRun(1, diagnosticsSession);
    }

    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    CreateGitLinkContext(root, staged || preCommit, platform, out string scmPlatform, out string remoteUrl);
    List<Finding> findings = ScanGitFragments(fragments, rules, ignoreGitleaksAllow, maxTargetBytes, maxDecodeDepth, timeoutTimestamp, scmPlatform, remoteUrl, out bool timedOut);
    IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
    if (nativeMode)
    {
        filteredFindings = OfflineSecretValidator.AnnotateAll(filteredFindings);
    }

    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    if (!TryWriteReport(filteredFindings, rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
    {
        return CompleteRun(1, diagnosticsSession);
    }

    if (timedOut)
    {
        Console.Error.WriteLine(TimeoutErrorMessage);
        return CompleteRun(1, diagnosticsSession);
    }

    return CompleteRun(filteredFindings.Count == 0 ? 0 : exitCode, diagnosticsSession);
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

static int RunHooks(string[] args)
{
    if (args.Length == 0 || IsHelp(args[0]))
    {
        WriteHooksHelp();
        return 0;
    }

    string subcommand = args[0];
    if (subcommand.Equals("install", StringComparison.OrdinalIgnoreCase))
    {
        return RunHooksInstall(args[1..]);
    }

    Console.Error.WriteLine($"unknown hooks command: {subcommand}");
    return UnknownFlagExitCode;
}

static int RunHooksInstall(string[] args)
{
    if (args.Length != 0 && IsHelp(args[0]))
    {
        WriteHooksInstallHelp();
        return 0;
    }

    string? baselinePath = null;
    string? configPath = null;
    string? maxTargetMegabytes = null;
    string commandPath = "picket";
    string repo = ".";
    int redactionPercent = 100;
    bool force = false;
    List<string> hookNames = [];
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsBaselinePathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--baseline-path", out baselinePath))
            {
                return UnknownFlagExitCode;
            }

            baselinePath = Path.GetFullPath(baselinePath);
            continue;
        }

        if (IsConfigFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--config", out configPath))
            {
                return UnknownFlagExitCode;
            }

            configPath = Path.GetFullPath(configPath);
            continue;
        }

        if (IsHookCommandFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--command", out string? commandValue))
            {
                return UnknownFlagExitCode;
            }

            commandPath = commandValue;
            if (commandPath.Length == 0)
            {
                Console.Error.WriteLine("--command requires a non-empty value");
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsForceFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--force", out force))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsHooksRepoFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--repo", out string? repoValue))
            {
                return UnknownFlagExitCode;
            }

            repo = repoValue.Length == 0 ? "." : repoValue;
            continue;
        }

        if (IsMaxTargetMegabytesFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--max-target-megabytes", out maxTargetMegabytes)
                || !TryParseMegabytes(maxTargetMegabytes, out _))
            {
                Console.Error.WriteLine("--max-target-megabytes requires a non-negative integer value");
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

        if (!TryAddHookName(hookNames, arg))
        {
            return UnknownFlagExitCode;
        }
    }

    if (hookNames.Count == 0)
    {
        hookNames.Add("pre-commit");
    }

    string hooksDirectory;
    try
    {
        hooksDirectory = ResolveHooksDirectory(repo);
    }
    catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    var options = (
        CommandPath: commandPath,
        ConfigPath: configPath,
        BaselinePath: baselinePath,
        MaxTargetMegabytes: maxTargetMegabytes,
        RedactionPercent: redactionPercent);
    foreach (string hookName in hookNames)
    {
        string script = CreateHookScript(hookName, options);
        if (!TryWriteHook(hooksDirectory, hookName, script, force))
        {
            return 1;
        }
    }

    return 0;
}

static bool TryAddHookName(List<string> hookNames, string hookName)
{
    string normalizedHookName = hookName.ToLowerInvariant();
    if (normalizedHookName.Equals("all", StringComparison.Ordinal))
    {
        return TryAddHookName(hookNames, "pre-commit")
            && TryAddHookName(hookNames, "pre-push")
            && TryAddHookName(hookNames, "pre-receive");
    }

    if (normalizedHookName is not ("pre-commit" or "pre-push" or "pre-receive"))
    {
        Console.Error.WriteLine($"unsupported hook: {hookName}");
        return false;
    }

    if (!hookNames.Contains(normalizedHookName, StringComparer.Ordinal))
    {
        hookNames.Add(normalizedHookName);
    }

    return true;
}

static string ResolveHooksDirectory(string repo)
{
    string repositoryPath = Path.GetFullPath(repo.Length == 0 ? "." : repo);
    string dotGitPath = Path.Combine(repositoryPath, ".git");
    if (Directory.Exists(dotGitPath))
    {
        return Path.Combine(dotGitPath, "hooks");
    }

    if (File.Exists(dotGitPath))
    {
        string gitDir = ReadGitDirectoryFile(repositoryPath, dotGitPath);
        return Path.Combine(gitDir, "hooks");
    }

    if (File.Exists(Path.Combine(repositoryPath, "HEAD"))
        && Directory.Exists(Path.Combine(repositoryPath, "objects")))
    {
        return Path.Combine(repositoryPath, "hooks");
    }

    throw new DirectoryNotFoundException($"{repositoryPath} is not a git repository or bare repository");
}

static string ReadGitDirectoryFile(string repositoryPath, string dotGitPath)
{
    string text = File.ReadAllText(dotGitPath).Trim();
    const string Prefix = "gitdir:";
    if (!text.StartsWith(Prefix, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"{dotGitPath} is not a supported gitdir file");
    }

    string gitDir = text[Prefix.Length..].Trim();
    if (Path.IsPathRooted(gitDir))
    {
        return Path.GetFullPath(gitDir);
    }

    return Path.GetFullPath(Path.Combine(repositoryPath, gitDir));
}

static bool TryWriteHook(string hooksDirectory, string hookName, string script, bool force)
{
    Directory.CreateDirectory(hooksDirectory);
    string hookPath = Path.Combine(hooksDirectory, hookName);
    if (File.Exists(hookPath) && !force && !File.ReadAllText(hookPath).Contains(ManagedHookMarker, StringComparison.Ordinal))
    {
        Console.Error.WriteLine($"{hookPath} already exists and was not created by Picket; use --force to overwrite it");
        return false;
    }

    File.WriteAllText(hookPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    TrySetHookExecutable(hookPath);
    Console.Out.WriteLine($"installed {hookName}: {hookPath}");
    return true;
}

static void TrySetHookExecutable(string hookPath)
{
    if (OperatingSystem.IsWindows())
    {
        return;
    }

    try
    {
        File.SetUnixFileMode(
            hookPath,
            UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead
                | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead
                | UnixFileMode.OtherExecute);
    }
    catch (IOException)
    {
    }
    catch (UnauthorizedAccessException)
    {
    }
}

static string CreateHookScript(
    string hookName,
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
{
    return hookName switch
    {
        "pre-commit" => CreatePreCommitHookScript(options),
        "pre-push" => CreatePrePushHookScript(options),
        "pre-receive" => CreatePreReceiveHookScript(options),
        _ => throw new InvalidOperationException($"unsupported hook: {hookName}"),
    };
}

static string CreatePreCommitHookScript(
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
{
    var builder = new StringBuilder();
    AppendHookHeader(builder);
    builder.Append("repo_root=$(git rev-parse --show-toplevel)\n");
    builder.Append("exec ");
    builder.Append(QuoteShell(options.CommandPath));
    builder.Append(" protect --source \"$repo_root\"");
    AppendHookScanOptions(builder, options);
    builder.Append('\n');
    return builder.ToString();
}

static string CreatePrePushHookScript(
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
{
    var builder = new StringBuilder();
    AppendHookHeader(builder);
    builder.Append("repo_root=$(git rev-parse --show-toplevel)\n");
    AppendHookRangeLoop(builder, options, "local_ref local_sha remote_ref remote_sha", "remote_sha", "local_sha");
    return builder.ToString();
}

static string CreatePreReceiveHookScript(
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
{
    var builder = new StringBuilder();
    AppendHookHeader(builder);
    builder.Append("git_dir=$(git rev-parse --git-dir)\n");
    builder.Append("case \"$git_dir\" in\n");
    builder.Append("  /*) repo_root=$git_dir ;;\n");
    builder.Append("  *) repo_root=$(pwd -P)/$git_dir ;;\n");
    builder.Append("esac\n");
    AppendHookRangeLoop(builder, options, "old_sha new_sha ref_name", "old_sha", "new_sha");
    return builder.ToString();
}

static void AppendHookHeader(StringBuilder builder)
{
    builder.Append("#!/bin/sh\n");
    builder.Append(ManagedHookMarker);
    builder.Append('\n');
    builder.Append("set -eu\n");
    builder.Append("zero=0000000000000000000000000000000000000000\n");
}

static void AppendHookRangeLoop(
    StringBuilder builder,
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options,
    string readVariables,
    string oldShaVariable,
    string newShaVariable)
{
    builder.Append("status=0\n");
    builder.Append("while read ");
    builder.Append(readVariables);
    builder.Append('\n');
    builder.Append("do\n");
    builder.Append("  [ \"$");
    builder.Append(newShaVariable);
    builder.Append("\" = \"$zero\" ] && continue\n");
    builder.Append("  if [ \"$");
    builder.Append(oldShaVariable);
    builder.Append("\" = \"$zero\" ]; then\n");
    builder.Append("    range=\"$");
    builder.Append(newShaVariable);
    builder.Append("\"\n");
    builder.Append("  else\n");
    builder.Append("    range=\"$");
    builder.Append(oldShaVariable);
    builder.Append("..$");
    builder.Append(newShaVariable);
    builder.Append("\"\n");
    builder.Append("  fi\n");
    builder.Append("  ");
    builder.Append(QuoteShell(options.CommandPath));
    builder.Append(" git \"$repo_root\" --log-opts \"$range\"");
    AppendHookScanOptions(builder, options);
    builder.Append(" || status=$?\n");
    builder.Append("done\n");
    builder.Append("exit \"$status\"\n");
}

static void AppendHookScanOptions(
    StringBuilder builder,
    (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
{
    AppendHookOption(builder, "--config", options.ConfigPath);
    AppendHookOption(builder, "--baseline-path", options.BaselinePath);
    AppendHookOption(builder, "--max-target-megabytes", options.MaxTargetMegabytes);
    builder.Append(' ');
    builder.Append(QuoteShell($"--redact={options.RedactionPercent.ToString(CultureInfo.InvariantCulture)}"));
}

static void AppendHookOption(StringBuilder builder, string name, string? value)
{
    if (string.IsNullOrEmpty(value))
    {
        return;
    }

    builder.Append(' ');
    builder.Append(name);
    builder.Append(' ');
    builder.Append(QuoteShell(value));
}

static string QuoteShell(string value)
{
    return string.Concat('\'', value.Replace("'", "'\"'\"'", StringComparison.Ordinal), '\'');
}

static bool IsHelp(string arg)
{
    return arg is "-h" or "--help" or "help";
}

static bool ContainsHelp(string[] args)
{
    for (int i = 0; i < args.Length; i++)
    {
        if (IsHelp(args[i]))
        {
            return true;
        }
    }

    return false;
}

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
    string? configPath = null;
    string fileName = "rules-test.txt";
    var positional = new List<string>(2);
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteRulesTestHelp();
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

        if (IsRulesTestPathFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--path", out string? pathValue))
            {
                return UnknownFlagExitCode;
            }

            fileName = pathValue;
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
        RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(configPath, ".");
        ValidateRulesWithScout(ruleSet);
        RuleSet selectedRuleSet = FilterEnabledRules(ruleSet, [ruleId]);
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
            inputBytes,
            fileName,
            CompiledRuleSet.Compile(selectedRuleSet)));
        Console.Out.Write(GitleaksJsonReportWriter.Write(findings));
        return 0;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
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
    int maxDecodeDepth,
    long timeoutTimestamp,
    string scmPlatform,
    string remoteUrl,
    out bool timedOut)
{
    timedOut = false;
    var findings = new List<Finding>();
    foreach (GitPatchFragment fragment in fragments)
    {
        if (IsTimedOut(timeoutTimestamp))
        {
            timedOut = true;
            break;
        }

        IReadOnlyList<Finding> fragmentFindings = SecretScanner.Scan(new ScanRequest(
            fragment.Input,
            fragment.FilePath,
            rules,
            ignoreGitleaksAllow,
            fragment.Commit,
            maxDecodeDepth,
            maxTargetBytes));
        foreach (Finding finding in fragmentFindings)
        {
            findings.Add(MapGitFinding(finding, fragment, scmPlatform, remoteUrl));
        }
    }

    return findings;
}

static Finding MapGitFinding(Finding finding, GitPatchFragment fragment, string scmPlatform, string remoteUrl)
{
    int startLine = MapGitLine(fragment, finding.StartLine);
    int endLine = MapGitLine(fragment, finding.EndLine);
    string link = CreateScmLink(scmPlatform, remoteUrl, finding.File, fragment.Commit, startLine, endLine);
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
        finding.Line,
        link,
        finding.SecretSha256,
        finding.MatchSha256,
        finding.ValidationState,
        finding.BlobSha256,
        finding.DecodePath);
}

static void CreateGitLinkContext(string root, bool disableLinks, string? platform, out string scmPlatform, out string remoteUrl)
{
    scmPlatform = disableLinks ? "none" : NormalizeScmPlatform(platform);
    remoteUrl = string.Empty;
    if (scmPlatform == "none")
    {
        return;
    }

    if (!TryReadGitRemoteUrl(root, out remoteUrl))
    {
        return;
    }

    if (scmPlatform == "unknown")
    {
        scmPlatform = GetScmPlatformFromRemoteUrl(remoteUrl);
    }
}

static bool TryReadGitRemoteUrl(string root, out string remoteUrl)
{
    using var process = new Process
    {
        StartInfo = new ProcessStartInfo("git")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        },
    };
    AddGitRemoteArguments(process.StartInfo, "-C", root, "ls-remote", "--quiet", "--get-url");
    try
    {
        if (!process.Start())
        {
            remoteUrl = string.Empty;
            return false;
        }
    }
    catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
    {
        remoteUrl = string.Empty;
        return false;
    }

    string output = process.StandardOutput.ReadToEnd().Trim();
    _ = process.StandardError.ReadToEnd();
    process.WaitForExit();
    remoteUrl = process.ExitCode == 0 ? NormalizeRemoteUrl(output) : string.Empty;
    return remoteUrl.Length != 0;
}

static void AddGitRemoteArguments(ProcessStartInfo startInfo, params string[] arguments)
{
    foreach (string argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }
}

static string NormalizeRemoteUrl(string remoteUrl)
{
    if (TryNormalizeSshRemoteUrl(remoteUrl, out string sshRemoteUrl))
    {
        remoteUrl = sshRemoteUrl;
    }

    if (remoteUrl.EndsWith(".git", StringComparison.Ordinal))
    {
        remoteUrl = remoteUrl[..^".git".Length];
    }

    if (!Uri.TryCreate(remoteUrl, UriKind.Absolute, out Uri? uri) || uri.UserInfo.Length == 0)
    {
        return remoteUrl;
    }

    var builder = new UriBuilder(uri)
    {
        UserName = string.Empty,
        Password = string.Empty,
    };
    return builder.Uri.AbsoluteUri.TrimEnd('/');
}

static bool TryNormalizeSshRemoteUrl(string remoteUrl, out string normalizedRemoteUrl)
{
    const string prefix = "git@";
    if (!remoteUrl.StartsWith(prefix, StringComparison.Ordinal))
    {
        normalizedRemoteUrl = string.Empty;
        return false;
    }

    int separatorIndex = remoteUrl.IndexOf(':', prefix.Length);
    if (separatorIndex < 0)
    {
        normalizedRemoteUrl = string.Empty;
        return false;
    }

    string host = remoteUrl[prefix.Length..separatorIndex];
    string path = remoteUrl[(separatorIndex + 1)..];
    int pathSlashIndex = path.IndexOf('/');
    if (pathSlashIndex > 0 && IsAllDigits(path.AsSpan(0, pathSlashIndex)))
    {
        path = path[(pathSlashIndex + 1)..];
    }

    if (host.Length == 0 || path.Length == 0)
    {
        normalizedRemoteUrl = string.Empty;
        return false;
    }

    normalizedRemoteUrl = $"https://{host}/{path}";
    return true;
}

static bool IsAllDigits(ReadOnlySpan<char> value)
{
    for (int i = 0; i < value.Length; i++)
    {
        if (!char.IsDigit(value[i]))
        {
            return false;
        }
    }

    return value.Length != 0;
}

static string CreateScmLink(string scmPlatform, string remoteUrl, string filePath, string commit, int startLine, int endLine)
{
    if (commit.Length == 0 || remoteUrl.Length == 0 || scmPlatform is "unknown" or "none")
    {
        return string.Empty;
    }

    bool hasInnerPath = filePath.Contains('!');
    filePath = CleanLinkFilePath(filePath);
    return scmPlatform switch
    {
        "github" => CreateGitHubLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
        "gitlab" => CreateGitLabLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
        "azuredevops" => CreateAzureDevOpsLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
        "gitea" => CreateGiteaLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
        "bitbucket" => CreateBitbucketLink(remoteUrl, commit, filePath, startLine, endLine, hasInnerPath),
        _ => string.Empty,
    };
}

static string CreateGitHubLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
{
    string link = $"{remoteUrl}/blob/{commit}/{filePath}";
    if (hasInnerPath)
    {
        return link;
    }

    if (IsPlainDisplaySource(filePath))
    {
        link += "?plain=1";
    }

    return AppendLineFragment(link, startLine, endLine, "#L", "-L");
}

static string CreateGitLabLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
{
    string link = $"{remoteUrl}/blob/{commit}/{filePath}";
    return hasInnerPath ? link : AppendLineFragment(link, startLine, endLine, "#L", "-");
}

static string CreateAzureDevOpsLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
{
    string link = $"{remoteUrl}/commit/{commit}?path=/{filePath}";
    if (hasInnerPath)
    {
        return link;
    }

    if (startLine != 0)
    {
        link += $"&line={startLine}";
    }

    if (endLine != startLine)
    {
        link += $"&lineEnd={endLine}";
    }

    return link + "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files";
}

static string CreateGiteaLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
{
    string link = $"{remoteUrl}/src/commit/{commit}/{filePath}";
    if (hasInnerPath)
    {
        return link;
    }

    if (IsPlainDisplaySource(filePath))
    {
        link += "?display=source";
    }

    return AppendLineFragment(link, startLine, endLine, "#L", "-L");
}

static string CreateBitbucketLink(string remoteUrl, string commit, string filePath, int startLine, int endLine, bool hasInnerPath)
{
    string link = $"{remoteUrl}/src/{commit}/{filePath}";
    return hasInnerPath ? link : AppendLineFragment(link, startLine, endLine, "#lines-", ":");
}

static string AppendLineFragment(string link, int startLine, int endLine, string startPrefix, string endPrefix)
{
    if (startLine != 0)
    {
        link += $"{startPrefix}{startLine}";
    }

    if (endLine != startLine)
    {
        link += $"{endPrefix}{endLine}";
    }

    return link;
}

static string CleanLinkFilePath(string filePath)
{
    int innerPathIndex = filePath.IndexOf('!');
    if (innerPathIndex >= 0)
    {
        filePath = filePath[..innerPathIndex];
    }

    return filePath.Replace("%", "%25", StringComparison.Ordinal).Replace(" ", "%20", StringComparison.Ordinal);
}

static bool IsPlainDisplaySource(string filePath)
{
    string extension = Path.GetExtension(filePath);
    return extension.Equals(".ipynb", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".md", StringComparison.OrdinalIgnoreCase);
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

static long CreateTimeoutTimestamp(int timeoutSeconds)
{
    return timeoutSeconds == 0 ? 0 : Stopwatch.GetTimestamp() + timeoutSeconds * Stopwatch.Frequency;
}

static bool IsTimedOut(long timeoutTimestamp)
{
    return timeoutTimestamp != 0 && Stopwatch.GetTimestamp() >= timeoutTimestamp;
}

static int CompleteRun(int exitCode, CompatibilityDiagnosticsSession? diagnosticsSession)
{
    if (diagnosticsSession is null)
    {
        return exitCode;
    }

    return diagnosticsSession.TryComplete(exitCode, Console.Error) ? exitCode : 1;
}

static bool LooksBinary(ReadOnlySpan<byte> input)
{
    int length = Math.Min(input.Length, BinaryProbeLength);
    for (int i = 0; i < length; i++)
    {
        if (input[i] == 0)
        {
            return true;
        }
    }

    return false;
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

static bool TryResolveNativeProfile(string[] args, bool defaultNativeProfile, out bool nativeProfile)
{
    nativeProfile = defaultNativeProfile;
    for (int i = 0; i < args.Length; i++)
    {
        if (!IsProfileFlag(args[i]))
        {
            continue;
        }

        if (!TryReadProfileFlag(args, ref i, out bool parsedNativeProfile))
        {
            return false;
        }

        nativeProfile = parsedNativeProfile;
    }

    return true;
}

static bool TryReadProfileFlag(string[] args, ref int index, out bool nativeProfile)
{
    nativeProfile = false;
    if (!TryReadStringFlag(args, ref index, "--profile", out string? value))
    {
        return false;
    }

    if (value.Equals("picket", StringComparison.OrdinalIgnoreCase))
    {
        nativeProfile = true;
        return true;
    }

    Console.Error.WriteLine($"unsupported profile: {value}");
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

static bool TryReadValidationResultsFlag(string[] args, ref int index, HashSet<string> validationResults)
{
    if (!TryReadStringFlag(args, ref index, "--results", out string? value))
    {
        return false;
    }

    foreach (string result in value.Split(','))
    {
        string normalizedResult = result.Trim();
        if (normalizedResult.Length == 0)
        {
            continue;
        }

        if (!IsSupportedValidationResult(normalizedResult))
        {
            Console.Error.WriteLine($"unsupported verification result: {normalizedResult}");
            return false;
        }

        validationResults.Add(normalizedResult);
    }

    if (validationResults.Count != 0)
    {
        return true;
    }

    Console.Error.WriteLine("--results requires at least one verification result");
    return false;
}

static bool TryReadCacheOptions(
    string[] args,
    bool allowPruneOptions,
    out string? cacheDir,
    out string? configPath,
    out string source,
    out int maxDecodeDepth,
    out long? maxTargetBytes,
    out bool pruneOtherKeys,
    out int? olderThanDays)
{
    cacheDir = null;
    configPath = null;
    source = ".";
    maxDecodeDepth = 5;
    maxTargetBytes = null;
    pruneOtherKeys = false;
    olderThanDays = null;
    bool sourceRead = false;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsCacheDirFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--cache-dir", out cacheDir))
            {
                return false;
            }

            continue;
        }

        if (IsConfigFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--config", out configPath))
            {
                return false;
            }

            continue;
        }

        if (IsSourceFlag(arg))
        {
            if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
            {
                return false;
            }

            source = sourceValue.Length == 0 ? "." : sourceValue;
            sourceRead = true;
            continue;
        }

        if (IsMaxDecodeDepthFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
            {
                return false;
            }

            continue;
        }

        if (IsMaxTargetMegabytesFlag(arg))
        {
            if (!TryReadMegabytesFlag(args, ref i, out maxTargetBytes))
            {
                return false;
            }

            continue;
        }

        if (allowPruneOptions && IsOtherKeysFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--other-keys", out pruneOtherKeys))
            {
                return false;
            }

            continue;
        }

        if (allowPruneOptions && IsOlderThanDaysFlag(arg))
        {
            if (!TryReadNonNegativeIntFlag(args, ref i, "--older-than-days", out int value))
            {
                return false;
            }

            olderThanDays = value;
            continue;
        }

        if (arg.StartsWith('-'))
        {
            Console.Error.WriteLine($"unknown flag: {arg}");
            return false;
        }

        if (sourceRead)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return false;
        }

        source = arg.Length == 0 ? "." : arg;
        sourceRead = true;
    }

    return true;
}

static bool IsSupportedValidationResult(string value)
{
    return value is "unknown" or "structurally-valid" or "test-credential" or "invalid";
}

static List<Finding> FilterValidationResults(IReadOnlyList<Finding> findings, HashSet<string> validationResults)
{
    var filtered = new List<Finding>(findings.Count);
    for (int i = 0; i < findings.Count; i++)
    {
        Finding finding = findings[i];
        string validationState = finding.ValidationState.Length == 0 ? "unknown" : finding.ValidationState;
        if (validationResults.Contains(validationState))
        {
            filtered.Add(finding);
        }
    }

    return filtered;
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

static bool IsCacheDirFlag(string arg)
{
    return arg.Equals("--cache-dir", StringComparison.Ordinal)
        || arg.StartsWith("--cache-dir=", StringComparison.Ordinal);
}

static bool IsOtherKeysFlag(string arg)
{
    return arg.Equals("--other-keys", StringComparison.Ordinal)
        || arg.StartsWith("--other-keys=", StringComparison.Ordinal);
}

static bool IsOlderThanDaysFlag(string arg)
{
    return arg.Equals("--older-than-days", StringComparison.Ordinal)
        || arg.StartsWith("--older-than-days=", StringComparison.Ordinal);
}

static bool IsRulesTestPathFlag(string arg)
{
    return arg.Equals("--path", StringComparison.Ordinal)
        || arg.StartsWith("--path=", StringComparison.Ordinal);
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

static bool IsOfflineVerificationFlag(string arg)
{
    return arg.Equals("--offline", StringComparison.Ordinal)
        || arg.StartsWith("--offline=", StringComparison.Ordinal);
}

static bool IsLiveVerificationFlag(string arg)
{
    return arg.Equals("--live", StringComparison.Ordinal)
        || arg.StartsWith("--live=", StringComparison.Ordinal);
}

static bool IsValidationResultsFlag(string arg)
{
    return arg.Equals("--results", StringComparison.Ordinal)
        || arg.StartsWith("--results=", StringComparison.Ordinal);
}

static bool IsOnlyVerifiedFlag(string arg)
{
    return arg.Equals("--only-verified", StringComparison.Ordinal)
        || arg.StartsWith("--only-verified=", StringComparison.Ordinal);
}

static bool IsPrintConfigFlag(string arg)
{
    return arg.Equals("--print-config", StringComparison.Ordinal)
        || arg.StartsWith("--print-config=", StringComparison.Ordinal);
}

static bool IsSourceFlag(string arg)
{
    return arg is "-s" or "--source"
        || arg.StartsWith("--source=", StringComparison.Ordinal);
}

static bool IsProfileFlag(string arg)
{
    return arg.Equals("--profile", StringComparison.Ordinal)
        || arg.StartsWith("--profile=", StringComparison.Ordinal);
}

static bool IsHooksRepoFlag(string arg)
{
    return arg.Equals("--repo", StringComparison.Ordinal)
        || arg.StartsWith("--repo=", StringComparison.Ordinal);
}

static bool IsHookCommandFlag(string arg)
{
    return arg.Equals("--command", StringComparison.Ordinal)
        || arg.StartsWith("--command=", StringComparison.Ordinal);
}

static bool IsForceFlag(string arg)
{
    return arg.Equals("--force", StringComparison.Ordinal)
        || arg.StartsWith("--force=", StringComparison.Ordinal);
}

static bool IsNativeIgnorePathFlag(string arg)
{
    return arg.Equals("--ignore-path", StringComparison.Ordinal)
        || arg.StartsWith("--ignore-path=", StringComparison.Ordinal);
}

static bool IsNoIgnoreFlag(string arg)
{
    return arg.Equals("--no-ignore", StringComparison.Ordinal)
        || arg.StartsWith("--no-ignore=", StringComparison.Ordinal);
}

static bool IsOpenFlag(string arg)
{
    return arg.Equals("--open", StringComparison.Ordinal)
        || arg.StartsWith("--open=", StringComparison.Ordinal);
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
    if (TryNormalizeScmPlatform(platform, out _))
    {
        return true;
    }

    Console.Error.WriteLine($"invalid scm platform value: {platform}");
    return false;
}

static string NormalizeScmPlatform(string? platform)
{
    return TryNormalizeScmPlatform(platform, out string? normalizedPlatform) ? normalizedPlatform : "unknown";
}

static bool TryNormalizeScmPlatform(string? platform, [NotNullWhen(true)] out string? normalizedPlatform)
{
    if (string.IsNullOrWhiteSpace(platform))
    {
        normalizedPlatform = "unknown";
        return true;
    }

    normalizedPlatform = platform.Trim().ToLowerInvariant();
    if (normalizedPlatform is "unknown" or "none" or "github" or "gitlab" or "azuredevops" or "gitea" or "bitbucket")
    {
        return true;
    }

    normalizedPlatform = null;
    return false;
}

static string GetScmPlatformFromRemoteUrl(string remoteUrl)
{
    if (!Uri.TryCreate(remoteUrl, UriKind.Absolute, out Uri? uri))
    {
        return "unknown";
    }

    return uri.Host.ToLowerInvariant() switch
    {
        "github.com" => "github",
        "gitlab.com" => "gitlab",
        "dev.azure.com" => "azuredevops",
        "visualstudio.com" => "azuredevops",
        "gitea.com" => "gitea",
        "code.forgejo.org" => "gitea",
        "codeberg.org" => "gitea",
        "bitbucket.org" => "bitbucket",
        _ => "unknown",
    };
}

static bool TryLoadRules(
    string? configPath,
    string source,
    IReadOnlyList<string> enabledRuleIds,
    bool nativeConfig,
    [NotNullWhen(true)] out CompiledRuleSet? rules)
{
    try
    {
        RuleSet ruleSet = nativeConfig
            ? PicketConfigLoader.LoadRuleSet(configPath, source)
            : GitleaksConfigLoader.LoadRuleSet(configPath, source);
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

static bool TryOpenNativeScanCache(
    string cacheDir,
    string? configPath,
    string source,
    int maxDecodeDepth,
    long? maxTargetBytes,
    [NotNullWhen(true)] out PicketScanCache? scanCache)
{
    scanCache = null;
    if (!TryLoadRules(configPath, source, [], nativeConfig: true, out CompiledRuleSet? rules))
    {
        return false;
    }

    try
    {
        scanCache = PicketScanCache.Open(cacheDir, ScanCacheKey.Create(rules.Fingerprint, maxDecodeDepth, maxTargetBytes));
        return true;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
    {
        Console.Error.WriteLine($"failed to open cache: {ex.Message}");
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
        ValidateRequiredRules(rule);
        ValidateAllowlists($"rule {rule.Id} allowlist", rule.Allowlists);
    }
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

static bool TryWriteReports(
    IReadOnlyList<Finding> findings,
    IReadOnlyList<SecretRule> rules,
    string? reportPath,
    IReadOnlyList<string> reportPaths,
    string? reportFormat,
    string? reportTemplatePath,
    bool nativeReportFormats = false)
{
    if (!nativeReportFormats || reportPaths.Count <= 1)
    {
        return TryWriteReport(findings, rules, reportPath, reportFormat, reportTemplatePath, nativeReportFormats);
    }

    if (!string.IsNullOrWhiteSpace(reportFormat))
    {
        Console.Error.WriteLine("report format cannot be specified when multiple report paths are specified");
        return false;
    }

    if (!string.IsNullOrWhiteSpace(reportTemplatePath))
    {
        Console.Error.WriteLine("report template cannot be specified when multiple report paths are specified");
        return false;
    }

    bool wroteStdout = false;
    foreach (string path in reportPaths)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Equals("-", StringComparison.Ordinal))
        {
            if (wroteStdout)
            {
                Console.Error.WriteLine("standard output can be specified only once when multiple report paths are specified");
                return false;
            }

            wroteStdout = true;
        }

        if (!TryWriteReport(findings, rules, path, reportFormat: null, reportTemplatePath: null, nativeReportFormats))
        {
            return false;
        }
    }

    return true;
}

static bool TryWriteAnalysisReports(
    IReadOnlyList<Finding> findings,
    string? reportPath,
    IReadOnlyList<string> reportPaths,
    string? reportFormat,
    string? reportTemplatePath)
{
    if (!string.IsNullOrWhiteSpace(reportTemplatePath))
    {
        Console.Error.WriteLine("report templates are not supported for analyze");
        return false;
    }

    if (reportPaths.Count <= 1)
    {
        return TryWriteAnalysisReport(findings, reportPath, reportFormat);
    }

    if (!string.IsNullOrWhiteSpace(reportFormat))
    {
        Console.Error.WriteLine("report format cannot be specified when multiple report paths are specified");
        return false;
    }

    bool wroteStdout = false;
    foreach (string path in reportPaths)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Equals("-", StringComparison.Ordinal))
        {
            if (wroteStdout)
            {
                Console.Error.WriteLine("standard output can be specified only once when multiple report paths are specified");
                return false;
            }

            wroteStdout = true;
        }

        if (!TryWriteAnalysisReport(findings, path, reportFormat: null))
        {
            return false;
        }
    }

    return true;
}

static bool TryWriteAnalysisReport(IReadOnlyList<Finding> findings, string? reportPath, string? reportFormat)
{
    if (!TryResolveAnalysisReportFormat(reportPath, reportFormat, out string? resolvedReportFormat))
    {
        return false;
    }

    List<CredentialAnalysis> analyses = CredentialAnalyzer.Analyze(findings);
    string report = resolvedReportFormat switch
    {
        "json" => CredentialAnalysisReportWriter.WriteJson(analyses),
        "jsonl" => CredentialAnalysisReportWriter.WriteJsonLines(analyses),
        "text" => CredentialAnalysisReportWriter.WriteText(analyses),
        _ => throw new InvalidOperationException($"unsupported analyze report format: {resolvedReportFormat}"),
    };

    return TryWriteTextReport(report, reportPath);
}

static bool TryResolveAnalysisReportFormat(string? reportPath, string? reportFormat, [NotNullWhen(true)] out string? resolvedReportFormat)
{
    if (!string.IsNullOrWhiteSpace(reportFormat))
    {
        resolvedReportFormat = reportFormat.ToLowerInvariant();
        if (resolvedReportFormat is "json" or "jsonl" or "text")
        {
            return true;
        }

        Console.Error.WriteLine($"unsupported analyze report format: {reportFormat}");
        resolvedReportFormat = null;
        return false;
    }

    resolvedReportFormat = InferAnalysisReportFormat(reportPath);
    return true;
}

static string InferAnalysisReportFormat(string? reportPath)
{
    if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
    {
        return "json";
    }

    string extension = Path.GetExtension(reportPath);
    return extension.ToLowerInvariant() switch
    {
        ".jsonl" => "jsonl",
        ".txt" or ".text" => "text",
        _ => "json",
    };
}

static bool TryWriteReport(
    IReadOnlyList<Finding> findings,
    IReadOnlyList<SecretRule> rules,
    string? reportPath,
    string? reportFormat,
    string? reportTemplatePath,
    bool nativeReportFormats = false)
{
    if (!TryResolveReportFormat(reportPath, reportFormat, reportTemplatePath, nativeReportFormats, out string? resolvedReportFormat))
    {
        return false;
    }

    string report;
    try
    {
        report = resolvedReportFormat switch
        {
            "csv" => nativeReportFormats ? PicketCsvReportWriter.Write(findings, rules) : GitleaksCsvReportWriter.Write(findings),
            "gitlab" => PicketGitLabCodeQualityReportWriter.Write(findings),
            "html" => PicketHtmlReportWriter.Write(findings, rules),
            "junit" => nativeReportFormats ? PicketJunitReportWriter.Write(findings, rules) : GitleaksJunitReportWriter.Write(findings),
            "json" => nativeReportFormats ? PicketJsonReportWriter.Write(findings, rules) : GitleaksJsonReportWriter.Write(findings),
            "jsonl" => PicketJsonlReportWriter.Write(findings, rules),
            "sarif" => nativeReportFormats ? PicketSarifReportWriter.Write(findings, rules) : GitleaksSarifReportWriter.Write(findings, rules),
            "template" => GitleaksTemplateReportWriter.Write(findings, ReadReportTemplate(reportTemplatePath)),
            "toon" => PicketToonReportWriter.Write(findings, rules),
            _ => throw new InvalidOperationException($"unsupported report format: {resolvedReportFormat}"),
        };
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"invalid report template: {ex.Message}");
        return false;
    }

    return TryWriteTextReport(report, reportPath);
}

static bool TryWriteTextReport(string report, string? reportPath)
{
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
    bool nativeReportFormats,
    [NotNullWhen(true)] out string? resolvedReportFormat)
{
    if (!string.IsNullOrWhiteSpace(reportFormat))
    {
        if (!TryNormalizeReportFormat(reportFormat, nativeReportFormats, out resolvedReportFormat))
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
    if (nativeReportFormats && IsGitLabCodeQualityReportPath(reportPath))
    {
        resolvedReportFormat = "gitlab";
        return true;
    }

    if (extension.Equals(".csv", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "csv";
        return true;
    }

    if (nativeReportFormats && (extension.Equals(".html", StringComparison.OrdinalIgnoreCase) || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase)))
    {
        resolvedReportFormat = "html";
        return true;
    }

    if (nativeReportFormats && IsJunitReportPath(reportPath))
    {
        resolvedReportFormat = "junit";
        return true;
    }

    if (extension.Equals(".json", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "json";
        return true;
    }

    if (nativeReportFormats && extension.Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "jsonl";
        return true;
    }

    if (extension.Equals(".sarif", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "sarif";
        return true;
    }

    if (nativeReportFormats && extension.Equals(".toon", StringComparison.OrdinalIgnoreCase))
    {
        resolvedReportFormat = "toon";
        return true;
    }

    Console.Error.WriteLine($"unknown report format for report path: {reportPath}");
    resolvedReportFormat = null;
    return false;
}

static bool TryNormalizeReportFormat(string reportFormat, bool nativeReportFormats, [NotNullWhen(true)] out string? resolvedReportFormat)
{
    string normalizedReportFormat = reportFormat.Trim().ToLowerInvariant();
    if (nativeReportFormats && IsGitLabCodeQualityReportFormat(normalizedReportFormat))
    {
        resolvedReportFormat = "gitlab";
        return true;
    }

    if (normalizedReportFormat is "csv" or "json" or "junit" or "sarif" or "template"
        || (nativeReportFormats && normalizedReportFormat.Equals("html", StringComparison.Ordinal))
        || (nativeReportFormats && normalizedReportFormat.Equals("jsonl", StringComparison.Ordinal))
        || (nativeReportFormats && normalizedReportFormat.Equals("toon", StringComparison.Ordinal)))
    {
        resolvedReportFormat = normalizedReportFormat;
        return true;
    }

    Console.Error.WriteLine($"unsupported report format: {reportFormat}");
    resolvedReportFormat = null;
    return false;
}

static bool IsGitLabCodeQualityReportFormat(string reportFormat)
{
    return reportFormat is "gitlab" or "gitlab-code-quality" or "codequality" or "code-quality" or "gl-code-quality";
}

static bool IsGitLabCodeQualityReportPath(string reportPath)
{
    string fileName = Path.GetFileName(reportPath);
    return fileName.Equals("gl-code-quality-report.json", StringComparison.OrdinalIgnoreCase)
        || fileName.EndsWith(".gitlab-code-quality.json", StringComparison.OrdinalIgnoreCase);
}

static bool IsJunitReportPath(string reportPath)
{
    string fileName = Path.GetFileName(reportPath);
    return fileName.EndsWith(".junit.xml", StringComparison.OrdinalIgnoreCase);
}

static bool IsHtmlReportPath(string reportPath)
{
    string extension = Path.GetExtension(reportPath);
    return extension.Equals(".html", StringComparison.OrdinalIgnoreCase)
        || extension.Equals(".htm", StringComparison.OrdinalIgnoreCase);
}

static GitleaksIgnore LoadGitleaksIgnore(string gitleaksIgnorePath, string source)
{
    return GitleaksIgnore.LoadExisting([
        gitleaksIgnorePath,
        Path.Combine(gitleaksIgnorePath, ".gitleaksignore"),
        Path.Combine(source, ".gitleaksignore"),
    ]);
}

static bool TryLoadPicketIgnore(
    string root,
    IReadOnlyList<string> nativeIgnorePaths,
    bool respectNativeIgnoreFiles,
    [NotNullWhen(true)] out PicketIgnore? picketIgnore)
{
    if (!respectNativeIgnoreFiles)
    {
        picketIgnore = PicketIgnore.Empty;
        return true;
    }

    try
    {
        picketIgnore = PicketIgnore.LoadExisting(root, nativeIgnorePaths);
        return true;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine(ex.Message);
        picketIgnore = null;
        return false;
    }
}

static List<string?> CreateControlFileDisplayPaths(string root, string? reportPath, IReadOnlyList<string> reportPaths)
{
    var displayPaths = new List<string?>();
    if (reportPaths.Count == 0)
    {
        displayPaths.Add(CreateControlFileDisplayPath(root, reportPath));
        return displayPaths;
    }

    for (int i = 0; i < reportPaths.Count; i++)
    {
        displayPaths.Add(CreateControlFileDisplayPath(root, reportPaths[i]));
    }

    return displayPaths;
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

static bool IsNativeIgnoreFile(SourceFile file)
{
    string fileName = Path.GetFileName(file.DisplayPath);
    return fileName.Equals(".picketignore", StringComparison.Ordinal)
        || fileName.Equals(".gitignore", StringComparison.Ordinal)
        || fileName.Equals(".ignore", StringComparison.Ordinal)
        || fileName.Equals(".rgignore", StringComparison.Ordinal)
        || fileName.Equals(".scoutignore", StringComparison.Ordinal)
        || file.DisplayPath.Equals(".git/info/exclude", StringComparison.Ordinal);
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

static bool IsControlDirectoryFile(SourceFile file, string? displayPath)
{
    if (displayPath is null)
    {
        return false;
    }

    string prefix = displayPath.EndsWith('/') ? displayPath : string.Concat(displayPath, '/');
    return file.DisplayPath.Equals(displayPath, StringComparison.Ordinal)
        || file.DisplayPath.StartsWith(prefix, StringComparison.Ordinal);
}

static void WriteReportViewSummary(string reportPath, ReportSummary summary)
{
    Console.Out.WriteLine($"report: {reportPath}");
    Console.Out.WriteLine($"format: {summary.Format}");
    Console.Out.WriteLine($"findings: {summary.FindingCount}");
    Console.Out.WriteLine($"files: {summary.FileCount}");
    if (summary.Findings.Count == 0)
    {
        return;
    }

    Console.Out.WriteLine();
    Console.Out.WriteLine("findings:");
    int count = Math.Min(summary.Findings.Count, 10);
    for (int i = 0; i < count; i++)
    {
        ReportFindingSummary finding = summary.Findings[i];
        string location = finding.Line == 0 ? finding.Path : $"{finding.Path}:{finding.Line}";
        if (finding.Fingerprint.Length == 0)
        {
            Console.Out.WriteLine($"  {finding.RuleId} {location}");
        }
        else
        {
            Console.Out.WriteLine($"  {finding.RuleId} {location} {finding.Fingerprint}");
        }
    }

    int remaining = summary.Findings.Count - count;
    if (remaining != 0)
    {
        Console.Out.WriteLine($"  ... {remaining} more");
    }
}

static void WriteHtmlViewSummary(string reportPath)
{
    Console.Out.WriteLine($"report: {reportPath}");
    Console.Out.WriteLine("format: html");
    Console.Out.WriteLine("findings: unknown");
    Console.Out.WriteLine("files: unknown");
}

static bool TryOpenReport(string reportPath)
{
    try
    {
        _ = Process.Start(new ProcessStartInfo(Path.GetFullPath(reportPath))
        {
            UseShellExecute = true,
        });
        return true;
    }
    catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or Win32Exception)
    {
        Console.Error.WriteLine($"failed to open report: {ex.Message}");
        return false;
    }
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket scan [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path]... [--profile picket] [--source path] [--ignore-path path] [--no-ignore] [--cache-dir path] [--enable-rule id] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket verify [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--cache-dir path] [--offline] [--results value] [--only-verified]");
    Console.Out.WriteLine("  picket analyze [path] [-c path] [-f json|jsonl|text] [-r path] [--profile picket] [--source path] [--cache-dir path] [--offline] [--results value]");
    Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--max-decode-depth n] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket git [repo] [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--log-opts value] [--platform value] [--staged] [--pre-commit] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket dir <path> [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-i path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--follow-symlinks] [--ignore-gitleaks-allow] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket stdin [-b path] [-c path] [-f json|csv|junit|sarif|template] [-r path] [-l level] [-v] [--profile picket] [--no-color] [--no-banner] [--report-template path] [--enable-rule id] [--exit-code n] [--ignore-gitleaks-allow] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
    Console.Out.WriteLine("  picket rules test <rule-id> <input> [-c path] [--path path]");
    Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket view <report> [--open]");
    Console.Out.WriteLine("  picket version");
}

static void WriteScanHelp()
{
    Console.Out.WriteLine("picket scan - native filesystem scan");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket scan [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path]... [--profile picket] [--source path] [--ignore-path path] [--no-ignore] [--cache-dir path] [--enable-rule id] [--max-target-megabytes n]");
}

static void WriteVerifyHelp()
{
    Console.Out.WriteLine("picket verify - run native offline verification for detected findings");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket verify [path] [-c path] [-f json|jsonl|csv|junit|html|gitlab|sarif|toon] [-r path] [--profile picket] [--source path] [--cache-dir path] [--offline] [--results unknown|structurally-valid|test-credential|invalid] [--only-verified]");
}

static void WriteAnalyzeHelp()
{
    Console.Out.WriteLine("picket analyze - write offline incident-response analysis for detected findings");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket analyze [path] [-c path] [-f json|jsonl|text] [-r path] [--profile picket] [--source path] [--cache-dir path] [--offline] [--results unknown|structurally-valid|test-credential|invalid]");
}

static void WriteBaselineHelp()
{
    Console.Out.WriteLine("picket baseline - baseline workflow commands");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--redact[=n]]");
}

static void WriteBaselineCreateHelp()
{
    Console.Out.WriteLine("picket baseline create - write a Gitleaks-compatible baseline JSON report");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket baseline create [path] [-c path] [-r path] [--source path] [--ignore-path path] [--no-ignore] [--enable-rule id] [--max-target-megabytes n] [--redact[=n]]");
}

static void WriteCacheHelp()
{
    Console.Out.WriteLine("picket cache - native scan cache maintenance");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--max-decode-depth n] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n]");
}

static void WriteCacheStatsHelp()
{
    Console.Out.WriteLine("picket cache stats - summarize native scan cache entries");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket cache stats [source] --cache-dir path [-c path] [--max-decode-depth n] [--max-target-megabytes n]");
}

static void WriteCachePruneHelp()
{
    Console.Out.WriteLine("picket cache prune - delete native scan cache entries");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket cache prune [source] --cache-dir path [-c path] [--other-keys] [--older-than-days n] [--max-decode-depth n] [--max-target-megabytes n]");
}

static void WriteViewHelp()
{
    Console.Out.WriteLine("picket view - summarize or open a local report");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket view <report> [--open]");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Formats:");
    Console.Out.WriteLine("  Picket JSON, Picket JSONL, Gitleaks JSON, SARIF, HTML");
}

static void WriteRulesHelp()
{
    Console.Out.WriteLine("picket rules - rule pack commands");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
    Console.Out.WriteLine("  picket rules test <rule-id> <input> [-c path] [--path path]");
}

static void WriteRulesCheckHelp()
{
    Console.Out.WriteLine("picket rules check - validate a resolved rule pack");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket rules check [source] [-c path] [--profile picket] [--print-config]");
}

static void WriteRulesTestHelp()
{
    Console.Out.WriteLine("picket rules test - scan sample text with a single rule");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket rules test <rule-id> <input> [-c path] [--path path]");
}

static void WriteHooksHelp()
{
    Console.Out.WriteLine("picket hooks - install local git hooks");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
}

static void WriteHooksInstallHelp()
{
    Console.Out.WriteLine("picket hooks install - write managed pre-commit, pre-push, and pre-receive hooks");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket hooks install [pre-commit|pre-push|pre-receive|all] [--repo path] [--force] [--command path] [-c path] [-b path] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Defaults:");
    Console.Out.WriteLine("  Installs pre-commit when no hook name is provided and uses --redact=100 in generated hooks.");
}
