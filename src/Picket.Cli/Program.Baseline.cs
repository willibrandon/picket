using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Sources;

namespace Picket;

internal static partial class Program
{
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
        int maxArchiveEntries = DefaultNativeMaxArchiveEntries;
        long? maxArchiveBytes = DefaultNativeMaxArchiveBytes;
        int maxArchiveCompressionRatio = DefaultNativeMaxArchiveCompressionRatio;
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

            if (IsMaxArchiveEntriesFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-entries", out maxArchiveEntries))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsMaxArchiveMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--max-archive-megabytes", out maxArchiveBytes))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsMaxArchiveRatioFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-ratio", out maxArchiveCompressionRatio))
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
            maxTargetBytes: maxTargetBytes,
            followSymbolicLinks: followSymlinks,
            maxArchiveDepth: maxArchiveDepth,
            maxArchiveEntries: maxArchiveEntries,
            maxArchiveBytes: maxArchiveBytes,
            maxArchiveCompressionRatio: maxArchiveCompressionRatio,
            isPathAllowed: rules.IsGlobalPathAllowed,
            readPicketIgnoreFiles: respectNativeIgnoreFiles,
            readIgnoreFiles: respectNativeIgnoreFiles,
            readGitIgnoreFiles: respectNativeIgnoreFiles,
            readGlobalGitIgnore: respectNativeIgnoreFiles,
            ignoreHidden: respectNativeIgnoreFiles,
            readParentIgnoreFiles: respectNativeIgnoreFiles,
            ignoreFilePaths: respectNativeIgnoreFiles ? nativeIgnorePaths : [],
            warningSink: Console.Error.WriteLine));
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
}
