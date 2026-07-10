using Picket.Analyze;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Sources;
using Picket.Store;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static int RunDirectory(
        string[] args,
        bool nativeReportFormats = false,
        string diagnosticsCommand = "dir",
        string? defaultRoot = null,
        bool allowValidationResultFilters = false,
        LiveVerificationConfiguration? liveVerification = null,
        bool allowReportInput = false,
        NativeSourceProvider? sourceFileProvider = null,
        Func<IReadOnlyList<Finding>, string?, List<string>, string?, string?, IReadOnlyDictionary<string, CredentialAnalysisMetadata>?, bool>? nativeResultWriter = null,
        CancellationToken cancellationToken = default)
    {
        if (ContainsHelp(args))
        {
            WriteDirectoryHelp();
            return 0;
        }

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
        ScanCacheStorageMode cacheStorageMode = ScanCacheStorageMode.SecretHashOnly;
        int maxArchiveEntries = nativeMode ? DefaultNativeMaxArchiveEntries : 0;
        long? maxArchiveBytes = nativeMode ? DefaultNativeMaxArchiveBytes : null;
        int maxArchiveCompressionRatio = nativeMode ? DefaultNativeMaxArchiveCompressionRatio : 0;
        int maxArchiveDepth = nativeMode ? DefaultNativeMaxArchiveDepth : 0;
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

            if (nativeMode && IsCacheModeFlag(arg))
            {
                if (!TryReadScanCacheStorageMode(args, ref i, out cacheStorageMode))
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
                    validationResults.Add("active");
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

            if (nativeMode && IsMaxArchiveEntriesFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-entries", out maxArchiveEntries))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (nativeMode && IsMaxArchiveMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--max-archive-megabytes", out maxArchiveBytes))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (nativeMode && IsMaxArchiveRatioFlag(arg))
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

        if (allowReportInput && File.Exists(root) && ReportFindingReader.TryRead(root, out List<Finding>? reportInputFindings))
        {
            string reportInputRoot = Path.GetDirectoryName(Path.GetFullPath(root)) ?? ".";
            GitleaksIgnore reportInputIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, reportInputRoot);
            if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? reportInputBaseline))
            {
                return CompleteRun(1, diagnosticsSession);
            }

            diagnosticsSession?.RecordScanInput();
            return CompleteFindingsRun(
                reportInputFindings,
                rules,
                reportInputBaseline,
                reportInputIgnore,
                redactionPercent,
                validationResults,
                liveVerification,
                cacheDir,
                reportPath,
                reportPaths,
                reportFormat,
                reportTemplatePath,
                nativeMode,
                timeoutTimestamp,
                diagnosticsSession,
                nativeResultWriter,
                exitCode,
                hadScanError: false);
        }

        if (allowReportInput && File.Exists(root) && TryGetSummaryOnlyReportFormat(root, out string? summaryOnlyReportFormat))
        {
            Console.Error.WriteLine($"report input format '{summaryOnlyReportFormat}' does not preserve raw secret material; use picket view for summary-only reports");
            return CompleteRun(1, diagnosticsSession);
        }

        PicketScanCache? scanCache = null;
        if (nativeMode && !string.IsNullOrWhiteSpace(cacheDir))
        {
            try
            {
                WarnIfRawScanCacheMode(cacheStorageMode);
                scanCache = PicketScanCache.Open(cacheDir, CreateNativeScanCacheKey(rules, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Console.Error.WriteLine($"failed to open cache: {ex.Message}");
                return CompleteRun(1, diagnosticsSession);
            }
        }

        PicketIgnore picketIgnore;
        IReadOnlyList<SourceFile> files;
        if (sourceFileProvider is null)
        {
            if (!TryLoadPicketIgnore(root, nativeIgnorePaths, respectNativeIgnoreFiles, out PicketIgnore? loadedPicketIgnore))
            {
                return CompleteRun(1, diagnosticsSession);
            }

            picketIgnore = loadedPicketIgnore;
            files = DirectorySource.Enumerate(new DirectoryScanOptions(
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
                warningSink: nativeMode ? Console.Error.WriteLine : null,
                isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken)));
        }
        else
        {
            try
            {
                picketIgnore = PicketIgnore.Empty;
                files = sourceFileProvider(
                    root,
                    rules,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    timeoutTimestamp,
                    cancellationToken);
            }
            catch (Exception ex) when (ex is ArgumentException or HttpRequestException or IOException or InvalidOperationException or TaskCanceledException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine(ex.Message);
                return CompleteRun(1, diagnosticsSession);
            }
        }

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
        bool hadScanError = IsScanStopped(timeoutTimestamp, cancellationToken);
        if (hadScanError)
        {
            WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
        }

        foreach (SourceFile file in files)
        {
            if (hadScanError)
            {
                break;
            }

            if (IsScanStopped(timeoutTimestamp, cancellationToken))
            {
                WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
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
                if (picketIgnore.TryIgnoreContentHash(input))
                {
                    continue;
                }

                if (LooksBinary(input))
                {
                    continue;
                }

                diagnosticsSession?.RecordScanInput();
                if (scanCache is not null && scanCache.TryRead(input, file.DisplayPath, file.SymlinkDisplayPath, out List<Finding>? cachedFindings))
                {
                    diagnosticsSession?.RecordCacheHit();
                    findings.AddRange(cachedFindings);
                    continue;
                }

                if (scanCache is not null)
                {
                    diagnosticsSession?.RecordCacheMiss();
                }

                IReadOnlyList<Finding> scannedFindings = SecretScanner.Scan(new ScanRequest(
                    input,
                    file.DisplayPath,
                    rules,
                    ignoreGitleaksAllow,
                    maxDecodeDepth: maxDecodeDepth,
                    maxTargetBytes: maxTargetBytes,
                    symlinkFile: file.SymlinkDisplayPath,
                    enableCSharpStringConcatenation: nativeMode,
                    isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
                    cancellationToken: cancellationToken));
                if (IsScanStopped(timeoutTimestamp, cancellationToken))
                {
                    WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
                    hadScanError = true;
                    break;
                }

                findings.AddRange(scannedFindings);
                if (scanCache is not null)
                {
                    scanCache.Write(input, file.DisplayPath, scannedFindings);
                    diagnosticsSession?.RecordCacheWrite();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine(ex.Message);
                hadScanError = true;
            }
        }

        if (nativeMode && respectNativeIgnoreFiles && !hadScanError)
        {
            WritePicketIgnoreStaleWarnings(picketIgnore);
        }

        return CompleteFindingsRun(
            findings,
            rules,
            baseline,
            gitleaksIgnore,
            redactionPercent,
            validationResults,
            liveVerification,
            cacheDir,
            reportPath,
            reportPaths,
            reportFormat,
            reportTemplatePath,
            nativeMode,
            timeoutTimestamp,
            diagnosticsSession,
            nativeResultWriter,
            exitCode,
            hadScanError);
    }

    private static bool IsScanStopped(long timeoutTimestamp, CancellationToken cancellationToken)
    {
        return cancellationToken.IsCancellationRequested || IsTimedOut(timeoutTimestamp);
    }

    private static void WriteScanStoppedMessage(long timeoutTimestamp, CancellationToken cancellationToken)
    {
        Console.Error.WriteLine(cancellationToken.IsCancellationRequested && !IsTimedOut(timeoutTimestamp)
            ? "scan canceled"
            : TimeoutErrorMessage);
    }

    static bool TryGetSummaryOnlyReportFormat(string path, [NotNullWhen(true)] out string? format)
    {
        try
        {
            ReportSummary summary = ReportSummaryReader.Read(path);
            if (summary.Format is "picket-json" or "picket-jsonl" or "gitleaks-json")
            {
                format = null;
                return false;
            }

            format = summary.Format;
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            format = null;
            return false;
        }
    }
}
