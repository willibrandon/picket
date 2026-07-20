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
        GitleaksBaselineComparisonMode baselineComparisonMode = GitleaksBaselineComparisonMode.Exact;
        string? cacheDir = null;
        string? checkpointPath = null;
        string? configPath = null;
        string? diagnostics = null;
        string? diagnosticsDir = null;
        string? reportPath = null;
        string? reportFormat = null;
        string? reportTemplatePath = null;
        var reportPaths = new List<string>();
        var validationResults = new HashSet<string>(StringComparer.Ordinal);
        List<string> enabledRuleIds = [];
        List<string> additionalRulePacks = [];
        string gitleaksIgnorePath = ".";
        var nativeIgnorePaths = new List<string>();
        int exitCode = 1;
        bool followSymlinks = false;
        bool ignoreGitleaksAllow = false;
        bool resetCheckpoint = false;
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

            if (IsBaselineModeFlag(arg))
            {
                if (!nativeMode)
                {
                    Console.Error.WriteLine("--baseline-mode requires --profile picket");
                    return UnknownFlagExitCode;
                }

                if (!TryReadBaselineComparisonMode(args, ref i, out baselineComparisonMode))
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

            if (nativeMode && IsCheckpointPathFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--checkpoint", out checkpointPath))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (nativeMode && IsCheckpointResetFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--checkpoint-reset", out resetCheckpoint))
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

            if (IsRulePackFlag(arg))
            {
                if (!nativeMode)
                {
                    Console.Error.WriteLine("--rule-pack requires a native command or --profile picket");
                    return UnknownFlagExitCode;
                }

                if (!TryReadRulePackFlag(args, ref i, additionalRulePacks))
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

        if (resetCheckpoint && string.IsNullOrWhiteSpace(checkpointPath))
        {
            Console.Error.WriteLine("--checkpoint-reset requires --checkpoint");
            return UnknownFlagExitCode;
        }

        if (!string.IsNullOrWhiteSpace(checkpointPath))
        {
            if (checkpointPath.Equals("-", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("--checkpoint requires a file path");
                return UnknownFlagExitCode;
            }

            if (sourceFileProvider is null)
            {
                Console.Error.WriteLine("--checkpoint requires a native source option such as --github-repository, --s3-bucket, or --registry-image");
                return UnknownFlagExitCode;
            }

            bool collidesWithReport;
            try
            {
                collidesWithReport = ReportPathsContainCheckpoint(reportPath, reportPaths, checkpointPath);
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
            {
                Console.Error.WriteLine($"invalid checkpoint path: {exception.Message}");
                return UnknownFlagExitCode;
            }

            if (collidesWithReport)
            {
                Console.Error.WriteLine("checkpoint path must be different from every report path");
                return UnknownFlagExitCode;
            }
        }

        if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, diagnosticsCommand, Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
        {
            return UnknownFlagExitCode;
        }

        long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
        if (!TryLoadRules(configPath, root, enabledRuleIds, additionalRulePacks, nativeConfig: nativeMode, out CompiledRuleSet? rules))
        {
            return CompleteRun(1, diagnosticsSession);
        }

        if (allowReportInput && File.Exists(root) && ReportFindingReader.TryRead(root, out List<Finding>? reportInputFindings))
        {
            string reportInputRoot = Path.GetDirectoryName(Path.GetFullPath(root)) ?? ".";
            GitleaksIgnore reportInputIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, reportInputRoot);
            if (!TryLoadBaseline(baselinePath, baselineComparisonMode, out GitleaksBaseline? reportInputBaseline))
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
                files = RemoteScanManifest.OrderFiles(sourceFileProvider(
                    root,
                    rules,
                    maxTargetBytes,
                    maxArchiveDepth,
                    maxArchiveEntries,
                    maxArchiveBytes,
                    maxArchiveCompressionRatio,
                    timeoutTimestamp,
                    cancellationToken));
            }
            catch (Exception ex) when (ex is ArgumentException or HttpRequestException or IOException or InvalidOperationException or TaskCanceledException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine(ex.Message);
                return CompleteRun(1, diagnosticsSession);
            }
        }

        GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
        if (!TryLoadBaseline(baselinePath, baselineComparisonMode, out GitleaksBaseline? baseline))
        {
            return CompleteRun(1, diagnosticsSession);
        }

        List<CheckpointSourceFile>? checkpointFiles = null;
        RemoteScanCheckpoint? openedCheckpoint = null;
        if (!string.IsNullOrWhiteSpace(checkpointPath))
        {
            WarnIfCheckpointEnabled();
            try
            {
                checkpointFiles = RemoteScanManifest.CreateFiles(files);
                string manifestFingerprint = RemoteScanManifest.CreateFingerprint(checkpointFiles);
                string scanFingerprint = CreateRemoteCheckpointScanFingerprint(
                    rules,
                    maxDecodeDepth,
                    maxTargetBytes,
                    ignoreGitleaksAllow);
                openedCheckpoint = RemoteScanCheckpoint.Open(
                    checkpointPath,
                    new RemoteScanCheckpointKey(scanFingerprint, manifestFingerprint),
                    resetCheckpoint);
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or InvalidDataException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"failed to open checkpoint: {exception.Message}");
                return CompleteRun(1, diagnosticsSession);
            }
        }

        using RemoteScanCheckpoint? scanCheckpoint = openedCheckpoint;

        string? baselineDisplayPath = CreateControlFileDisplayPath(root, baselinePath);
        string? configDisplayPath = CreateControlFileDisplayPath(root, ResolveConfigControlPath(configPath, root));
        List<string?> reportDisplayPaths = CreateControlFileDisplayPaths(root, reportPath, reportPaths);
        List<string?> nativeIgnoreDisplayPaths = respectNativeIgnoreFiles
            ? CreateControlFileDisplayPaths(root, reportPath: null, nativeIgnorePaths)
            : [];
        string? cacheDisplayPath = nativeMode ? CreateControlFileDisplayPath(root, cacheDir) : null;
        string?[] controlDisplayPaths = [baselineDisplayPath, configDisplayPath, .. reportDisplayPaths, .. nativeIgnoreDisplayPaths];
        var findings = new List<Finding>();
        int startFileIndex = 0;
        if (scanCheckpoint is not null)
        {
            try
            {
                if (scanCheckpoint.CompletedFileCount > checkpointFiles!.Count)
                {
                    throw new InvalidDataException("Checkpoint low-water mark exceeds the current source manifest.");
                }

                for (; startFileIndex < scanCheckpoint.CompletedFileCount; startFileIndex++)
                {
                    CheckpointSourceFile checkpointFile = checkpointFiles![startFileIndex];
                    SourceFile sourceFile = checkpointFile.SourceFile;
                    if (!scanCheckpoint.TryRestoreFile(
                        startFileIndex,
                        sourceFile.DisplayPath,
                        sourceFile.SymlinkDisplayPath,
                        checkpointFile.Content,
                        out List<Finding>? restoredFindings))
                    {
                        throw new InvalidDataException("Checkpoint ended before its recorded low-water mark.");
                    }

                    findings.AddRange(restoredFindings);
                    diagnosticsSession?.RecordScanInput();
                }

                if (startFileIndex != 0)
                {
                    Console.Error.WriteLine($"resuming checkpoint: {startFileIndex} of {checkpointFiles!.Count} files completed");
                }
            }
            catch (InvalidDataException exception)
            {
                Console.Error.WriteLine($"failed to restore checkpoint: {exception.Message}");
                return CompleteRun(1, diagnosticsSession);
            }
        }

        bool hadScanError = IsScanStopped(timeoutTimestamp, cancellationToken);
        if (hadScanError)
        {
            WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
        }

        int sourceFileCount = checkpointFiles?.Count ?? files.Count;
        if (scanCheckpoint is null)
        {
            if (!hadScanError)
            {
                int parallelScanDegree = GetSourceFileScanDegree(sourceFileCount - startFileIndex);
                bool completed = ScanSourceFiles(
                    files,
                    startFileIndex,
                    file => IsControlFile(file, controlDisplayPaths)
                        || IsControlDirectoryFile(file, cacheDisplayPath)
                        || (respectNativeIgnoreFiles && IsNativeIgnoreFile(file)),
                    rules,
                    picketIgnore,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    maxTargetBytes,
                    nativeMode,
                    timeoutTimestamp,
                    parallelScanDegree,
                    scanCache,
                    diagnosticsSession,
                    findings,
                    out bool stopped,
                    out Exception? scanError,
                    cancellationToken);
                if (!completed)
                {
                    if (stopped)
                    {
                        WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
                    }
                    else if (scanError is not null)
                    {
                        Console.Error.WriteLine(scanError.Message);
                    }

                    hadScanError = true;
                }
            }
        }
        else
        {
            for (int fileIndex = startFileIndex; fileIndex < sourceFileCount; fileIndex++)
            {
                CheckpointSourceFile? checkpointFile = checkpointFiles?[fileIndex];
                SourceFile file = checkpointFile?.SourceFile ?? files[fileIndex];
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

                if (IsControlFile(file, controlDisplayPaths)
                    || IsControlDirectoryFile(file, cacheDisplayPath)
                    || (respectNativeIgnoreFiles && IsNativeIgnoreFile(file)))
                {
                    try
                    {
                        scanCheckpoint?.AppendCompletedFile(file.DisplayPath, file.SymlinkDisplayPath, checkpointFile!.Content, []);
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                    {
                        Console.Error.WriteLine(exception.Message);
                        hadScanError = true;
                    }

                    continue;
                }

                try
                {
                    if (checkpointFile is null && file.Length > SourceFragmentReader.DefaultBufferSize)
                    {
                        List<Finding> fragmentFindings = ScanSourceFileFragments(
                            file,
                            rules,
                            picketIgnore,
                            ignoreGitleaksAllow,
                            maxDecodeDepth,
                            maxTargetBytes,
                            nativeMode,
                            timeoutTimestamp,
                            scanCache,
                            diagnosticsSession,
                            out bool stopped,
                            cancellationToken);
                        if (stopped)
                        {
                            WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
                            hadScanError = true;
                            break;
                        }

                        findings.AddRange(fragmentFindings);
                        continue;
                    }

                    byte[] input = checkpointFile?.Content ?? file.ReadAllBytes();
                    if (picketIgnore.TryIgnoreContentHash(input))
                    {
                        scanCheckpoint?.AppendCompletedFile(file.DisplayPath, file.SymlinkDisplayPath, input, []);
                        continue;
                    }

                    if (LooksBinary(input))
                    {
                        scanCheckpoint?.AppendCompletedFile(file.DisplayPath, file.SymlinkDisplayPath, input, []);
                        continue;
                    }

                    diagnosticsSession?.RecordScanInput();
                    if (scanCache is not null && scanCache.TryRead(input, file.DisplayPath, file.SymlinkDisplayPath, out List<Finding>? cachedFindings))
                    {
                        diagnosticsSession?.RecordCacheHit();
                        findings.AddRange(cachedFindings);
                        scanCheckpoint?.AppendCompletedFile(file.DisplayPath, file.SymlinkDisplayPath, input, cachedFindings);
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
                        cancellationToken: cancellationToken)
                    {
                        EnableNativeDetectors = nativeMode,
                        EnableRandomnessScoring = nativeMode,
                        PositionKind = nativeMode
                            ? FindingPositionKind.UnicodeCodePointsExclusive
                            : FindingPositionKind.GitleaksUtf8BytesInclusive,
                    });
                    if (IsScanStopped(timeoutTimestamp, cancellationToken))
                    {
                        WriteScanStoppedMessage(timeoutTimestamp, cancellationToken);
                        hadScanError = true;
                        break;
                    }

                    if (scanCache is not null && nativeMode)
                    {
                        scannedFindings = AnnotateFindingsForNativeCache(scannedFindings);
                    }

                    findings.AddRange(scannedFindings);
                    if (scanCache is not null)
                    {
                        scanCache.Write(input, file.DisplayPath, scannedFindings);
                        diagnosticsSession?.RecordCacheWrite();
                    }

                    scanCheckpoint?.AppendCompletedFile(file.DisplayPath, file.SymlinkDisplayPath, input, scannedFindings);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Console.Error.WriteLine(ex.Message);
                    hadScanError = true;
                }
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
            hadScanError,
            scanCheckpoint is null
                ? null
                : () => CompleteRemoteScanCheckpoint(scanCheckpoint));
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
