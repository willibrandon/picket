using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Sources;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static int RunGit(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteGitHelp();
            return 0;
        }

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
        int maxArchiveEntries = nativeMode ? DefaultNativeMaxArchiveEntries : 0;
        long? maxArchiveBytes = nativeMode ? DefaultNativeMaxArchiveBytes : null;
        int maxArchiveCompressionRatio = nativeMode ? DefaultNativeMaxArchiveCompressionRatio : 0;
        int maxArchiveDepth = nativeMode ? DefaultNativeMaxArchiveDepth : 0;
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
                logOptions: logOptions,
                staged: staged,
                preCommit: preCommit,
                maxArchiveDepth: maxArchiveDepth,
                maxArchiveEntries: maxArchiveEntries,
                maxArchiveBytes: maxArchiveBytes,
                maxArchiveCompressionRatio: maxArchiveCompressionRatio,
                maxTargetBytes: maxTargetBytes,
                isPathAllowed: rules.IsGlobalPathAllowed,
                warningSink: nativeMode ? Console.Error.WriteLine : null,
                isCancellationRequested: () => IsTimedOut(timeoutTimestamp)));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return CompleteRun(1, diagnosticsSession);
        }

        GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
        CreateGitLinkContext(root, staged || preCommit, platform, out string scmPlatform, out string remoteUrl);
        diagnosticsSession?.RecordScanInputs(fragments.Count);
        List<Finding> findings = ScanGitFragments(fragments, rules, ignoreGitleaksAllow, maxTargetBytes, maxDecodeDepth, nativeMode, timeoutTimestamp, scmPlatform, remoteUrl, out bool timedOut);
        timedOut |= IsTimedOut(timeoutTimestamp);
        IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
        if (nativeMode)
        {
            filteredFindings = OfflineSecretValidator.AnnotateAll(filteredFindings);
            filteredFindings = SecretRandomnessFindingProcessor.Apply(filteredFindings, rules);
        }

        if (redactionPercent > 0)
        {
            filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent, requirePartialMask: nativeMode);
        }

        diagnosticsSession?.RecordFindingCount(filteredFindings.Count);
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
}
