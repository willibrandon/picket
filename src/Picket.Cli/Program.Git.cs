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
            return 1;
        }

        string? baselinePath = null;
        GitleaksBaselineComparisonMode baselineComparisonMode = GitleaksBaselineComparisonMode.Exact;
        string? configPath = null;
        string? diagnostics = null;
        string? diagnosticsDir = null;
        string? reportPath = null;
        string? reportFormat = null;
        string? reportTemplatePath = null;
        string? logOptions = null;
        string? platform = null;
        List<string> enabledRuleIds = [];
        List<string> additionalRulePacks = [];
        string gitleaksIgnorePath = ".";
        string root = ".";
        int exitCode = 1;
        bool ignoreGitleaksAllow = false;
        int maxArchiveEntries = DefaultNativeMaxArchiveEntries;
        long? maxArchiveBytes = DefaultNativeMaxArchiveBytes;
        int maxArchiveCompressionRatio = DefaultNativeMaxArchiveCompressionRatio;
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
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsBaselineModeFlag(arg))
            {
                if (!nativeMode)
                {
                    Console.Error.WriteLine("--baseline-mode requires --profile picket");
                    return GetOperationalExitCode(nativeMode);
                }

                if (!TryReadBaselineComparisonMode(args, ref i, out baselineComparisonMode))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsProfileFlag(arg))
            {
                if (!TryReadProfileFlag(args, ref i, out _))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
            {
                if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsEnableRuleFlag(arg))
            {
                if (!TryReadRuleIdFlag(args, ref i, enabledRuleIds))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsRulePackFlag(arg))
            {
                if (!nativeMode)
                {
                    Console.Error.WriteLine("--rule-pack requires --profile picket");
                    return GetOperationalExitCode(nativeMode);
                }

                if (!TryReadRulePackFlag(args, ref i, additionalRulePacks))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsReportFormatFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--report-format", out reportFormat))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsReportTemplateFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--report-template", out reportTemplatePath))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
            {
                if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsGitleaksIgnorePathFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--gitleaks-ignore-path", out string? value))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                gitleaksIgnorePath = value;
                continue;
            }

            if (IsIgnoreGitleaksAllowFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--ignore-gitleaks-allow", out ignoreGitleaksAllow))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsLogOptionsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsPlatformFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--platform", out platform))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsPreCommitFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--pre-commit", out preCommit))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsStagedFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--staged", out staged))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsMaxTargetMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, out maxTargetBytes))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsRedactFlag(arg))
            {
                if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsMaxDecodeDepthFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsMaxArchiveDepthFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out maxArchiveDepth))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (nativeMode && IsMaxArchiveEntriesFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-entries", out maxArchiveEntries))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (nativeMode && IsMaxArchiveMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, "--max-archive-megabytes", out maxArchiveBytes))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (nativeMode && IsMaxArchiveRatioFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-ratio", out maxArchiveCompressionRatio))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsTimeoutFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--timeout", out timeoutSeconds))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsDiagnosticsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--diagnostics", out diagnostics))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (IsDiagnosticsDirFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--diagnostics-dir", out diagnosticsDir))
                {
                    return GetOperationalExitCode(nativeMode);
                }

                continue;
            }

            if (!TryHandleCommonCompatibilityFlag(args, ref i, out bool handledCommonFlag))
            {
                return GetOperationalExitCode(nativeMode);
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
                return GetOperationalExitCode(nativeMode);
            }

            root = arg.Length == 0 ? "." : arg;
            rootProvided = true;
        }

        if (nativeMode && exitCode == NativeOperationalExitCode)
        {
            Console.Error.WriteLine("--exit-code 2 is reserved for incomplete or failed native scans");
            return NativeOperationalExitCode;
        }

        if (!staged && !preCommit && !TryValidatePlatform(platform))
        {
            return GetOperationalExitCode(nativeMode);
        }

        if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, "git", Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
        {
            return GetOperationalExitCode(nativeMode);
        }

        if (!TryLoadRules(configPath, root, enabledRuleIds, additionalRulePacks, nativeConfig: nativeMode, out CompiledRuleSet? rules))
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        if (!TryLoadBaseline(baselinePath, baselineComparisonMode, out GitleaksBaseline? baseline))
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
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
                warningSink: Console.Error.WriteLine,
                isCancellationRequested: () => IsTimedOut(timeoutTimestamp),
                identifyArchivesByContent: nativeMode));
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
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
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        if (timedOut)
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        return CompleteRun(filteredFindings.Count == 0 ? 0 : exitCode, diagnosticsSession);
    }
}
