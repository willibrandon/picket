using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static Task<int> RunStdinAsync(string[] args, string configSource = ".")
    {
        return Task.FromResult(RunStdin(args, configSource));
    }

    private static int RunStdin(string[] args, string configSource)
    {
        if (ContainsHelp(args))
        {
            WriteStdinHelp();
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
        List<string> enabledRuleIds = [];
        List<string> additionalRulePacks = [];
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
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-archive-depth", out _))
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

            Console.Error.WriteLine($"unknown flag: {arg}");
            return UnknownFlagExitCode;
        }

        if (nativeMode && exitCode == NativeOperationalExitCode)
        {
            Console.Error.WriteLine("--exit-code 2 is reserved for incomplete or failed native scans");
            return NativeOperationalExitCode;
        }

        if (!CompatibilityDiagnosticsSession.TryStart(diagnostics, diagnosticsDir, "stdin", Console.Error, out CompatibilityDiagnosticsSession? diagnosticsSession))
        {
            return GetOperationalExitCode(nativeMode);
        }

        long timeoutTimestamp = CreateTimeoutTimestamp(timeoutSeconds);
        if (!TryLoadRules(configPath, configSource, enabledRuleIds, additionalRulePacks, nativeConfig: nativeMode, out CompiledRuleSet? rules))
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        if (!TryLoadBaseline(baselinePath, baselineComparisonMode, out GitleaksBaseline? baseline))
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, configSource);
        if (IsTimedOut(timeoutTimestamp))
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            if (!TryWriteReport([], rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
            {
                return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
            }

            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        diagnosticsSession?.RecordScanInput();
        using Stream input = Console.OpenStandardInput();
        List<Finding> scannedFindings = ScanStandardInputFragments(
            input,
            rules,
            ignoreGitleaksAllow,
            maxDecodeDepth,
            maxTargetBytes,
            nativeMode,
            timeoutTimestamp,
            out bool stopped,
            CancellationToken.None);
        if (stopped || IsTimedOut(timeoutTimestamp))
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            if (!TryWriteReport([], rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
            {
                return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
            }

            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        IReadOnlyList<Finding> findings = baseline.Filter(gitleaksIgnore.Filter(scannedFindings), redactionPercent);
        if (nativeMode)
        {
            findings = OfflineSecretValidator.AnnotateAll(findings);
            findings = SecretRandomnessFindingProcessor.Apply(findings, rules);
        }

        if (redactionPercent > 0)
        {
            findings = GitleaksFindingRedactor.Redact(findings, redactionPercent, requirePartialMask: nativeMode);
        }

        diagnosticsSession?.RecordFindingCount(findings.Count);
        if (!TryWriteReport(findings, rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        return CompleteRun(findings.Count == 0 ? 0 : exitCode, diagnosticsSession);
    }
}
