using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
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

        diagnosticsSession?.RecordScanInput();
        IReadOnlyList<Finding> scannedFindings = SecretScanner.Scan(new ScanRequest(
            input,
            string.Empty,
            rules,
            ignoreGitleaksAllow,
            maxDecodeDepth: maxDecodeDepth,
            maxTargetBytes: maxTargetBytes,
            isCancellationRequested: () => IsTimedOut(timeoutTimestamp)));
        if (IsTimedOut(timeoutTimestamp))
        {
            Console.Error.WriteLine(TimeoutErrorMessage);
            if (!TryWriteReport([], rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
            {
                return CompleteRun(1, diagnosticsSession);
            }

            return CompleteRun(1, diagnosticsSession);
        }

        IReadOnlyList<Finding> findings = baseline.Filter(gitleaksIgnore.Filter(scannedFindings), redactionPercent);
        if (nativeMode)
        {
            findings = OfflineSecretValidator.AnnotateAll(findings);
        }

        if (redactionPercent > 0)
        {
            findings = GitleaksFindingRedactor.Redact(findings, redactionPercent);
        }

        diagnosticsSession?.RecordFindingCount(findings.Count);
        if (!TryWriteReport(findings, rules.Rules, reportPath, reportFormat, reportTemplatePath, nativeMode))
        {
            return CompleteRun(1, diagnosticsSession);
        }

        return CompleteRun(findings.Count == 0 ? 0 : exitCode, diagnosticsSession);
    }
}
