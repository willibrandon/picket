using Picket.Analyze;
using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static List<Finding> AnnotateFindingsForNativeCache(IReadOnlyList<Finding> findings)
    {
        return OfflineSecretValidator.AnnotateAll(findings);
    }

    static int CompleteFindingsRun(
        IReadOnlyList<Finding> findings,
        CompiledRuleSet rules,
        GitleaksBaseline baseline,
        GitleaksIgnore gitleaksIgnore,
        int redactionPercent,
        HashSet<string> validationResults,
        LiveVerificationConfiguration? liveVerification,
        string? cacheDir,
        string? reportPath,
        List<string> reportPaths,
        string? reportFormat,
        string? reportTemplatePath,
        bool nativeMode,
        long timeoutTimestamp,
        CompatibilityDiagnosticsSession? diagnosticsSession,
        Func<IReadOnlyList<Finding>, string?, List<string>, string?, string?, IReadOnlyDictionary<string, CredentialAnalysisMetadata>?, bool>? nativeResultWriter,
        int exitCode,
        bool hadScanError,
        Action? successfulRunCallback = null)
    {
        IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
        if (nativeMode)
        {
            filteredFindings = OfflineSecretValidator.AnnotateAll(filteredFindings);
            filteredFindings = SecretRandomnessFindingProcessor.Apply(filteredFindings, rules);
        }

        IReadOnlyDictionary<string, CredentialAnalysisMetadata>? analysisMetadata = null;
        if (liveVerification is not null)
        {
            if (!TryCreateLiveVerifier(liveVerification, cacheDir, rules.Fingerprint, out SecretLiveVerifier? liveVerifier))
            {
                return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
            }

            using (liveVerifier)
            {
                if (!TryApplyLiveValidation(
                    filteredFindings,
                    liveVerifier,
                    timeoutTimestamp,
                    out List<Finding>? liveFindings,
                    out Dictionary<string, CredentialAnalysisMetadata>? liveAnalysisMetadata))
                {
                    return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
                }

                filteredFindings = liveFindings;
                analysisMetadata = liveAnalysisMetadata;
            }
        }

        if (validationResults.Count != 0)
        {
            filteredFindings = FilterValidationResults(filteredFindings, validationResults);
        }

        if (redactionPercent > 0)
        {
            filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent, requirePartialMask: nativeMode);
        }

        diagnosticsSession?.RecordFindingCount(filteredFindings.Count);
        bool wroteResults = nativeResultWriter is null
            ? TryWriteReports(
                filteredFindings,
                rules.Rules,
                reportPath,
                reportPaths,
                reportFormat,
                reportTemplatePath,
                nativeMode,
                scanComplete: !hadScanError)
            : nativeResultWriter(filteredFindings, reportPath, reportPaths, reportFormat, reportTemplatePath, analysisMetadata);
        if (!wroteResults)
        {
            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        if (hadScanError)
        {
            if (nativeMode)
            {
                Console.Error.WriteLine(IncompleteScanMessage);
            }

            return CompleteRun(GetOperationalExitCode(nativeMode), diagnosticsSession);
        }

        successfulRunCallback?.Invoke();

        return CompleteRun(filteredFindings.Count == 0 ? 0 : exitCode, diagnosticsSession);
    }
}
