using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Picket.Analyze;
using Picket.Engine;
using Picket.Security;
using Picket.Verify;

namespace Picket;

internal static partial class Program
{
    static bool TryCreateLiveVerifier(
        LiveVerificationConfiguration configuration,
        string? cacheDir,
        string ruleFingerprint,
        [NotNullWhen(true)] out SecretLiveVerifier? liveVerifier)
    {
        liveVerifier = null;
        var githubOptions = GitHubSecretLiveValidatorOptions.CreateDefault();
        if (configuration.GitHubApiEndpoint is not null)
        {
            try
            {
                githubOptions.UserEndpoint = configuration.GitHubApiEndpoint;
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"invalid GitHub API endpoint: {ex.Message}");
                return false;
            }
        }

        if (configuration.GitHubApiProxyEndpoint is not null)
        {
            try
            {
                githubOptions.ProxyEndpoint = configuration.GitHubApiProxyEndpoint;
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine($"invalid GitHub API proxy: {ex.Message}");
                return false;
            }
        }

        var verifierOptions = SecretLiveVerifierOptions.CreateDefault();
        verifierOptions.EndpointGuardOptions = new EndpointGuardOptions
        {
            AllowNonPublicAddresses = configuration.AllowNonPublicProviderEndpoints,
        };
        if (configuration.MinimumRequestInterval.HasValue)
        {
            verifierOptions.MinimumRequestInterval = configuration.MinimumRequestInterval.Value;
        }

        if (configuration.MinimumRequestIntervalPerProvider.HasValue)
        {
            verifierOptions.MinimumRequestIntervalPerProvider = configuration.MinimumRequestIntervalPerProvider.Value;
        }

        SecretValidationCache? validationCache = null;
        if (!string.IsNullOrWhiteSpace(cacheDir))
        {
            try
            {
                validationCache = SecretValidationCache.Open(
                    Path.Combine(cacheDir, "validation"),
                    string.Concat(
                        "rules:",
                        ruleFingerprint,
                        ";github:",
                        githubOptions.UserEndpoint,
                        ";github-proxy:",
                        githubOptions.ProxyEndpoint?.ToString() ?? string.Empty));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Console.Error.WriteLine($"failed to open validation cache: {ex.Message}");
                return false;
            }
        }

        liveVerifier = new SecretLiveVerifier([new GitHubSecretLiveValidator(githubOptions)], validationCache, verifierOptions);
        return true;
    }

    static bool TryApplyLiveValidation(
        IReadOnlyList<Finding> findings,
        SecretLiveVerifier liveVerifier,
        long timeoutTimestamp,
        [NotNullWhen(true)] out List<Finding>? liveFindings,
        [NotNullWhen(true)] out Dictionary<string, CredentialAnalysisMetadata>? analysisMetadata)
    {
        liveFindings = null;
        analysisMetadata = null;
        using CancellationTokenSource? cancellation = CreateLiveCancellation(timeoutTimestamp);
        CancellationToken cancellationToken = cancellation?.Token ?? CancellationToken.None;
        var annotated = new List<Finding>(findings.Count);
        var metadata = new Dictionary<string, CredentialAnalysisMetadata>(StringComparer.Ordinal);
        for (int i = 0; i < findings.Count; i++)
        {
            if (IsTimedOut(timeoutTimestamp))
            {
                Console.Error.WriteLine(TimeoutErrorMessage);
                return false;
            }

            try
            {
                if (IsOfflineTerminalValidationState(findings[i].ValidationState))
                {
                    annotated.Add(findings[i]);
                    continue;
                }

                SecretValidationResult result = liveVerifier.VerifyAsync(findings[i], cancellationToken).GetAwaiter().GetResult();
                Finding annotatedFinding = CopyWithValidationState(findings[i], result.ReportValue);
                annotated.Add(annotatedFinding);
                metadata[StableFindingFingerprint.Create(annotatedFinding)] = CreateAnalysisMetadata(result);
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine(TimeoutErrorMessage);
                return false;
            }
        }

        liveFindings = annotated;
        analysisMetadata = metadata;
        return true;
    }

    private static bool IsOfflineTerminalValidationState(string validationState)
    {
        return validationState is "invalid" or "test-credential";
    }

    private static CancellationTokenSource? CreateLiveCancellation(long timeoutTimestamp)
    {
        if (timeoutTimestamp == 0)
        {
            return null;
        }

        var cancellation = new CancellationTokenSource();
        long remainingTicks = timeoutTimestamp - Stopwatch.GetTimestamp();
        if (remainingTicks <= 0)
        {
            cancellation.Cancel();
            return cancellation;
        }

        cancellation.CancelAfter(TimeSpan.FromSeconds((double)remainingTicks / Stopwatch.Frequency));
        return cancellation;
    }

    private static Finding CopyWithValidationState(Finding finding, string validationState)
    {
        return new Finding(
            finding.RuleID,
            finding.Description,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            finding.File,
            finding.SymlinkFile,
            finding.Commit,
            finding.Entropy,
            finding.Author,
            finding.Email,
            finding.Date,
            finding.Message,
            finding.Tags,
            finding.Fingerprint,
            finding.Line,
            finding.Link,
            finding.SecretSha256,
            finding.MatchSha256,
            validationState,
            finding.BlobSha256,
            finding.DecodePath);
    }

    private static CredentialAnalysisMetadata CreateAnalysisMetadata(SecretValidationResult result)
    {
        var evidence = new List<string>(result.Evidence.Count + 2)
        {
            string.Concat("liveValidationState=", result.ReportValue)
        };
        if (result.Reason.Length != 0)
        {
            evidence.Add(string.Concat("liveValidationReason=", result.Reason));
        }

        for (int i = 0; i < result.Evidence.Count; i++)
        {
            evidence.Add(result.Evidence[i]);
        }

        return new CredentialAnalysisMetadata(
            result.Identity,
            ToStringArray(result.Scopes),
            ToStringArray(result.ReachableResources),
            [.. evidence]);
    }

    private static string[] ToStringArray(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return [];
        }

        var result = new string[values.Count];
        for (int i = 0; i < values.Count; i++)
        {
            result[i] = values[i];
        }

        return result;
    }
}
