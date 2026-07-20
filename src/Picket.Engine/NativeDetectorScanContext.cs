using Picket.Rules;

namespace Picket.Engine;

/// <summary>
/// Caches structured parsing products for one scanner pass.
/// </summary>
internal sealed class NativeDetectorScanContext
{
    private readonly Dictionary<string, List<NativeDetectorMatch>> _matchesByRuleId = new(StringComparer.Ordinal);
    private NativeJsonIndex? _jsonIndex;
    private bool _jsonIndexAttempted;
    private NativeYamlIndex? _kubernetesYamlIndex;
    private bool _kubernetesYamlIndexAttempted;
    private NativeNpmrcIndex? _npmrcIndex;

    internal IReadOnlyList<NativeDetectorMatch> GetMatches(
        SecretRule rule,
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        if (_matchesByRuleId.TryGetValue(rule.Id, out List<NativeDetectorMatch>? cachedMatches))
        {
            return cachedMatches;
        }

        List<NativeDetectorMatch> matches = rule.Detector switch
        {
            PicketBuiltInDetectorNames.CodexCredentials
                or PicketBuiltInDetectorNames.DockerRegistryCredentials
                or PicketBuiltInDetectorNames.GcpServiceAccountKey
                or PicketBuiltInDetectorNames.JwkPrivateKey
                or PicketBuiltInDetectorNames.McpServerCredentials => FindJsonMatches(rule, input, isCancellationRequested),
            PicketBuiltInDetectorNames.NpmCredentials => FindNpmMatches(rule, input, isCancellationRequested),
            PicketBuiltInDetectorNames.KubernetesSecret => FindKubernetesMatches(input, isCancellationRequested),
            _ => [],
        };
        _matchesByRuleId.Add(rule.Id, matches);
        return matches;
    }

    private List<NativeDetectorMatch> FindKubernetesMatches(
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        if (!_kubernetesYamlIndexAttempted)
        {
            _kubernetesYamlIndexAttempted = true;
            NativeYamlIndex.TryCreate(input, isCancellationRequested, out _kubernetesYamlIndex);
        }

        return _kubernetesYamlIndex is null
            ? []
            : NativeKubernetesSecretDetector.Find(_kubernetesYamlIndex);
    }

    private List<NativeDetectorMatch> FindJsonMatches(
        SecretRule rule,
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        if (!_jsonIndexAttempted)
        {
            _jsonIndexAttempted = true;
            NativeJsonIndex.TryCreate(input, isCancellationRequested, out _jsonIndex);
        }

        return NativeJsonCredentialDetector.Find(rule, _jsonIndex, input, isCancellationRequested);
    }

    private List<NativeDetectorMatch> FindNpmMatches(
        SecretRule rule,
        ReadOnlySpan<byte> input,
        Func<bool>? isCancellationRequested)
    {
        _npmrcIndex ??= NativeNpmrcIndex.Create(input, isCancellationRequested);
        return NativeNpmCredentialDetector.Find(rule.Id, _npmrcIndex);
    }
}
