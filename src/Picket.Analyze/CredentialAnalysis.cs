namespace Picket.Analyze;

/// <summary>
/// Describes offline incident-response analysis for one detected credential.
/// </summary>
/// <param name="schema">The stable analysis schema identifier.</param>
/// <param name="ruleId">The finding rule identifier.</param>
/// <param name="provider">The inferred credential provider.</param>
/// <param name="credentialType">The inferred credential type.</param>
/// <param name="file">The source file path.</param>
/// <param name="startLine">The one-based finding start line.</param>
/// <param name="startColumn">The one-based finding start column.</param>
/// <param name="fingerprint">The stable Picket-native finding fingerprint.</param>
/// <param name="secretSha256">The SHA-256 hash of the original secret.</param>
/// <param name="validationState">The offline validation state.</param>
/// <param name="risk">The offline triage risk.</param>
/// <param name="identity">The discovered identity, or an explanatory placeholder.</param>
/// <param name="scopes">The discovered credential scopes.</param>
/// <param name="reachableResources">The discovered reachable resources.</param>
/// <param name="riskSummary">A concise non-secret risk summary.</param>
/// <param name="recommendedActions">Recommended incident-response actions.</param>
/// <param name="evidence">Non-secret evidence used for the analysis.</param>
public sealed class CredentialAnalysis(
    string schema,
    string ruleId,
    string provider,
    string credentialType,
    string file,
    int startLine,
    int startColumn,
    string fingerprint,
    string secretSha256,
    string validationState,
    string risk,
    string identity,
    IReadOnlyList<string> scopes,
    IReadOnlyList<string> reachableResources,
    string riskSummary,
    IReadOnlyList<string> recommendedActions,
    IReadOnlyList<string> evidence)
{
    /// <summary>
    /// Gets the stable analysis schema identifier.
    /// </summary>
    public string Schema { get; } = schema;

    /// <summary>
    /// Gets the finding rule identifier.
    /// </summary>
    public string RuleId { get; } = ruleId;

    /// <summary>
    /// Gets the inferred credential provider.
    /// </summary>
    public string Provider { get; } = provider;

    /// <summary>
    /// Gets the inferred credential type.
    /// </summary>
    public string CredentialType { get; } = credentialType;

    /// <summary>
    /// Gets the source file path.
    /// </summary>
    public string File { get; } = file;

    /// <summary>
    /// Gets the one-based finding start line.
    /// </summary>
    public int StartLine { get; } = startLine;

    /// <summary>
    /// Gets the one-based finding start column.
    /// </summary>
    public int StartColumn { get; } = startColumn;

    /// <summary>
    /// Gets the stable Picket-native finding fingerprint.
    /// </summary>
    public string Fingerprint { get; } = fingerprint;

    /// <summary>
    /// Gets the SHA-256 hash of the original secret.
    /// </summary>
    public string SecretSha256 { get; } = secretSha256;

    /// <summary>
    /// Gets the offline validation state.
    /// </summary>
    public string ValidationState { get; } = validationState;

    /// <summary>
    /// Gets the offline triage risk.
    /// </summary>
    public string Risk { get; } = risk;

    /// <summary>
    /// Gets the discovered identity, or an explanatory placeholder.
    /// </summary>
    public string Identity { get; } = identity;

    /// <summary>
    /// Gets the discovered credential scopes.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; } = scopes;

    /// <summary>
    /// Gets the discovered reachable resources.
    /// </summary>
    public IReadOnlyList<string> ReachableResources { get; } = reachableResources;

    /// <summary>
    /// Gets a concise non-secret risk summary.
    /// </summary>
    public string RiskSummary { get; } = riskSummary;

    /// <summary>
    /// Gets recommended incident-response actions.
    /// </summary>
    public IReadOnlyList<string> RecommendedActions { get; } = recommendedActions;

    /// <summary>
    /// Gets non-secret evidence used for the analysis.
    /// </summary>
    public IReadOnlyList<string> Evidence { get; } = evidence;
}
