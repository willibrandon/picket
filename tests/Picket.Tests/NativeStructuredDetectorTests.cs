using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests native structured credential detectors.
/// </summary>
[TestClass]
public sealed class NativeStructuredDetectorTests
{
    /// <summary>
    /// Verifies that the embedded Kubernetes rule accepts its kind-after-data example.
    /// </summary>
    [TestMethod]
    public void EmbeddedKubernetesRuleFindsKindAfterDataExample()
    {
        SecretRule rule = PicketConfigLoader.LoadDefaultRuleSet().Rules.Single(
            static candidate => candidate.Id.Equals("picket-kubernetes-secret", StringComparison.Ordinal));

        Assert.AreEqual("(?i)\\bkind[ \\t]*:[ \\t]*Secret\\b", rule.Pattern);
        Assert.AreEqual(PicketBuiltInDetectorNames.KubernetesSecret, rule.Detector);
        Assert.AreEqual(0, rule.Entropy);
        Assert.AreEqual(0, rule.RandomnessThreshold);
        Assert.AreEqual(0, rule.SecretGroup);
        Assert.IsFalse(rule.SkipReport);
        Assert.IsEmpty(rule.PathPattern);
        Assert.Contains("kind: Secret", rule.Examples[0]);
        Assert.Contains("cGlja2V0LWt1YmVybmV0ZXMtcGFzc3dvcmQ=", rule.Examples[0]);

        const string expectedExample =
            "apiVersion: v1\ndata:\n  password: cGlja2V0LWt1YmVybmV0ZXMtcGFzc3dvcmQ=\nkind: Secret";
        IReadOnlyList<Finding> literalFindings = Scan(expectedExample, rule);
        Assert.HasCount(1, literalFindings);
        Assert.AreEqual(expectedExample, rule.Examples[0]);

        IReadOnlyList<Finding> findings = Scan(rule.Examples[0], rule);

        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-kubernetes-password", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that Codex access tokens are read from the tokens object.
    /// </summary>
    [TestMethod]
    public void CodexDetectorFindsAccessTokenInJson()
    {
        const string token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwaWNrZXQifQ.signature_value";
        string input = $"{{\"tokens\":{{\"access_token\":\"{token}\"}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-openai-codex-access-token", "access_token", PicketBuiltInDetectorNames.CodexCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual(token, findings[0].Secret);
    }

    /// <summary>
    /// Verifies that Codex refresh tokens are read from textual assignments.
    /// </summary>
    [TestMethod]
    public void CodexDetectorFindsRefreshTokenAssignment()
    {
        const string token = "rt_picket_refresh_token_0123456789abcdefghijklmnopqrstuvwxyz";
        string input = $"refresh_token = \"{token}\"";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-openai-codex-refresh-token", "refresh_token", PicketBuiltInDetectorNames.CodexCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual(token, findings[0].Secret);
    }

    /// <summary>
    /// Verifies that generic OAuth refresh values are not attributed to Codex.
    /// </summary>
    [TestMethod]
    [DataRow("insert_your_refresh_token_here_now_1234567890")]
    [DataRow("another-provider-refresh-token-value-1234567890")]
    [DataRow("rt_placeholder_refresh_token_value_1234567890")]
    public void CodexDetectorRejectsGenericRefreshToken(string token)
    {
        string input = $"refresh_token = \"{token}\"";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-openai-codex-refresh-token", "refresh_token", PicketBuiltInDetectorNames.CodexCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that malformed JSON does not produce a structured Codex finding.
    /// </summary>
    [TestMethod]
    public void CodexDetectorRejectsMalformedJsonWithoutAssignment()
    {
        const string input = "{\"tokens\":{\"access_token\":true";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-openai-codex-access-token", "access_token", PicketBuiltInDetectorNames.CodexCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that Docker registry basic credentials are decoded from auth entries.
    /// </summary>
    [TestMethod]
    public void DockerDetectorFindsRegistryCredential()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("picket-user:picket-password"));
        string input = $"{{\"auths\":{{\"registry.example.com\":{{\"auth\":\"{encoded}\"}}}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-docker-registry-auth", "auths", PicketBuiltInDetectorNames.DockerRegistryCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-user:picket-password", findings[0].Secret);
        Assert.Contains("docker-auth-base64", findings[0].DecodePath);
    }

    /// <summary>
    /// Verifies that unrelated base64 auth properties are not treated as Docker credentials.
    /// </summary>
    [TestMethod]
    public void DockerDetectorRequiresAuthsObject()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("picket-user:picket-password"));
        string input = $"{{\"settings\":{{\"auth\":\"{encoded}\"}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-docker-registry-auth", "auth", PicketBuiltInDetectorNames.DockerRegistryCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that GCP service account private key material is selected from a complete object.
    /// </summary>
    [TestMethod]
    public void GcpDetectorFindsServiceAccountPrivateKey()
    {
        const string input = "{\"type\":\"service_account\",\"client_email\":\"scanner@example.iam.gserviceaccount.com\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nQUJD\\n-----END PRIVATE KEY-----\\n\"}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-gcp-service-account-key", "service_account", PicketBuiltInDetectorNames.GcpServiceAccountKey));

        Assert.HasCount(1, findings);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", findings[0].Secret);
        Assert.Contains("json-string", findings[0].DecodePath);
    }

    /// <summary>
    /// Verifies that a public JWK does not produce a private-key finding.
    /// </summary>
    [TestMethod]
    public void JwkDetectorRejectsPublicKey()
    {
        const string input = "{\"kty\":\"RSA\",\"n\":\"0123456789abcdefghijklmnopqrstuvwxyz_ABCD\",\"e\":\"AQAB\"}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-jwk-private-key", "kty", PicketBuiltInDetectorNames.JwkPrivateKey));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that a private JWK produces a finding for its private parameter.
    /// </summary>
    [TestMethod]
    public void JwkDetectorFindsPrivateKey()
    {
        const string secret = "0123456789abcdefghijklmnopqrstuvwxyz_ABCD";
        const string input = "{\"kty\":\"RSA\",\"n\":\"0123456789abcdefghijklmnopqrstuvwxyz_ABCD\",\"e\":\"AQAB\",\"d\":\"0123456789abcdefghijklmnopqrstuvwxyz_ABCD\"}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-jwk-private-key", "kty", PicketBuiltInDetectorNames.JwkPrivateKey));

        Assert.HasCount(1, findings);
        Assert.AreEqual(secret, findings[0].Secret);
    }

    /// <summary>
    /// Verifies that credential-bearing environment values are found inside MCP server configurations.
    /// </summary>
    [TestMethod]
    public void McpDetectorFindsServerEnvironmentCredential()
    {
        const string secret = "mcp_8Kz4Wn7Qp2Rx9Tv6Lm3Yc5Hd1Js0Fa8B";
        const string input = "{\"mcpServers\":{\"linear\":{\"command\":\"npx\",\"env\":{\"LINEAR_API_KEY\":\"mcp_8Kz4Wn7Qp2Rx9Tv6Lm3Yc5Hd1Js0Fa8B\",\"LOG_LEVEL\":\"debug\"}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-mcp-server-credential", "mcpServers", PicketBuiltInDetectorNames.McpServerCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual(secret, findings[0].Secret);
    }

    /// <summary>
    /// Verifies that MCP environment-variable references are not reported as embedded credentials.
    /// </summary>
    [TestMethod]
    [DataRow("${LINEAR_API_KEY}")]
    [DataRow("$LINEAR_API_KEY")]
    [DataRow("%LINEAR_API_KEY%")]
    public void McpDetectorRejectsEnvironmentReference(string value)
    {
        string input = $"{{\"mcpServers\":{{\"linear\":{{\"env\":{{\"LINEAR_API_KEY\":\"{value}\"}}}}}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-mcp-server-credential", "mcpServers", PicketBuiltInDetectorNames.McpServerCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that credential-looking values outside an MCP server environment block are not reported.
    /// </summary>
    [TestMethod]
    public void McpDetectorRequiresServerEnvironmentPath()
    {
        const string input = "{\"env\":{\"LINEAR_API_KEY\":\"mcp_8Kz4Wn7Qp2Rx9Tv6Lm3Yc5Hd1Js0Fa8B\"}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-mcp-server-credential", "env", PicketBuiltInDetectorNames.McpServerCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that non-credential MCP environment settings are not reported.
    /// </summary>
    [TestMethod]
    public void McpDetectorRejectsOrdinaryEnvironmentSetting()
    {
        const string input = "{\"mcpServers\":{\"linear\":{\"env\":{\"LOG_LEVEL\":\"debugging-value\"}}}}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-mcp-server-credential", "mcpServers", PicketBuiltInDetectorNames.McpServerCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that scoped npm authentication tokens are detected without interpolation.
    /// </summary>
    [TestMethod]
    public void NpmDetectorFindsAuthToken()
    {
        const string input = "//registry.npmjs.org/:_authToken=npm_picket_token_0123456789";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-npm-auth-token", "_authToken", PicketBuiltInDetectorNames.NpmCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual("npm_picket_token_0123456789", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that npm environment interpolation is not reported as a token.
    /// </summary>
    [TestMethod]
    public void NpmDetectorRejectsEnvironmentInterpolation()
    {
        const string input = "//registry.npmjs.org/:_authToken=${NPM_TOKEN}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-npm-auth-token", "_authToken", PicketBuiltInDetectorNames.NpmCredentials));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that npm basic credentials are decoded from the auth property.
    /// </summary>
    [TestMethod]
    public void NpmDetectorFindsBasicCredential()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("picket-user:picket-password"));
        string input = $"_auth={encoded}";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-npm-basic-auth", "_auth", PicketBuiltInDetectorNames.NpmCredentials));

        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-user:picket-password", findings[0].Secret);
    }

    /// <summary>
    /// Verifies that Kubernetes Secret data and stringData values are detected.
    /// </summary>
    [TestMethod]
    public void KubernetesDetectorFindsEncodedAndPlainValues()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("picket-password"));
        string input = $$"""
            apiVersion: v1
            data:
              password: {{encoded}}
            stringData:
              apiKey: picket-api-key-value
            kind: Secret
            """;

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule(
                "picket-kubernetes-secret",
                "kind",
                PicketBuiltInDetectorNames.KubernetesSecret,
                "(?i)\\bkind[ \\t]*:[ \\t]*Secret\\b"));

        Assert.HasCount(2, findings);
        Assert.Contains(static finding => finding.Secret == "picket-password", findings);
        Assert.Contains(static finding => finding.Secret == "picket-api-key-value", findings);
    }

    /// <summary>
    /// Verifies that YAML aliases are not expanded into Kubernetes Secret findings.
    /// </summary>
    [TestMethod]
    public void KubernetesDetectorDoesNotExpandAliases()
    {
        const string input = "kind: Secret\nshared: &credential picket-password\nstringData:\n  password: *credential\n";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-kubernetes-secret", "kind", PicketBuiltInDetectorNames.KubernetesSecret));

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies that only Secret items in a Kubernetes List contribute findings.
    /// </summary>
    [TestMethod]
    public void KubernetesDetectorScopesValuesToSecretListItems()
    {
        const string input = "kind: List\nitems:\n- kind: Secret\n  stringData:\n    password: picket-password\n- kind: ConfigMap\n  data:\n    setting: not-a-secret\n";

        IReadOnlyList<Finding> findings = Scan(
            input,
            CreateRule("picket-kubernetes-secret", "kind", PicketBuiltInDetectorNames.KubernetesSecret));

        Assert.HasCount(1, findings);
        Assert.AreEqual("picket-password", findings[0].Secret);
    }

    private static SecretRule CreateRule(string id, string keyword, string detector, string? pattern = null)
    {
        return SecretRule.Create(
            id,
            "Detected a structured credential.",
            pattern ?? $"(?i){keyword}",
            keywords: [keyword],
            tags: ["picket", "structured"],
            rulePack: "picket-default",
            detector: detector);
    }

    private static IReadOnlyList<Finding> Scan(string input, SecretRule rule)
    {
        return SecretScanner.Scan(new ScanRequest(
            Encoding.UTF8.GetBytes(input),
            "fixture.txt",
            new RuleSet([rule]),
            maxDecodeDepth: 0)
        {
            EnableNativeDetectors = true,
            PositionKind = FindingPositionKind.UnicodeCodePointsExclusive,
        });
    }
}
