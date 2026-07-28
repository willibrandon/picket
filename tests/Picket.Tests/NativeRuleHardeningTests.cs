using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests native rule hardening derived from upstream false-positive reports.
/// </summary>
[TestClass]
public sealed class NativeRuleHardeningTests
{
    private const string SquareBase64LikeMimeSample =
        "mJeJ0b3bVQZu6P8AUEsHCFDBu3Q+EAAAWRAAAFBLAwQUAAgICAAYZxlbAAAAAAAAAAAAAAAAEwAA";
    private const string VueAttributeSample =
        "<my-custom-component v-model=\"anyValWithKeyInside\" :followed-by-a-dynamic-attributes-with-at-least-two-dashes=\"true\" />";

    /// <summary>
    /// Verifies native randomness filtering rejects a base64-like MIME fragment matched by the Square rule.
    /// </summary>
    [TestMethod]
    public void NativeSquareRuleRejectsBase64LikeMimeFragment()
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("square-access-token", SquareBase64LikeMimeSample);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("square-access-token", SquareBase64LikeMimeSample);

        Assert.IsNotEmpty(strictFindings);
        Assert.IsEmpty(nativeFindings);
    }

    /// <summary>
    /// Verifies current strict and native generic rules reject the reported Vue attribute false positive.
    /// </summary>
    [TestMethod]
    public void GenericRulesRejectVueAttributeName()
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", VueAttributeSample);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("generic-api-key", VueAttributeSample);

        Assert.IsEmpty(strictFindings);
        Assert.IsEmpty(nativeFindings);
    }

    /// <summary>
    /// Verifies the native generic rule covers modern assignment forms without changing strict compatibility.
    /// </summary>
    /// <param name="input">The source text to scan.</param>
    [TestMethod]
    [DataRow("secret                         = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    [DataRow("my_secret: str = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    [DataRow("my_secret: SecretStr = SecretStr(\"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\")")]
    [DataRow("pword = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"")]
    public void NativeGenericRuleCoversModernAssignments(string input)
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", input);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("generic-api-key", input);

        Assert.IsEmpty(strictFindings);
        Assert.HasCount(1, nativeFindings);
        Assert.AreEqual("A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH", nativeFindings[0].Secret);
    }

    /// <summary>
    /// Verifies documented client-side keys are suppressed only by the native profile.
    /// </summary>
    /// <param name="input">The public-key assignment.</param>
    [TestMethod]
    [DataRow("SUPABASE_PUBLISHABLE_KEY = \"sb_publishable_7Gk2Vm9Qp4Rx8Ts3Yw6Nc1Hd\"")]
    [DataRow("STRIPE_PUBLISHABLE_KEY = \"pk_live_7Gk2Vm9Qp4Rx8Ts3Yw6Nc1Hd\"")]
    [DataRow("STRIPE_PUBLISHABLE_KEY = \"pk_test_7Gk2Vm9Qp4Rx8Ts3Yw6Nc1Hd\"")]
    public void NativeGenericRuleSuppressesDocumentedPublicKeys(string input)
    {
        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", input);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("generic-api-key", input);

        Assert.HasCount(1, strictFindings);
        Assert.IsEmpty(nativeFindings);
    }

    /// <summary>
    /// Verifies the Supabase secret-key counterpart remains reportable.
    /// </summary>
    [TestMethod]
    public void NativeGenericRuleDoesNotSuppressSupabaseSecretKey()
    {
        const string input = "SUPABASE_SECRET_KEY = \"sb_secret_7Gk2Vm9Qp4Rx8Ts3Yw6Nc1Hd\"";

        IReadOnlyList<Finding> findings = ScanNativeRule("generic-api-key", input);

        Assert.HasCount(1, findings);
        Assert.AreEqual("sb_secret_7Gk2Vm9Qp4Rx8Ts3Yw6Nc1Hd", findings[0].Secret);
    }

    /// <summary>
    /// Verifies Cargo checksum suppression requires the checksum file path.
    /// </summary>
    [TestMethod]
    public void NativeGenericRuleSuppressesCargoChecksumOnlyInChecksumFile()
    {
        const string input = "{\"files\":{\"api_key\":\"7f4a9c2e8b6d1f305a7c9e2b4d6f8a1c3e5b7d9f2a4c6e8b1d3f5a7c9e2b4d6f\"}}";

        IReadOnlyList<Finding> cargoFindings = ScanNativeRule(
            "generic-api-key",
            input,
            "vendor/package/.cargo-checksum.json");
        IReadOnlyList<Finding> ordinaryFindings = ScanNativeRule(
            "generic-api-key",
            input,
            "fixture.json");

        Assert.IsEmpty(cargoFindings);
        Assert.HasCount(1, ordinaryFindings);
    }

    /// <summary>
    /// Verifies Cargo files are not ignored as a class.
    /// </summary>
    [TestMethod]
    public void NativeGenericRuleStillFindsCredentialInCargoManifest()
    {
        const string input = "api_key = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"";

        IReadOnlyList<Finding> findings = ScanNativeRule(
            "generic-api-key",
            input,
            "Cargo.toml");

        Assert.HasCount(1, findings);
    }

    /// <summary>
    /// Verifies complete template references in Kubernetes Secret values are suppressed.
    /// </summary>
    [TestMethod]
    public void NativeKubernetesRuleSuppressesTemplateReference()
    {
        const string input = "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"{{ .credential }}\"\n";

        IReadOnlyList<Finding> findings = ScanNativeRule("picket-kubernetes-secret", input, "secret.yaml");

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies a Kubernetes ExternalSecret template is not treated as an embedded Secret.
    /// </summary>
    [TestMethod]
    public void NativeKubernetesRuleRejectsExternalSecretResource()
    {
        const string input = "apiVersion: external-secrets.io/v1\nkind: ExternalSecret\nspec:\n  target:\n    template:\n      data:\n        password: \"{{ .credential }}\"\n";

        IReadOnlyList<Finding> findings = ScanNativeRule("picket-kubernetes-secret", input, "external-secret.yaml");

        Assert.IsEmpty(findings);
    }

    /// <summary>
    /// Verifies concrete Kubernetes Secret values remain reportable.
    /// </summary>
    [TestMethod]
    public void NativeKubernetesRuleStillFindsConcreteValue()
    {
        const string input = "apiVersion: v1\nkind: Secret\nstringData:\n  password: \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"\n";

        IReadOnlyList<Finding> findings = ScanNativeRule("picket-kubernetes-secret", input, "secret.yaml");

        Assert.HasCount(1, findings);
        Assert.AreEqual("A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH", findings[0].Secret);
    }

    /// <summary>
    /// Verifies generated passwords remain detectable when they contain an inherited stopword.
    /// </summary>
    [TestMethod]
    public void NativeGeneratedPasswordRuleFindsValueContainingStopword()
    {
        const string input = "password = \"A7f9Q2hook8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"";

        IReadOnlyList<Finding> strictFindings = ScanStrictRule("generic-api-key", input);
        IReadOnlyList<Finding> nativeFindings = ScanNativeRule("picket-generated-password", input);

        Assert.IsEmpty(strictFindings);
        Assert.HasCount(1, nativeFindings);
        Assert.AreEqual("A7f9Q2hook8Lm4Kx6Np3Rt5Yw7Bc9De1FgH", nativeFindings[0].Secret);
    }

    /// <summary>
    /// Verifies generated passwords may contain punctuation outside the generic rule alphabet.
    /// </summary>
    [TestMethod]
    public void NativeGeneratedPasswordRuleFindsValueContainingPunctuation()
    {
        const string input = "databasePassword: \"G7!qZ@2#vN$8%kR^4&mT*9?xP\"";

        IReadOnlyList<Finding> findings = ScanNativeRule("picket-generated-password", input);

        Assert.HasCount(1, findings);
        Assert.AreEqual("G7!qZ@2#vN$8%kR^4&mT*9?xP", findings[0].Secret);
    }

    /// <summary>
    /// Verifies the embedded prefilter preserves the detector's bounded aligned-assignment support.
    /// </summary>
    [TestMethod]
    public void NativeGeneratedPasswordRuleFindsAlignedAssignment()
    {
        const string input = "password                               = \"A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH\"";

        IReadOnlyList<Finding> findings = ScanNativeRule("picket-generated-password", input);

        Assert.HasCount(1, findings);
        Assert.AreEqual("A7f9Q2v8Lm4Kx6Np3Rt5Yw7Bc9De1FgH", findings[0].Secret);
    }

    /// <summary>
    /// Verifies low-randomness prose and indirections remain suppressed.
    /// </summary>
    /// <param name="input">The password assignment to scan.</param>
    [TestMethod]
    [DataRow("password = \"correct horse battery staple\"")]
    [DataRow("password = \"${DATABASE_PASSWORD}\"")]
    [DataRow("password = \"{{ .credential }}\"")]
    public void NativeGeneratedPasswordRuleRejectsNonGeneratedValues(string input)
    {
        IReadOnlyList<Finding> findings = ScanNativeRule("picket-generated-password", input);

        Assert.IsEmpty(findings);
    }

    private static IReadOnlyList<Finding> ScanNativeRule(
        string ruleId,
        string input,
        string fileName = "fixture.txt")
    {
        SecretRule rule = PicketConfigLoader.LoadDefaultRuleSet().Rules.Single(
            rule => rule.Id.Equals(ruleId, StringComparison.Ordinal));
        return Scan(rule, input, fileName, enableRandomnessScoring: true);
    }

    private static IReadOnlyList<Finding> ScanStrictRule(string ruleId, string input)
    {
        SecretRule rule = GitleaksConfigLoader.LoadDefaultRuleSet().Rules.Single(
            rule => rule.Id.Equals(ruleId, StringComparison.Ordinal));
        return Scan(rule, input, "fixture.txt", enableRandomnessScoring: false);
    }

    private static IReadOnlyList<Finding> Scan(
        SecretRule rule,
        string input,
        string fileName,
        bool enableRandomnessScoring)
    {
        return SecretScanner.Scan(new ScanRequest(
            Encoding.UTF8.GetBytes(input),
            fileName,
            new RuleSet([rule]),
            maxDecodeDepth: 0)
        {
            EnableNativeDetectors = rule.Detector.Length != 0,
            EnableRandomnessScoring = enableRandomnessScoring,
        });
    }
}
