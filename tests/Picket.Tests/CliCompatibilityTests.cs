using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Verify;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Tests;

/// <summary>
/// Tests Gitleaks-compatible CLI behavior through the built executable.
/// </summary>
[TestClass]
public sealed class CliCompatibilityTests
{
    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that --exit-code controls the leak exit code.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanUsesConfiguredExitCode()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--exit-code", "7").ConfigureAwait(false);

        Assert.AreEqual(7, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that -r writes JSON reports to a file instead of standard output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.json");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that -r - writes JSON reports to standard output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesStdoutReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", "-").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that compatibility directory scans keep the Gitleaks JSON shape.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesGitleaksJsonReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.DoesNotContain("\"schema\":\"picket.report.v1\"", result.Stdout);
        Assert.DoesNotContain("blobSha256", result.Stdout);
    }

    /// <summary>
    /// Verifies that -f csv writes a Gitleaks-compatible CSV report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesCsvReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "csv").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags\n", result.Stdout);
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,11,,,,,secret.txt:token:1,\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that report paths ending in .csv infer CSV when -f is omitted.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanInfersCsvReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.csv");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,11,,,,,secret.txt:token:1,\n", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that -f junit writes a Gitleaks-compatible JUnit report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesJunitReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "junit").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", result.Stdout);
        Assert.Contains("<testsuite failures=\"1\" name=\"gitleaks\" tests=\"1\" time=\"\">", result.Stdout);
        Assert.Contains("<failure message=\"token has detected a secret in file secret.txt, line 1.\" type=\"\">", result.Stdout);
        Assert.Contains("{&#xA;&#x9;&#34;RuleID&#34;: &#34;token&#34;,", result.Stdout);
    }

    /// <summary>
    /// Verifies that -f sarif writes a Gitleaks-compatible SARIF report.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesSarifReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "sarif").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\"", result.Stdout);
        Assert.Contains("\"name\": \"gitleaks\"", result.Stdout);
        Assert.Contains("\"ruleId\": \"token\"", result.Stdout);
        Assert.Contains("\"uri\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"text\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that compatibility directory scans reject native JSONL reports.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeJsonlReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported report format: jsonl", result.Stderr);
    }

    /// <summary>
    /// Verifies that compatibility directory scans reject native GitLab Code Quality reports.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeGitLabReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "gitlab").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported report format: gitlab", result.Stderr);
    }

    /// <summary>
    /// Verifies that compatibility directory scans reject native HTML reports.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeHtmlReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "html").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported report format: html", result.Stderr);
    }

    /// <summary>
    /// Verifies that compatibility directory scans reject native TOON reports.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeToonReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-f", "toon").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported report format: toon", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scans can write Picket JSONL reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesJsonlReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"secret.txt\"", result.Stdout);
        Assert.Contains("\"blobSha256\":\"7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded Picket default rule pack when no config is supplied.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedPicketDefaultRulePack()
    {
        using TempDirectory root = TempDirectory.Create();
        string accountKey = CreateAzureStorageAccountKeyFixture();
        File.WriteAllText(
            Path.Combine(root.Path, "settings.txt"),
            $"DefaultEndpointsProtocol=https;AccountName=picketstorage;AccountKey={accountKey};EndpointSuffix=core.windows.net");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-azure-storage-connection-string\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{accountKey}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"Azure\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://learn.microsoft.com/azure/storage/common/storage-account-keys-manage\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded database connection URL rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedDatabaseConnectionUrlRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string connectionUrl = CreateDatabaseConnectionUrlFixture();
        File.WriteAllText(Path.Combine(root.Path, "settings.env"), $"DATABASE_URL=\"{connectionUrl}\"");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-database-connection-url\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{connectionUrl}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"Database\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded Sourcegraph access token rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedSourcegraphAccessTokenRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateSourcegraphAccessTokenFixture();
        File.WriteAllText(Path.Combine(root.Path, "settings.env"), $"SOURCEGRAPH_TOKEN=\"{token}\"");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-sourcegraph-access-token\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{token}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"Sourcegraph\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://sourcegraph.com/docs/api\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded GCP service account key rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedGcpServiceAccountRule()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, "service-account.json"), CreateGcpServiceAccountKeyJsonFixture());

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-gcp-service-account-key\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"GCP\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://cloud.google.com/iam/docs/keys-create-delete\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded Google API key rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedGoogleApiKeyRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string apiKey = CreateGoogleApiKeyFixture();
        File.WriteAllText(Path.Combine(root.Path, "settings.txt"), $"api_key = \"{apiKey}\"");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-google-api-key\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{apiKey}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"GCP\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://cloud.google.com/docs/authentication/api-keys\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded GitHub personal access token rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedGitHubPersonalAccessTokenRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubPatFixture();
        File.WriteAllText(Path.Combine(root.Path, "settings.txt"), token);

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-github-personal-access-token\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{token}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"GitHub\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens\"", result.Stdout);
        Assert.DoesNotContain("\"ruleId\":\"github-pat\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the embedded AWS access key pair rule.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesEmbeddedAwsAccessKeyPairRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string accessKeyId = CreateAwsAccessKeyIdFixture();
        string secretAccessKey = CreateAwsSecretAccessKeyFixture();
        File.WriteAllText(
            Path.Combine(root.Path, "credentials.ini"),
            $"aws_access_key_id = {accessKeyId}{Environment.NewLine}aws_secret_access_key = {secretAccessKey}");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"picket-aws-access-key-pair\"", result.Stdout);
        Assert.Contains($"\"secret\":\"{secretAccessKey}\"", result.Stdout);
        Assert.Contains("\"rulePack\":\"picket-default\"", result.Stdout);
        Assert.Contains("\"provider\":\"AWS\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"documentationUrl\":\"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that target-local config still takes precedence over the embedded Picket default rule pack.
    /// </summary>
    [TestMethod]
    public async Task NativeScanPrefersTargetLocalConfigOverEmbeddedPicketDefaultRulePack()
    {
        using TempDirectory root = TempDirectory.Create();
        string accountKey = CreateAzureStorageAccountKeyFixture();
        File.WriteAllText(Path.Combine(root.Path, ".gitleaks.toml"), CreateRuleConfig("local-rule", "local-only-secret"));
        File.WriteAllText(
            Path.Combine(root.Path, "settings.txt"),
            $"DefaultEndpointsProtocol=https;AccountName=picketstorage;AccountKey={accountKey};EndpointSuffix=core.windows.net");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.DoesNotContain("picket-azure-storage-connection-string", result.Stdout);
        Assert.DoesNotContain("picket-default", result.Stdout);
    }

    /// <summary>
    /// Verifies that --profile picket opts a compatibility directory command into native config and report behavior.
    /// </summary>
    [TestMethod]
    public async Task DirectoryProfilePicketUsesNativeConfigAndReports()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG"] = configPath,
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            environment,
            "dir",
            root.Path,
            "--profile",
            "picket",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"blobSha256\":\"7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that unsupported scan profiles are rejected before scanning.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsUnsupportedProfile()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "--profile", "strict").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported profile: strict", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scans report decode provenance for decoded findings.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesDecodePathForDecodedFinding()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "encoded=dG9rZW4tMTIzNDU=");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"secret\":\"token-12345\"", result.Stdout);
        Assert.Contains("\"decodePath\":[\"base64\"]", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can write Picket CSV reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesCsvReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "csv").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,SecretSha256,Match,MatchSha256,BlobSha256,DecodePath,Line,Commit,Entropy,Author,Email,Date,Message,Fingerprint,ValidationState,Severity,Confidence,RulePack,Provider,DocumentationUrl,ProvenanceType,BaselineStatus,IgnoreReason,Tags,Link\n", result.Stdout);
        Assert.Contains("picket.finding.v1,token,,secret.txt,,1,1,1,11,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,,token-12345,,", result.Stdout);
        Assert.Contains(",unknown,critical,high,,,,filesystem,new,,", result.Stdout);
        Assert.DoesNotContain("RuleID,Commit,File,SymlinkFile", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can write Picket JUnit reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesJunitReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "junit").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("<testsuite failures=\"1\" name=\"picket\" tests=\"1\" time=\"\">", result.Stdout);
        Assert.DoesNotContain("name=\"gitleaks\"", result.Stdout);
        Assert.Contains("<property name=\"schema\" value=\"picket.junit.v1\"></property>", result.Stdout);
        Assert.Contains("<failure message=\"token detected a secret in secret.txt on line 1.\" type=\"picket.finding.v1\">", result.Stdout);
        Assert.Contains("{&#34;schema&#34;:&#34;picket.finding.v1&#34;,&#34;ruleId&#34;:&#34;token&#34;", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can write GitLab Code Quality reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesGitLabCodeQualityReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "gitlab").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"check_name\":\"token\"", result.Stdout);
        Assert.Contains("\"severity\":\"critical\"", result.Stdout);
        Assert.Contains("\"location\":{\"path\":\"secret.txt\",\"lines\":{\"begin\":1}}", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can write Picket HTML reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesHtmlReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "html").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("<!doctype html>", result.Stdout);
        Assert.Contains("<h1>Picket Secret Scan Report</h1>", result.Stdout);
        Assert.Contains("<span>Findings</span><strong>1</strong>", result.Stdout);
        Assert.Contains("secret.txt:1:1", result.Stdout);
        Assert.Contains("picket:v1:", result.Stdout);
        Assert.Contains("Secret SHA-256", result.Stdout);
        Assert.Contains("Blob SHA-256", result.Stdout);
        Assert.DoesNotContain("<script", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the Picket rich JSON report shape.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesPicketJsonReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.report.v1\"", result.Stdout);
        Assert.Contains("\"rules\":[{\"id\":\"token\"", result.Stdout);
        Assert.Contains("\"findings\":[{\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"blobSha256\":\"7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad\"", result.Stdout);
        Assert.Contains("\"validationState\":\"unknown\"", result.Stdout);
        Assert.Contains("\"severity\":\"critical\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans attach offline validation metadata to known provider tokens.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesOfflineValidationState()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), CreateGitHubPatFixture());

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can filter findings by offline validation result.
    /// </summary>
    [TestMethod]
    public async Task NativeScanFiltersOfflineValidationResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_invalid", Environment.NewLine, "custom-12345"));

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl", "--results", "invalid").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"invalid\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can filter to live verified active results.
    /// </summary>
    [TestMethod]
    public async Task NativeScanOnlyVerifiedKeepsActiveLiveResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        string token = CreateGitHubPatFixture();
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(
            Path.Combine(root.Path, "secret.txt"),
            string.Concat(token, Environment.NewLine, "custom-12345"));
        WriteActiveGitHubValidationCache(cachePath, configPath, token);

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--cache-dir",
            cachePath,
            "--verify",
            "-f",
            "jsonl",
            "--only-verified").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"active\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can explicitly opt into guarded live provider verification.
    /// </summary>
    [TestMethod]
    public async Task NativeScanVerifyBlocksUnsafeProviderEndpoint()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), CreateGitHubPatFixture());

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "--verify",
            "--github-api-endpoint",
            "https://metadata.google.internal/user",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"error\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native live verification blocks unsafe provider proxies before a proxy can see requests.
    /// </summary>
    [TestMethod]
    public async Task NativeScanVerifyBlocksUnsafeProviderProxy()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "--verify",
            "--github-api-proxy",
            "http://127.0.0.1:8080",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("blocked GitHub API proxy endpoint", result.Stderr);
        Assert.Contains("endpoint URI must use HTTPS", result.Stderr);
    }

    /// <summary>
    /// Verifies that scan provider endpoint options require explicit live verification.
    /// </summary>
    [TestMethod]
    public async Task NativeScanProviderEndpointRequiresVerify()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync("scan", root.Path, "--github-api-endpoint", "https://api.github.com/user").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("live provider options require --verify", result.Stderr);
    }

    /// <summary>
    /// Verifies that scan provider proxy options require explicit live verification.
    /// </summary>
    [TestMethod]
    public async Task NativeScanProviderProxyRequiresVerify()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync("scan", root.Path, "--github-api-proxy", "http://127.0.0.1:8080").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("live provider options require --verify", result.Stderr);
    }

    /// <summary>
    /// Verifies that scan provider rate-limit options require explicit live verification.
    /// </summary>
    [TestMethod]
    public async Task NativeScanProviderRateLimitRequiresVerify()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync("scan", root.Path, "--live-provider-rate-limit-ms", "100").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("live provider options require --verify", result.Stderr);
    }

    /// <summary>
    /// Verifies that scan provider TLS options require explicit live verification.
    /// </summary>
    [TestMethod]
    public async Task NativeScanProviderTlsModeRequiresVerify()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync("scan", root.Path, "--live-tls-mode", "tls12-plus").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("live provider options require --verify", result.Stderr);
    }

    /// <summary>
    /// Verifies that live TLS mode values are validated before scanning begins.
    /// </summary>
    [TestMethod]
    public async Task NativeScanRejectsUnsupportedLiveTlsMode()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliAsync("scan", root.Path, "--verify", "--live-tls-mode", "legacy").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("unsupported live TLS mode: legacy", result.Stderr);
    }

    /// <summary>
    /// Verifies that native verification runs safe offline validators and writes native findings.
    /// </summary>
    [TestMethod]
    public async Task VerifyWritesOfflineValidationState()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), CreateGitHubPatFixture());

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "verify", "--offline", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native verification can validate findings from a Gitleaks JSON report.
    /// </summary>
    [TestMethod]
    public async Task VerifyReadsGitleaksJsonReportInput()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = Path.Combine(root.Path, "gitleaks.json");
        File.WriteAllText(reportPath, GitleaksJsonReportWriter.Write([CreateGitHubPatFinding(CreateGitHubPatFixture())]));

        CliResult result = await RunCliAsync("verify", reportPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"file\":\"secret.txt\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.DoesNotContain("gitleaks.json", result.Stdout);
    }

    /// <summary>
    /// Verifies that native verification can filter findings by offline validation result.
    /// </summary>
    [TestMethod]
    public async Task VerifyFiltersOfflineValidationResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_invalid", Environment.NewLine, "custom-12345"));

        CliResult result = await RunCliAsync("verify", root.Path, "-c", configPath, "-f", "jsonl", "--results", "invalid").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"invalid\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that --only-verified keeps structurally valid offline results.
    /// </summary>
    [TestMethod]
    public async Task VerifyOnlyVerifiedKeepsStructurallyValidResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        File.WriteAllText(
            Path.Combine(root.Path, "secret.txt"),
            string.Concat(CreateGitHubPatFixture(), Environment.NewLine, "custom-12345"));

        CliResult result = await RunCliAsync("verify", root.Path, "-c", configPath, "-f", "jsonl", "--only-verified").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"structurally-valid\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that --only-verified keeps live verified active results.
    /// </summary>
    [TestMethod]
    public async Task VerifyOnlyVerifiedKeepsActiveLiveResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        string token = CreateGitHubPatFixture();
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(
            Path.Combine(root.Path, "secret.txt"),
            string.Concat(token, Environment.NewLine, "custom-12345"));
        WriteActiveGitHubValidationCache(cachePath, configPath, token);

        CliResult result = await RunCliAsync(
            "verify",
            root.Path,
            "-c",
            configPath,
            "--cache-dir",
            cachePath,
            "--live",
            "-f",
            "jsonl",
            "--only-verified").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"active\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that live verification blocks unsafe provider endpoints before network verification can run.
    /// </summary>
    [TestMethod]
    public async Task VerifyLiveBlocksUnsafeProviderEndpoint()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), CreateGitHubPatFixture());

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            "verify",
            "--live",
            "--github-api-endpoint",
            "https://metadata.google.internal/user",
            "--results",
            "error",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"error\"", result.Stdout);
        Assert.DoesNotContain("live verification is not implemented yet", result.Stderr);
    }

    /// <summary>
    /// Verifies that live verification does not contact providers for offline-invalid findings.
    /// </summary>
    [TestMethod]
    public async Task VerifyLiveKeepsOfflineInvalidFindingsLocal()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_invalid"));

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            "verify",
            "-c",
            configPath,
            "--live",
            "--github-api-endpoint",
            "https://metadata.google.internal/user",
            "--results",
            "invalid",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"invalid\"", result.Stdout);
        Assert.DoesNotContain("\"validationState\":\"error\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that verify help advertises the native offline workflow.
    /// </summary>
    [TestMethod]
    public async Task VerifyHelpAdvertisesOfflineValidation()
    {
        CliResult result = await RunCliAsync("verify", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket verify", result.Stdout);
        Assert.Contains("--offline", result.Stdout);
        Assert.Contains("--live", result.Stdout);
        Assert.Contains("--github-api-endpoint", result.Stdout);
        Assert.Contains("--github-api-proxy", result.Stdout);
        Assert.Contains("--live-tls-mode", result.Stdout);
        Assert.Contains("--live-rate-limit-ms", result.Stdout);
        Assert.Contains("--live-provider-rate-limit-ms", result.Stdout);
        Assert.Contains("--results", result.Stdout);
        Assert.Contains("--only-verified", result.Stdout);
        Assert.Contains("--max-target-megabytes", result.Stdout);
        Assert.Contains("--max-archive-depth", result.Stdout);
        Assert.Contains("--timeout", result.Stdout);
        Assert.Contains("--diagnostics", result.Stdout);
        Assert.Contains("--diagnostics-dir", result.Stdout);
        Assert.Contains("--cache-mode", result.Stdout);
        Assert.DoesNotContain("Additional Arguments", result.Stdout);
    }

    /// <summary>
    /// Verifies that Gitleaks-compatible commands expose command-local help.
    /// </summary>
    [TestMethod]
    public async Task CompatibilityCommandsExposeCommandLocalHelp()
    {
        CliResult git = await RunCliAsync("git", "--help").ConfigureAwait(false);
        CliResult directory = await RunCliAsync("dir", "--help").ConfigureAwait(false);
        CliResult stdin = await RunCliAsync("stdin", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, git.ExitCode);
        Assert.Contains("picket git", git.Stdout);
        Assert.Contains("-f, --report-format", git.Stdout);
        Assert.Contains("--log-opts", git.Stdout);
        Assert.Contains("--timeout", git.Stdout);
        Assert.DoesNotContain("Additional Arguments", git.Stdout);
        Assert.AreEqual(0, directory.ExitCode);
        Assert.Contains("picket dir", directory.Stdout);
        Assert.Contains("--follow-symlinks", directory.Stdout);
        Assert.Contains("--max-archive-depth", directory.Stdout);
        Assert.DoesNotContain("Additional Arguments", directory.Stdout);
        Assert.AreEqual(0, stdin.ExitCode);
        Assert.Contains("picket stdin", stdin.Stdout);
        Assert.Contains("--max-decode-depth", stdin.Stdout);
        Assert.Contains("--timeout", stdin.Stdout);
        Assert.DoesNotContain("Additional Arguments", stdin.Stdout);
    }

    /// <summary>
    /// Verifies that native analysis writes offline incident-response JSON without leaking the raw secret.
    /// </summary>
    [TestMethod]
    public async Task AnalyzeWritesOfflineIncidentResponseJson()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        string token = CreateGitHubPatFixture();
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), token);

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "analyze", "--offline", "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.analysis.report.v1\"", result.Stdout);
        Assert.Contains("\"schema\":\"picket.analysis.v1\"", result.Stdout);
        Assert.Contains("\"provider\":\"GitHub\"", result.Stdout);
        Assert.Contains("\"credentialType\":\"GitHub token\"", result.Stdout);
        Assert.Contains("\"risk\":\"critical\"", result.Stdout);
        Assert.Contains("\"identity\":\"unknown-offline\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.Contains("\"recommendedActions\"", result.Stdout);
        Assert.Contains("\"revocationAvailable\":true", result.Stdout);
        Assert.Contains("https://api.github.com/credentials/revoke", result.Stdout);
        Assert.Contains("<github-token>", result.Stdout);
        Assert.Contains("\"revocationGuidance\"", result.Stdout);
        Assert.DoesNotContain(token, result.Stdout);
    }

    /// <summary>
    /// Verifies that native analysis can analyze findings from a Picket JSON Lines report.
    /// </summary>
    [TestMethod]
    public async Task AnalyzeReadsPicketJsonLinesReportInput()
    {
        using TempDirectory root = TempDirectory.Create();
        string token = CreateGitHubPatFixture();
        string reportPath = Path.Combine(root.Path, "report.jsonl");
        File.WriteAllText(reportPath, PicketJsonlReportWriter.Write([CreateGitHubPatFinding(token)]));

        CliResult result = await RunCliAsync("analyze", reportPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.analysis.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"provider\":\"GitHub\"", result.Stdout);
        Assert.Contains("\"file\":\"secret.txt\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
        Assert.DoesNotContain(token, result.Stdout);
        Assert.DoesNotContain("report.jsonl", result.Stdout);
    }

    /// <summary>
    /// Verifies that native analysis can filter by offline validation result and write JSON Lines.
    /// </summary>
    [TestMethod]
    public async Task AnalyzeFiltersOfflineValidationResults()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteVerificationFilterConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_invalid", Environment.NewLine, "custom-12345"));

        CliResult result = await RunCliAsync("analyze", root.Path, "-c", configPath, "-f", "jsonl", "--results", "invalid").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"invalid\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that live analysis uses guarded provider validation before writing analysis.
    /// </summary>
    [TestMethod]
    public async Task AnalyzeLiveBlocksUnsafeProviderEndpoint()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), CreateGitHubPatFixture());

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            "analyze",
            "--live",
            "--github-api-endpoint",
            "https://metadata.google.internal/user",
            "--results",
            "error",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"error\"", result.Stdout);
        Assert.Contains("\"identity\":\"unknown-live\"", result.Stdout);
        Assert.Contains("liveValidationReason=endpoint blocked", result.Stdout);
        Assert.DoesNotContain("not implemented", result.Stderr);
    }

    /// <summary>
    /// Verifies that analyze help advertises offline analysis output.
    /// </summary>
    [TestMethod]
    public async Task AnalyzeHelpAdvertisesOfflineAnalysis()
    {
        CliResult result = await RunCliAsync("analyze", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket analyze", result.Stdout);
        Assert.Contains("--offline", result.Stdout);
        Assert.Contains("--live", result.Stdout);
        Assert.Contains("--github-api-endpoint", result.Stdout);
        Assert.Contains("--github-api-proxy", result.Stdout);
        Assert.Contains("--live-tls-mode", result.Stdout);
        Assert.Contains("--live-rate-limit-ms", result.Stdout);
        Assert.Contains("--live-provider-rate-limit-ms", result.Stdout);
        Assert.Contains("--results", result.Stdout);
        Assert.Contains("--only-verified", result.Stdout);
        Assert.Contains("json|jsonl|text", result.Stdout);
        Assert.Contains("--max-target-megabytes", result.Stdout);
        Assert.Contains("--max-archive-depth", result.Stdout);
        Assert.Contains("--timeout", result.Stdout);
        Assert.Contains("--diagnostics", result.Stdout);
        Assert.Contains("--diagnostics-dir", result.Stdout);
        Assert.DoesNotContain("Additional Arguments", result.Stdout);
    }

    /// <summary>
    /// Verifies that root help advertises the command index instead of every command option.
    /// </summary>
    [TestMethod]
    public async Task RootHelpAdvertisesCommandIndex()
    {
        CliResult result = await RunCliAsync("--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket [command] [options]", result.Stdout);
        Assert.Contains("Commands:", result.Stdout);
        Assert.Contains("scan <path>", result.Stdout);
        Assert.Contains("verify <path>", result.Stdout);
        Assert.Contains("analyze <path>", result.Stdout);
        Assert.Contains("git <repo>", result.Stdout);
        Assert.Contains("dir, directory, file <path>", result.Stdout);
        Assert.Contains("stdin", result.Stdout);
        Assert.Contains("rules", result.Stdout);
        Assert.Contains("hooks", result.Stdout);
        Assert.Contains("tui <report>", result.Stdout);
        Assert.Contains("--version", result.Stdout);
        Assert.DoesNotContain("--github-api-endpoint", result.Stdout);
        Assert.DoesNotContain("--max-decode-depth", result.Stdout);
        Assert.DoesNotContain("--diagnostics-dir", result.Stdout);
        Assert.DoesNotContain("  detect", result.Stdout);
        Assert.DoesNotContain("  protect", result.Stdout);
        Assert.DoesNotContain("Additional Arguments", result.Stdout);
    }

    /// <summary>
    /// Verifies that the help command form displays command-local help.
    /// </summary>
    [TestMethod]
    public async Task HelpCommandDisplaysCommandLocalHelp()
    {
        CliResult result = await RunCliAsync("help", "scan").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket scan [<path>] [options]", result.Stdout);
        Assert.Contains("--github-api-endpoint", result.Stdout);
        Assert.Contains("--max-target-megabytes", result.Stdout);
        Assert.DoesNotContain("Additional Arguments", result.Stdout);
    }

    /// <summary>
    /// Verifies that System.CommandLine shell suggestions expose public commands.
    /// </summary>
    [TestMethod]
    public async Task RootSuggestionsAdvertisePublicCommands()
    {
        CliResult result = await RunCliAsync("[suggest:8]", "sc").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("scan", result.Stdout);
        Assert.DoesNotContain("detect", result.Stdout);
        Assert.DoesNotContain("protect", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scan cache files are not scanned as source files on later runs.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesCacheDirectoryWithoutScanningCacheFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        string diagnosticsDir = Path.Combine(root.Path, "diagnostics");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult first = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult second = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--cache-dir",
            cachePath,
            "-f",
            "jsonl",
            "--diagnostics",
            "cpu",
            "--diagnostics-dir",
            diagnosticsDir).ConfigureAwait(false);
        string[] secondLines = second.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string cpu = File.ReadAllText(Path.Combine(diagnosticsDir, "cpu.json"));

        Assert.AreEqual(1, first.ExitCode);
        Assert.AreEqual(1, second.ExitCode);
        Assert.IsTrue(Directory.Exists(cachePath));
        Assert.HasCount(1, secondLines);
        Assert.Contains("\"file\":\"secret.txt\"", secondLines[0]);
        Assert.DoesNotContain(".picket/cache", second.Stdout);
        Assert.Contains("\"scanInputs\": 1", cpu);
        Assert.Contains("\"findings\": 1", cpu);
        Assert.Contains("\"cacheHits\": 1", cpu);
        Assert.Contains("\"cacheMisses\": 0", cpu);
        Assert.Contains("\"cacheWrites\": 0", cpu);
    }

    /// <summary>
    /// Verifies that native scan caching deduplicates identical same-extension blobs.
    /// </summary>
    [TestMethod]
    public async Task NativeScanCacheDeduplicatesSameExtensionBlobs()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "first.txt"), "finding");
        File.WriteAllText(Path.Combine(root.Path, "second.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.Contains("\"file\":\"first.txt\"", scan.Stdout);
        Assert.Contains("\"file\":\"second.txt\"", scan.Stdout);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.Contains("entries: 1", stats.Stdout);
        Assert.Contains("current-key entries: 1", stats.Stdout);
    }

    /// <summary>
    /// Verifies that native scan caching keeps path-sensitive rule results separate.
    /// </summary>
    [TestMethod]
    public async Task NativeScanCacheKeepsPathSensitiveRulesSeparate()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "word"
            regex = '''finding'''
            path = '''first\.txt$'''
            """);
        File.WriteAllText(Path.Combine(root.Path, "first.txt"), "finding");
        File.WriteAllText(Path.Combine(root.Path, "second.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.Contains("\"file\":\"first.txt\"", scan.Stdout);
        Assert.DoesNotContain("\"file\":\"second.txt\"", scan.Stdout);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.Contains("entries: 2", stats.Stdout);
        Assert.Contains("current-key entries: 2", stats.Stdout);
    }

    /// <summary>
    /// Verifies that native scan cache defaults avoid persisted raw evidence.
    /// </summary>
    [TestMethod]
    public async Task NativeScanCacheDefaultsToSecretHashOnlyMode()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult first = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult second = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult defaultStats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path).ConfigureAwait(false);
        CliResult rawStats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path, "--cache-mode", "raw").ConfigureAwait(false);
        string cacheEntry = File.ReadAllText(GetSingleCacheEntryPath(cachePath));
        string expectedHash = ComputeSha256("finding").ToLowerInvariant();

        Assert.AreEqual(1, first.ExitCode);
        Assert.Contains("\"secret\":\"finding\"", first.Stdout);
        Assert.AreEqual(1, second.ExitCode);
        Assert.Contains("\"match\":\"\"", second.Stdout);
        Assert.Contains("\"secret\":\"\"", second.Stdout);
        Assert.Contains($"\"secretSha256\":\"{expectedHash}\"", second.Stdout);
        Assert.Contains($"\"matchSha256\":\"{expectedHash}\"", second.Stdout);
        Assert.Contains("\"line\":\"\"", second.Stdout);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("finding")), cacheEntry);
        Assert.Contains("storageMode\tSecretHashOnly", cacheEntry);
        Assert.AreEqual(0, defaultStats.ExitCode);
        Assert.Contains("current-key entries: 1", defaultStats.Stdout);
        Assert.AreEqual(0, rawStats.ExitCode);
        Assert.Contains("current-key entries: 0", rawStats.Stdout);
    }

    /// <summary>
    /// Verifies that native scan cache entries are invalidated by inline allow behavior.
    /// </summary>
    [TestMethod]
    public async Task NativeScanCacheSeparatesGitleaksAllowBehavior()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345 # gitleaks:allow");

        CliResult honoringAllow = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult ignoringAllow = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "--ignore-gitleaks-allow", "-f", "jsonl").ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path, "--ignore-gitleaks-allow").ConfigureAwait(false);

        Assert.AreEqual(0, honoringAllow.ExitCode);
        Assert.IsEmpty(honoringAllow.Stdout);
        Assert.AreEqual(1, ignoringAllow.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", ignoringAllow.Stdout);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.Contains("entries: 2", stats.Stdout);
        Assert.Contains("current-key entries: 1", stats.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can load config from PICKET_CONFIG_TOML.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesPicketConfigTomlEnvironmentVariable()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "native-only-secret");
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithEnvironmentAsync(environment, "scan", root.Path, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"native-rule\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that strict compatibility directory scans ignore PICKET_CONFIG_TOML.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanIgnoresPicketConfigTomlEnvironmentVariable()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, ".gitleaks.toml"), CreateRuleConfig("compat-rule", "compat-only-secret"));
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "native-only-secret");
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithEnvironmentAsync(environment, "dir", root.Path, "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.DoesNotContain("native-rule", result.Stdout);
        Assert.DoesNotContain("native-only-secret", result.Stdout);
    }

    /// <summary>
    /// Verifies strict compatibility directory scans reject native cache flags.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeCacheDirFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--cache-dir", Path.Combine(root.Path, ".picket", "cache")).ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("unknown flag: --cache-dir", result.Stderr);
    }

    /// <summary>
    /// Verifies strict compatibility directory scans reject native archive entry-count caps.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeArchiveEntryLimitFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-archive-entries", "1").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("unknown flag: --max-archive-entries", result.Stderr);
    }

    /// <summary>
    /// Verifies strict compatibility directory scans reject native archive byte caps.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeArchiveByteLimitFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-archive-megabytes", "1").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("unknown flag: --max-archive-megabytes", result.Stderr);
    }

    /// <summary>
    /// Verifies strict compatibility directory scans reject native archive compression-ratio caps.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsNativeArchiveRatioFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-archive-ratio", "1").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.Contains("unknown flag: --max-archive-ratio", result.Stderr);
    }

    /// <summary>
    /// Verifies native scans can cap archive entries and emit a clear warning.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsArchiveEntryLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("first.txt", "token-12345"),
            ("second.txt", "token-23456"));

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--max-archive-depth",
            "1",
            "--max-archive-entries",
            "1",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"secrets.zip!first.txt\"", result.Stdout);
        Assert.DoesNotContain("secrets.zip!second.txt", result.Stdout);
        Assert.Contains("archive entry limit reached after 1 entries while reading secrets.zip", result.Stderr);
    }

    /// <summary>
    /// Verifies native scans include first-level archives by default with bounded archive traversal.
    /// </summary>
    [TestMethod]
    public async Task NativeScanFindsZipArchiveSecretByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteZipFile(Path.Combine(root.Path, "secrets.zip"), ("nested/secret.txt", "token-12345"));

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"secrets.zip!nested/secret.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies native scans can explicitly disable archive traversal.
    /// </summary>
    [TestMethod]
    public async Task NativeScanCanDisableArchiveTraversal()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteZipFile(Path.Combine(root.Path, "secrets.zip"), ("nested/secret.txt", "token-12345"));

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--max-archive-depth=0",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
    }

    /// <summary>
    /// Verifies native scans can cap decompressed archive bytes and emit a clear warning.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsArchiveByteLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("first.txt", string.Concat("token-12345\n", new string('!', 599_988))),
            ("second.txt", string.Concat("token-23456\n", new string('!', 599_988))));

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--max-archive-depth",
            "1",
            "--max-archive-megabytes",
            "1",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"secrets.zip!first.txt\"", result.Stdout);
        Assert.DoesNotContain("secrets.zip!second.txt", result.Stdout);
        Assert.Contains("archive byte limit reached while reading secrets.zip", result.Stderr);
    }

    /// <summary>
    /// Verifies native scans can cap archive compression ratios and emit a clear warning.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsArchiveCompressionRatioLimit()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteCompressedZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("secret.txt", string.Concat("token-12345\n", new string('!', 8192))));

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--max-archive-depth",
            "1",
            "--max-archive-ratio",
            "1",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("archive compression ratio limit reached while reading secrets.zip", result.Stderr);
    }

    /// <summary>
    /// Verifies that native cache stats summarize entries for the active scanner key.
    /// </summary>
    [TestMethod]
    public async Task CacheStatsWritesNativeCacheSummary()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.IsEmpty(stats.Stderr);
        Assert.Contains("cache: ", stats.Stdout);
        Assert.Contains("entries: 1", stats.Stdout);
        Assert.Contains("current-key entries: 1", stats.Stdout);
        Assert.Contains("bytes: ", stats.Stdout);
    }

    /// <summary>
    /// Verifies that cache pruning can remove entries from inactive scanner keys.
    /// </summary>
    [TestMethod]
    public async Task CachePruneDeletesInactiveScannerKeys()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        string otherConfigPath = WriteTokenConfig(root.Path, "other.toml");
        CliResult prune = await RunCliAsync("cache", "prune", "--cache-dir", cachePath, "-c", otherConfigPath, "--source", root.Path, "--other-keys").ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", cachePath, "-c", otherConfigPath, "--source", root.Path).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, prune.ExitCode);
        Assert.Contains("deleted: 1", prune.Stdout);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.Contains("entries: 0", stats.Stdout);
    }

    /// <summary>
    /// Verifies that cache pruning can remove entries older than the configured retention age.
    /// </summary>
    [TestMethod]
    public async Task CachePruneDeletesExpiredEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        File.SetLastWriteTimeUtc(GetSingleCacheEntryPath(cachePath), DateTime.UtcNow - TimeSpan.FromDays(2));
        CliResult prune = await RunCliAsync("cache", "prune", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path, "--older-than-days", "1").ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, prune.ExitCode);
        Assert.Contains("deleted: 1", prune.Stdout);
    }

    /// <summary>
    /// Verifies that cache export and import move active scanner-key entries between cache roots.
    /// </summary>
    [TestMethod]
    public async Task CacheExportImportRoundTripsActiveScannerKeyEntries()
    {
        using TempDirectory root = TempDirectory.Create();
        string sourcePath = Path.Combine(root.Path, "source");
        string destinationPath = Path.Combine(root.Path, "destination");
        Directory.CreateDirectory(sourcePath);
        Directory.CreateDirectory(destinationPath);
        string configPath = WriteFindingWordConfig(root.Path);
        string sourceCachePath = Path.Combine(root.Path, ".picket", "source-cache");
        string destinationCachePath = Path.Combine(root.Path, ".picket", "destination-cache");
        string archivePath = Path.Combine(root.Path, "cache.zip");
        File.WriteAllText(Path.Combine(sourcePath, "secret.txt"), "finding");
        File.WriteAllText(Path.Combine(destinationPath, "secret.txt"), "finding");

        CliResult scan = await RunCliAsync("scan", sourcePath, "-c", configPath, "--cache-dir", sourceCachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult export = await RunCliAsync("cache", "export", "--cache-dir", sourceCachePath, "-c", configPath, "--source", sourcePath, "--output", archivePath).ConfigureAwait(false);
        CliResult import = await RunCliAsync("cache", "import", "--cache-dir", destinationCachePath, "-c", configPath, "--source", destinationPath, "--input", archivePath).ConfigureAwait(false);
        CliResult stats = await RunCliAsync("cache", "stats", "--cache-dir", destinationCachePath, "-c", configPath, "--source", destinationPath).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, export.ExitCode);
        Assert.Contains("exported: 1", export.Stdout);
        Assert.AreEqual(0, import.ExitCode);
        Assert.Contains("imported: 1", import.Stdout);
        Assert.AreEqual(0, stats.ExitCode);
        Assert.Contains("current-key entries: 1", stats.Stdout);
    }

    /// <summary>
    /// Verifies that cache import rejects malformed portable archives.
    /// </summary>
    [TestMethod]
    public async Task CacheImportRejectsMalformedArchive()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteFindingWordConfig(root.Path);
        string cachePath = Path.Combine(root.Path, ".picket", "cache");
        string archivePath = Path.Combine(root.Path, "cache.zip");
        WriteCompressedZipFile(archivePath, ("../evil.cache", "not a cache entry"));

        CliResult import = await RunCliAsync("cache", "import", "--cache-dir", cachePath, "-c", configPath, "--source", root.Path, "--input", archivePath).ConfigureAwait(false);

        Assert.AreEqual(1, import.ExitCode);
        Assert.Contains("failed to import cache: Invalid cache archive entry path", import.Stderr);
        Assert.IsFalse(File.Exists(Path.Combine(root.Path, "evil.cache")));
    }

    /// <summary>
    /// Verifies that cache help advertises supported maintenance commands.
    /// </summary>
    [TestMethod]
    public async Task CacheHelpAdvertisesStatsAndPrune()
    {
        CliResult result = await RunCliAsync("cache", "--help").ConfigureAwait(false);
        CliResult prune = await RunCliAsync("cache", "prune", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket cache [command] [options]", result.Stdout);
        Assert.Contains("stats <source>", result.Stdout);
        Assert.Contains("prune <source>", result.Stdout);
        Assert.Contains("export <source>", result.Stdout);
        Assert.Contains("import <source>", result.Stdout);
        Assert.AreEqual(0, prune.ExitCode);
        Assert.Contains("picket cache prune", prune.Stdout);
        Assert.Contains("--older-than-days", prune.Stdout);
        Assert.Contains("--ignore-gitleaks-allow", prune.Stdout);
        Assert.Contains("--cache-mode", prune.Stdout);
    }

    /// <summary>
    /// Verifies that native scans use the Picket SARIF report shape.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesPicketSarifReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "sarif").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"name\": \"picket\"", result.Stdout);
        Assert.DoesNotContain("\"name\": \"gitleaks\"", result.Stdout);
        Assert.Contains("\"informationUri\": \"https://github.com/willibrandon/picket\"", result.Stdout);
        Assert.Contains("\"ruleId\": \"token\"", result.Stdout);
        Assert.Contains("\"security-severity\": \"8.0\"", result.Stdout);
        Assert.Contains("\"picketFingerprint\": \"picket:v1:", result.Stdout);
        Assert.Contains("\"blobSha256\": \"7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad\"", result.Stdout);
        Assert.Contains("\"validationState\": \"unknown\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can write Picket TOON reports.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesToonReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "toon").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("schema: picket.report.v1", result.Stdout);
        Assert.Contains("summary:\n  findings: 1\n  rules: 1", result.Stdout);
        Assert.Contains("findings[1]{schema,ruleId,description,file,symlinkFile,startLine,endLine,startColumn,endColumn,match,secret,secretSha256,matchSha256,blobSha256,decodePath,line,commit,entropy,author,email,date,message,fingerprint,validationState,severity,confidence,rulePack,provider,provenanceType,baselineStatus,ignoreReason,link}:", result.Stdout);
        Assert.Contains("  picket.finding.v1,token,\"\",secret.txt,\"\",1,1,1,11,token-12345,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,\"\",token-12345,\"\",", result.Stdout);
        Assert.Contains(",unknown,critical,high,\"\",\"\",filesystem,new,\"\",\"\"", result.Stdout);
        Assert.DoesNotContain("\r\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans infer JSONL from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersJsonlReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.jsonl");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans infer CSV from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersCsvReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.csv");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("picket.finding.v1,token,,secret.txt,,1,1,1,11,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,,token-12345,,", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans infer JUnit from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersJunitReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.junit.xml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("<testsuite failures=\"1\" name=\"picket\" tests=\"1\" time=\"\">", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans infer GitLab Code Quality from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersGitLabCodeQualityReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "gl-code-quality-report.json");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"check_name\":\"token\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans infer HTML from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersHtmlReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.html");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("<h1>Picket Secret Scan Report</h1>", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans infer TOON from report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanInfersToonReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.toon");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("schema: picket.report.v1", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that native scans can write multiple inferred report formats in one run.
    /// </summary>
    [TestMethod]
    public async Task NativeScanWritesMultipleReportPaths()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string jsonlReportPath = Path.Combine(root.Path, "report.jsonl");
        string sarifReportPath = Path.Combine(root.Path, "report.sarif");
        string toonReportPath = Path.Combine(root.Path, "report.toon");
        File.WriteAllText(jsonlReportPath, "token-99991");
        File.WriteAllText(sarifReportPath, "token-99992");
        File.WriteAllText(toonReportPath, "token-99993");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "-r",
            jsonlReportPath,
            "-r",
            sarifReportPath,
            "-r",
            toonReportPath).ConfigureAwait(false);

        string jsonl = File.ReadAllText(jsonlReportPath);
        string sarif = File.ReadAllText(sarifReportPath);
        string toon = File.ReadAllText(toonReportPath);
        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", jsonl);
        Assert.Contains("\"name\": \"picket\"", sarif);
        Assert.Contains("summary:\n  findings: 1\n  rules: 1", toon);
        Assert.DoesNotContain("token-99991", jsonl);
        Assert.DoesNotContain("token-99992", sarif);
        Assert.DoesNotContain("token-99993", toon);
    }

    /// <summary>
    /// Verifies that explicit report format is rejected for multiple native report paths.
    /// </summary>
    [TestMethod]
    public async Task NativeScanRejectsReportFormatWithMultipleReportPaths()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string jsonReportPath = Path.Combine(root.Path, "report.json");
        string sarifReportPath = Path.Combine(root.Path, "report.sarif");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "-f",
            "json",
            "-r",
            jsonReportPath,
            "-r",
            sarifReportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("report format cannot be specified when multiple report paths are specified", result.Stderr);
    }

    /// <summary>
    /// Verifies that native scans accept --source as the scan root.
    /// </summary>
    [TestMethod]
    public async Task NativeScanUsesSourceFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("scan", "--source", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans honor .picketignore without scanning the ignore file itself.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsPicketIgnore()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), "ignored.txt\ntoken-99991\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-23456");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"keep.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-23456\"", result.Stdout);
        Assert.DoesNotContain("ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
        Assert.DoesNotContain("token-99991", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans honor .picketignore SHA-256 content hashes.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsPicketIgnoreContentHash()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string ignoredContent = "token-12345";
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), $"sha256:{ComputeSha256(ignoredContent)}\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), ignoredContent);
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-23456");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"keep.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-23456\"", result.Stdout);
        Assert.DoesNotContain("ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans honor .gitignore, .ignore, and hidden-file policy.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsScoutIgnorePolicy()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        Directory.CreateDirectory(Path.Combine(root.Path, ".git"));
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "git-ignored.txt\ntoken-99991\n");
        File.WriteAllText(Path.Combine(root.Path, ".ignore"), "dot-ignored.txt\ntoken-99992\n");
        File.WriteAllText(Path.Combine(root.Path, ".hidden.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "git-ignored.txt"), "token-23456");
        File.WriteAllText(Path.Combine(root.Path, "dot-ignored.txt"), "token-34567");
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-45678");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"keep.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-45678\"", result.Stdout);
        Assert.DoesNotContain(".hidden.txt", result.Stdout);
        Assert.DoesNotContain("git-ignored.txt", result.Stdout);
        Assert.DoesNotContain("dot-ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
        Assert.DoesNotContain("token-23456", result.Stdout);
        Assert.DoesNotContain("token-34567", result.Stdout);
        Assert.DoesNotContain("token-99991", result.Stdout);
        Assert.DoesNotContain("token-99992", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can disable native ignore handling.
    /// </summary>
    [TestMethod]
    public async Task NativeScanNoIgnoreDisablesNativeIgnorePolicy()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        Directory.CreateDirectory(Path.Combine(root.Path, ".git"));
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "git-ignored.txt\n");
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), "ignored.txt\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "git-ignored.txt"), "token-23456");
        File.WriteAllText(Path.Combine(root.Path, ".hidden.txt"), "token-34567");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "-f", "jsonl", "--no-ignore").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"ignored.txt\"", result.Stdout);
        Assert.Contains("\"file\":\"git-ignored.txt\"", result.Stdout);
        Assert.Contains("\"file\":\".hidden.txt\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-12345\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-23456\"", result.Stdout);
        Assert.Contains("\"secret\":\"token-34567\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native scans can apply explicit Scout ignore files.
    /// </summary>
    [TestMethod]
    public async Task NativeScanHonorsExplicitIgnorePath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string ignorePath = Path.Combine(root.Path, "picket.ignore");
        File.WriteAllText(ignorePath, "ignored.txt\ntoken-99991\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-23456");

        CliResult result = await RunCliAsync("scan", root.Path, "-c", configPath, "--ignore-path", ignorePath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"file\":\"keep.txt\"", result.Stdout);
        Assert.DoesNotContain("ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
        Assert.DoesNotContain("token-99991", result.Stdout);
    }

    /// <summary>
    /// Verifies that compatibility directory scans are not affected by native .picketignore rules.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanIgnoresNativePicketIgnore()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        Directory.CreateDirectory(Path.Combine(root.Path, ".git"));
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "git-ignored.txt\n");
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), "ignored.txt\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "git-ignored.txt"), "token-23456");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"File\": \"ignored.txt\"", result.Stdout);
        Assert.Contains("\"File\": \"git-ignored.txt\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-23456\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that baseline creation writes a Gitleaks-compatible baseline that suppresses later scans.
    /// </summary>
    [TestMethod]
    public async Task BaselineCreateWritesConsumableGitleaksBaseline()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string baselinePath = Path.Combine(root.Path, "baseline.json");
        File.WriteAllText(baselinePath, "token-99991");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult create = await RunCliAsync("baseline", "create", root.Path, "-c", configPath, "-r", baselinePath).ConfigureAwait(false);
        string baseline = File.ReadAllText(baselinePath);
        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "--baseline-path", baselinePath, "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, create.ExitCode);
        Assert.IsEmpty(create.Stdout);
        Assert.Contains("\"RuleID\": \"token\"", baseline);
        Assert.Contains("\"Secret\": \"token-12345\"", baseline);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", baseline);
        Assert.DoesNotContain("\"schema\":\"picket.report.v1\"", baseline);
        Assert.DoesNotContain("token-99991", baseline);
        Assert.AreEqual(0, scan.ExitCode);
        Assert.IsEmpty(scan.Stdout);
    }

    /// <summary>
    /// Verifies that secret-hash-only cache entries do not bypass baseline suppression.
    /// </summary>
    [TestMethod]
    public async Task NativeScanAppliesBaselineToSecretHashOnlyCacheHits()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string baselinePath = Path.Combine(root.Path, "baseline.json");
        string cachePath = Path.Combine(root.Path, ".picket-cache");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult create = await RunCliAsync("baseline", "create", root.Path, "-c", configPath, "-r", baselinePath).ConfigureAwait(false);
        CliResult firstScan = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--baseline-path",
            baselinePath,
            "--cache-dir",
            cachePath,
            "--cache-mode",
            "secret-hash-only",
            "-f",
            "jsonl").ConfigureAwait(false);
        CliResult secondScan = await RunCliAsync(
            "scan",
            root.Path,
            "-c",
            configPath,
            "--baseline-path",
            baselinePath,
            "--cache-dir",
            cachePath,
            "--cache-mode",
            "secret-hash-only",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, create.ExitCode);
        Assert.AreEqual(0, firstScan.ExitCode);
        Assert.AreEqual(0, secondScan.ExitCode);
        Assert.IsEmpty(firstScan.Stdout);
        Assert.IsEmpty(secondScan.Stdout);
    }

    /// <summary>
    /// Verifies that baseline creation can scan a --source path and write to standard output.
    /// </summary>
    [TestMethod]
    public async Task BaselineCreateUsesSourceFlagAndStdout()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("baseline", "create", "--source", root.Path, "-c", configPath, "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that baseline creation honors native .picketignore rules.
    /// </summary>
    [TestMethod]
    public async Task BaselineCreateHonorsPicketIgnore()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), "ignored.txt\ntoken-99991\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-23456");

        CliResult result = await RunCliAsync("baseline", "create", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"File\": \"keep.txt\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-23456\"", result.Stdout);
        Assert.DoesNotContain("ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
        Assert.DoesNotContain("token-99991", result.Stdout);
    }

    /// <summary>
    /// Verifies that baseline creation honors .picketignore SHA-256 content hashes.
    /// </summary>
    [TestMethod]
    public async Task BaselineCreateHonorsPicketIgnoreContentHash()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string ignoredContent = "token-12345";
        File.WriteAllText(Path.Combine(root.Path, ".picketignore"), $"sha256:{ComputeSha256(ignoredContent)}\n");
        File.WriteAllText(Path.Combine(root.Path, "ignored.txt"), ignoredContent);
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-23456");

        CliResult result = await RunCliAsync("baseline", "create", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"File\": \"keep.txt\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-23456\"", result.Stdout);
        Assert.DoesNotContain("ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
    }

    /// <summary>
    /// Verifies that baseline creation honors native Scout ignore policy.
    /// </summary>
    [TestMethod]
    public async Task BaselineCreateHonorsScoutIgnorePolicy()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        Directory.CreateDirectory(Path.Combine(root.Path, ".git"));
        File.WriteAllText(Path.Combine(root.Path, ".gitignore"), "git-ignored.txt\ntoken-99991\n");
        File.WriteAllText(Path.Combine(root.Path, ".ignore"), "dot-ignored.txt\ntoken-99992\n");
        File.WriteAllText(Path.Combine(root.Path, ".hidden.txt"), "token-12345");
        File.WriteAllText(Path.Combine(root.Path, "git-ignored.txt"), "token-23456");
        File.WriteAllText(Path.Combine(root.Path, "dot-ignored.txt"), "token-34567");
        File.WriteAllText(Path.Combine(root.Path, "keep.txt"), "token-45678");

        CliResult result = await RunCliAsync("baseline", "create", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"File\": \"keep.txt\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-45678\"", result.Stdout);
        Assert.DoesNotContain(".hidden.txt", result.Stdout);
        Assert.DoesNotContain("git-ignored.txt", result.Stdout);
        Assert.DoesNotContain("dot-ignored.txt", result.Stdout);
        Assert.DoesNotContain("token-12345", result.Stdout);
        Assert.DoesNotContain("token-23456", result.Stdout);
        Assert.DoesNotContain("token-34567", result.Stdout);
        Assert.DoesNotContain("token-99991", result.Stdout);
        Assert.DoesNotContain("token-99992", result.Stdout);
    }

    /// <summary>
    /// Verifies that baseline help advertises the baseline create workflow.
    /// </summary>
    [TestMethod]
    public async Task BaselineHelpShowsCreateCommand()
    {
        CliResult result = await RunCliAsync("baseline", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket baseline [command] [options]", result.Stdout);
        Assert.Contains("create <path>", result.Stdout);
    }

    /// <summary>
    /// Verifies that view summarizes a native report without printing the secret value.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesNativeReportWithoutSecretValue()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.json");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: picket-json", view.Stdout);
        Assert.Contains("findings: 1", view.Stdout);
        Assert.Contains("files: 1", view.Stdout);
        Assert.Contains("token secret.txt:1 picket:v1:", view.Stdout);
        Assert.DoesNotContain("token-12345", view.Stdout);
    }

    /// <summary>
    /// Verifies that view summarizes a native HTML report without printing the secret value.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesNativeHtmlReportWithoutSecretValue()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.html");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: picket-html", view.Stdout);
        Assert.Contains("findings: 1", view.Stdout);
        Assert.Contains("files: 1", view.Stdout);
        Assert.Contains("token secret.txt:1 picket:v1:", view.Stdout);
        Assert.DoesNotContain("token-12345", view.Stdout);
    }

    /// <summary>
    /// Verifies that view preserves the generic HTML fallback for non-Picket reports.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesGenericHtmlReportWithUnknownCounts()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = Path.Combine(root.Path, "report.html");
        File.WriteAllText(reportPath, "<!doctype html><title>External report</title>");

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: html", view.Stdout);
        Assert.Contains("findings: unknown", view.Stdout);
        Assert.Contains("files: unknown", view.Stdout);
    }

    /// <summary>
    /// Verifies that view --open refuses to shell-open non-report file extensions.
    /// </summary>
    [TestMethod]
    public async Task ViewOpenRejectsUnsafeReportExtension()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string jsonReportPath = Path.Combine(root.Path, "report.json");
        string executableReportPath = Path.Combine(root.Path, "report.cmd");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");
        CliResult scan = await RunCliAsync("scan", root.Path, "-c", configPath, "-r", jsonReportPath).ConfigureAwait(false);
        File.Copy(jsonReportPath, executableReportPath);

        CliResult view = await RunCliAsync("view", executableReportPath, "--open").ConfigureAwait(false);

        Assert.AreEqual(1, scan.ExitCode);
        Assert.AreEqual(1, view.ExitCode);
        Assert.Contains("format: picket-json", view.Stdout);
        Assert.Contains("refusing to open report: unsupported report extension: .cmd", view.Stderr);
    }

    /// <summary>
    /// Verifies that view summarizes TruffleHog JSONL without printing secret fields.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesTruffleHogJsonlWithoutSecretValue()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = Path.Combine(root.Path, "trufflehog.jsonl");
        File.WriteAllText(
            reportPath,
            """
            {"SourceMetadata":{"Data":{"Git":{"commit":"abc","file":"keys.txt","line":4}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIASECRET","RawV2":"AKIASECRET:secret","Redacted":"AKIA********","ExtraData":{"account":"123"}}
            """);

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: trufflehog-jsonl", view.Stdout);
        Assert.Contains("findings: 1", view.Stdout);
        Assert.Contains("AWS keys.txt:4 trufflehog:AWS:keys.txt:4", view.Stdout);
        Assert.DoesNotContain("AKIASECRET", view.Stdout);
        Assert.DoesNotContain("AKIA********", view.Stdout);
    }

    /// <summary>
    /// Verifies that view help advertises every supported imported report format.
    /// </summary>
    [TestMethod]
    public async Task ViewHelpListsImportedReportFormats()
    {
        CliResult view = await RunCliAsync("view", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("Picket JSON/JSONL", view.Stdout);
        Assert.Contains("Gitleaks JSON", view.Stdout);
        Assert.Contains("TruffleHog JSON/JSONL", view.Stdout);
        Assert.Contains("GitLab code-quality JSON", view.Stdout);
        Assert.Contains("SARIF", view.Stdout);
        Assert.Contains("HTML", view.Stdout);
    }

    /// <summary>
    /// Verifies that view summarizes GitLab code-quality reports without printing ignored secret-like fields.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesGitLabCodeQualityReportWithoutSecretValue()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = Path.Combine(root.Path, "gl-code-quality-report.json");
        File.WriteAllText(
            reportPath,
            """
            [{"description":"secret token-12345","check_name":"gitlab-rule","fingerprint":"gitlab-fingerprint","severity":"critical","location":{"path":"src/secret.txt","lines":{"begin":7}}}]
            """);

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: gitlab-code-quality", view.Stdout);
        Assert.Contains("findings: 1", view.Stdout);
        Assert.Contains("gitlab-rule src/secret.txt:7 gitlab-fingerprint", view.Stdout);
        Assert.DoesNotContain("token-12345", view.Stdout);
    }

    /// <summary>
    /// Verifies that view summarizes SARIF reports without printing ignored secret-like properties.
    /// </summary>
    [TestMethod]
    public async Task ViewSummarizesSarifReportWithoutSecretValue()
    {
        using TempDirectory root = TempDirectory.Create();
        string reportPath = Path.Combine(root.Path, "report.sarif");
        File.WriteAllText(
            reportPath,
            """
            {"version":"2.1.0","runs":[{"results":[{"ruleId":"sarif-rule","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/secret.txt"},"region":{"startLine":9}}}],"partialFingerprints":{"picketFingerprint":"sarif-fingerprint"},"properties":{"secret":"token-12345"}}]}]}
            """);

        CliResult view = await RunCliAsync("view", reportPath).ConfigureAwait(false);

        Assert.AreEqual(0, view.ExitCode);
        Assert.Contains("format: sarif", view.Stdout);
        Assert.Contains("findings: 1", view.Stdout);
        Assert.Contains("sarif-rule src/secret.txt:9 sarif-fingerprint", view.Stdout);
        Assert.DoesNotContain("token-12345", view.Stdout);
    }

    /// <summary>
    /// Verifies that report paths ending in .sarif infer SARIF when -f is omitted.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanInfersSarifReportFormatFromPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.sarif");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"ruleId\": \"token\"", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that --report-template implies template output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesTemplateReport()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string templatePath = Path.Combine(root.Path, "report.tmpl");
        File.WriteAllText(
            templatePath,
            "{{ range . -}}{{ .RuleID }}|{{ .File }}|{{ quote .Secret }}|{{ .Line }}\n{{ end -}}");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "prefix token-12345 suffix");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--report-template", templatePath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.AreEqual("token|secret.txt|\"token-12345\"|prefix token-12345 suffix\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that template reports can be written to a report path.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesTemplateReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string templatePath = Path.Combine(root.Path, "report.tmpl");
        string reportPath = Path.Combine(root.Path, "report.txt");
        File.WriteAllText(templatePath, "findings={{ len . }}\n");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--report-template", templatePath, "-r", reportPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.AreEqual("findings=1\n", File.ReadAllText(reportPath));
    }

    /// <summary>
    /// Verifies that --report-template rejects contradictory explicit formats.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsTemplateWithNonTemplateFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string templatePath = Path.Combine(root.Path, "report.tmpl");
        File.WriteAllText(templatePath, "{{ len . }}\n");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--report-template", templatePath, "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("report format must be 'template' if --report-template is specified", result.Stderr);
    }

    /// <summary>
    /// Verifies that mixed singular and plural allowlist tables fail during CLI config loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsMixedAllowlistForms()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [allowlist]
            paths = ['''vendor/''']

            [[allowlists]]
            paths = ['''README\.md$''']

            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]", result.Stderr);
    }

    /// <summary>
    /// Verifies that invalid secretGroup values fail during CLI config loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsInvalidSecretGroup()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-([0-9]+)'''
            secretGroup = 2
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token: invalid regex secret group 2, max regex secret group 1", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules without regex or path fail during CLI config loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsRuleWithoutRegexOrPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            description = "Token rule"
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token: both |regex| and |path| are empty, this rule will have no effect", result.Stderr);
    }

    /// <summary>
    /// Verifies that invalid rule regex patterns fail during CLI config loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsInvalidRuleRegex()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-([0-9]+'''
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token: invalid regex pattern 'token-([0-9]+'", result.Stderr);
    }

    /// <summary>
    /// Verifies that invalid allowlist regex patterns fail during CLI config loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsInvalidAllowlistRegex()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''

            [[rules.allowlists]]
            regexes = ['''(''']
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("token: [[rules.allowlists]]: invalid allowlist regex pattern '('", result.Stderr);
    }

    /// <summary>
    /// Verifies that common Gitleaks global flags and equals-value spellings are accepted.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanAcceptsGitleaksGlobalFlagSpellings()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string ignoreRoot = Path.Combine(root.Path, "ignore");
        Directory.CreateDirectory(ignoreRoot);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync(
            "dir",
            root.Path,
            $"--config={configPath}",
            $"--gitleaks-ignore-path={ignoreRoot}",
            "--log-level=debug",
            "-v",
            "--no-color",
            "--no-banner",
            "--timeout=1",
            "--max-target-megabytes=0").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that directory scans skip files that look binary.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanSkipsBinaryFiles()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        byte[] secretBytes = Encoding.UTF8.GetBytes("token-12345");
        byte[] binaryBytes = new byte[secretBytes.Length + 1];
        secretBytes.CopyTo(binaryBytes, 1);
        File.WriteAllBytes(Path.Combine(root.Path, "secret.bin"), binaryBytes);

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that directory scans report symlink metadata when symlink following is enabled.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanReportsSymlinkFileWhenFollowingSymlinks()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string hiddenPath = Path.Combine(root.Path, ".hidden");
        Directory.CreateDirectory(hiddenPath);
        string targetPath = Path.Combine(hiddenPath, "target.txt");
        string linkPath = Path.Combine(root.Path, "link.txt");
        File.WriteAllText(targetPath, "token-12345");
        File.CreateSymbolicLink(linkPath, targetPath);

        CliResult disabled = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult enabled = await RunCliAsync("dir", root.Path, "-c", configPath, "--follow-symlinks").ConfigureAwait(false);

        Assert.AreEqual(1, disabled.ExitCode);
        Assert.DoesNotContain("\"SymlinkFile\": \"link.txt\"", disabled.Stdout);
        Assert.AreEqual(1, enabled.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", enabled.Stdout);
        Assert.Contains("\"SymlinkFile\": \"link.txt\"", enabled.Stdout);
    }

    /// <summary>
    /// Verifies that --max-decode-depth controls recursive decoded scanning.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanHonorsMaxDecodeDepth()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "encoded=dG9rZW4tMTIzNDU=");

        CliResult decoded = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult disabled = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-decode-depth=0").ConfigureAwait(false);

        Assert.AreEqual(1, decoded.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", decoded.Stdout);
        Assert.Contains("\"decoded:base64\"", decoded.Stdout);
        Assert.AreEqual(0, disabled.ExitCode);
        Assert.AreEqual("[]\n", disabled.Stdout);
    }

    /// <summary>
    /// Verifies that directory scans include Unicode decoded findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanFindsUnicodeDecodedSecret()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(
            Path.Combine(root.Path, "secret.txt"),
            "encoded=\\u0074\\u006f\\u006b\\u0065\\u006e\\u002d\\u0031\\u0032\\u0033\\u0034\\u0035");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
        Assert.Contains("\"decoded:unicode\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that directory scans find secrets inside zip archives when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanFindsZipArchiveSecretWhenArchiveDepthEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        WriteZipFile(Path.Combine(root.Path, "secrets.zip"), ("nested/secret.txt", "token-12345"));

        CliResult disabled = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult enabled = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-archive-depth=1").ConfigureAwait(false);

        Assert.AreEqual(0, disabled.ExitCode);
        Assert.AreEqual("[]\n", disabled.Stdout);
        Assert.AreEqual(1, enabled.ExitCode);
        Assert.Contains("\"File\": \"secrets.zip!nested/secret.txt\"", enabled.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", enabled.Stdout);
    }

    /// <summary>
    /// Verifies that directory archive extraction honors anchored global allowlist paths against inner entry names.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanArchiveHonorsInnerPathGlobalAllowlist()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteArchiveInnerAllowlistConfig(root.Path);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("ignored.txt", "token-11111"),
            ("kept.txt", "token-22222"));

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--max-archive-depth=1").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.DoesNotContain("\"Secret\": \"token-11111\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-22222\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git scans find secrets inside zip archives when archive traversal is enabled.
    /// </summary>
    [TestMethod]
    public async Task GitScanFindsZipArchiveSecretWhenArchiveDepthEnabled()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(Path.Combine(root.Path, "secrets.zip"), ("nested/secret.txt", "token-12345"));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        CliResult disabled = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult enabled = await RunCliAsync("git", root.Path, "-c", configPath, "--max-archive-depth=1", "--timeout=1").ConfigureAwait(false);

        Assert.AreEqual(0, disabled.ExitCode);
        Assert.AreEqual("[]\n", disabled.Stdout);
        Assert.AreEqual(1, enabled.ExitCode);
        Assert.Contains("\"File\": \"secrets.zip!nested/secret.txt\"", enabled.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", enabled.Stdout);
        Assert.Contains($"\"Commit\": \"{commit}\"", enabled.Stdout);
        Assert.Contains($"\"Fingerprint\": \"{commit}:secrets.zip!nested/secret.txt:token:1\"", enabled.Stdout);
    }

    /// <summary>
    /// Verifies that git archive extraction honors anchored global allowlist paths against inner entry names.
    /// </summary>
    [TestMethod]
    public async Task GitScanArchiveHonorsInnerPathGlobalAllowlist()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteArchiveInnerAllowlistConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        WriteZipFile(
            Path.Combine(root.Path, "secrets.zip"),
            ("ignored.txt", "token-11111"),
            ("kept.txt", "token-22222"));
        await RunGitCommandAsync(root.Path, "add", "secrets.zip").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add archive").ConfigureAwait(false);

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath, "--max-archive-depth=1").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.DoesNotContain("\"Secret\": \"token-11111\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-22222\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that diagnostics modes write scan artifacts without changing scan output.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanWritesDiagnosticsArtifacts()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string diagnosticsDir = Path.Combine(root.Path, "diagnostics");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync(
            "dir",
            root.Path,
            "-c",
            configPath,
            "--diagnostics",
            "cpu,mem,trace",
            "--diagnostics-dir",
            diagnosticsDir).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
        string cpu = File.ReadAllText(Path.Combine(diagnosticsDir, "cpu.json"));
        string memory = File.ReadAllText(Path.Combine(diagnosticsDir, "mem.json"));
        string trace = File.ReadAllText(Path.Combine(diagnosticsDir, "trace.jsonl"));
        Assert.Contains("\"diagnostic\": \"cpu\"", cpu);
        Assert.Contains("\"command\": \"dir\"", cpu);
        Assert.Contains("\"exitCode\": 1", cpu);
        Assert.Contains("\"scanInputs\": 1", cpu);
        Assert.Contains("\"findings\": 1", cpu);
        Assert.Contains("\"cacheHits\": 0", cpu);
        Assert.Contains("\"diagnostic\": \"mem\"", memory);
        Assert.Contains("\"allocatedBytes\"", memory);
        Assert.Contains("\"cacheMisses\": 0", memory);
        Assert.Contains("\"event\":\"scan.start\"", trace);
        Assert.Contains("\"event\":\"scan.stop\"", trace);
        Assert.Contains("\"scanInputs\":1", trace);
    }

    /// <summary>
    /// Verifies that HTTP diagnostics start a loopback endpoint while stdin scans are waiting for input.
    /// </summary>
    [TestMethod]
    public async Task StdinScanServesHttpDiagnostics()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = root.Path,
        };
        process.StartInfo.ArgumentList.Add("stdin");
        process.StartInfo.ArgumentList.Add("-c");
        process.StartInfo.ArgumentList.Add(configPath);
        process.StartInfo.ArgumentList.Add("--diagnostics=http");

        process.Start();
        string firstErrorLine = await process.StandardError.ReadLineAsync(TestContext.CancellationToken).ConfigureAwait(false) ?? string.Empty;
        const string DiagnosticsStartedPrefix = "diagnostics server started at ";
        Assert.StartsWith(DiagnosticsStartedPrefix, firstErrorLine);
        var diagnosticsUri = new Uri(firstErrorLine[DiagnosticsStartedPrefix.Length..]);
        var profileUriBuilder = new UriBuilder(diagnosticsUri)
        {
            Path = "/debug/pprof/profile",
        };

        using var client = new HttpClient();
        using HttpResponseMessage unauthorized = await client.GetAsync(
            new Uri($"{diagnosticsUri.GetLeftPart(UriPartial.Path)}"),
            TestContext.CancellationToken).ConfigureAwait(false);
        string index = await client.GetStringAsync(diagnosticsUri, TestContext.CancellationToken).ConfigureAwait(false);
        string cpu = await client.GetStringAsync(profileUriBuilder.Uri, TestContext.CancellationToken).ConfigureAwait(false);

        await process.StandardInput.WriteAsync("token-12345".AsMemory(), TestContext.CancellationToken).ConfigureAwait(false);
        await process.StandardInput.FlushAsync(TestContext.CancellationToken).ConfigureAwait(false);
        process.StandardInput.Close();

        string stdout = await process.StandardOutput.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string stderr = firstErrorLine + '\n' + await process.StandardError.ReadToEndAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, process.ExitCode);
        Assert.AreEqual(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        Assert.Contains("\"diagnostic\": \"http\"", index);
        Assert.Contains("\"endpoints\"", index);
        Assert.Contains("\"diagnostic\": \"cpu\"", cpu);
        Assert.Contains("\"Secret\": \"token-12345\"", stdout);
        Assert.DoesNotContain("not supported yet", stderr);
    }

    /// <summary>
    /// Verifies that HTTP diagnostics reject diagnostics-dir like Gitleaks.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsHttpDiagnosticsDirectory()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--diagnostics=http", "--diagnostics-dir", root.Path).ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("the diagnostics directory should not be set in http mode", result.Stderr);
    }

    /// <summary>
    /// Verifies that HTTP diagnostics cannot be combined with file diagnostics.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsMixedHttpDiagnostics()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--diagnostics=http,cpu").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("other diagnostics modes should not be enabled when http mode is enabled", result.Stderr);
    }

    /// <summary>
    /// Verifies that inline gitleaks:allow comments suppress CLI findings by default.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanSuppressesInlineGitleaksAllowByDefault()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345 // gitleaks:allow");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that --ignore-gitleaks-allow reports otherwise suppressed CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanReportsInlineGitleaksAllowWhenIgnored()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345 // gitleaks:allow");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--ignore-gitleaks-allow").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that skipReport rules suppress normal CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanSuppressesSkipReportRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "supporting-rule"
            regex = '''token-[0-9]+'''
            skipReport = true
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that no-config directory scans use the embedded Gitleaks default ruleset.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanUsesEmbeddedGitleaksDefaultConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "picket_key = abc123def456ghi7890");

        CliResult result = await RunCliAsync("dir", root.Path).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"generic-api-key\"", result.Stdout);
        Assert.Contains("\"Secret\": \"abc123def456ghi7890\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that --enable-rule limits directory scans to requested rule IDs.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanEnableRuleFiltersConfiguredRules()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTwoRuleConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "alpha-12345\nbeta-12345\n");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--enable-rule", "alpha-token").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"alpha-token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"alpha-12345\"", result.Stdout);
        Assert.DoesNotContain("\"RuleID\": \"beta-token\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that comma-separated --enable-rule values select multiple rules like Gitleaks string slices.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanEnableRuleAcceptsCommaSeparatedValues()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTwoRuleConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "alpha-12345\nbeta-12345\n");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--enable-rule=alpha-token,beta-token").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"alpha-token\"", result.Stdout);
        Assert.Contains("\"RuleID\": \"beta-token\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that --enable-rule rejects missing rule IDs during rule loading.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanEnableRuleRejectsMissingRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--enable-rule", "missing-token").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("Requested rule missing-token not found in rules", result.Stderr);
    }

    /// <summary>
    /// Verifies that --enable-rule applies to stdin scans.
    /// </summary>
    [TestMethod]
    public async Task StdinScanEnableRuleFiltersConfiguredRules()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTwoRuleConfig(root.Path);

        CliResult result = await RunCliWithInputAsync("alpha-12345\nbeta-12345\n", "stdin", "-c", configPath, "--enable-rule", "beta-token").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.DoesNotContain("\"RuleID\": \"alpha-token\"", result.Stdout);
        Assert.Contains("\"RuleID\": \"beta-token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"beta-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that --profile picket opts stdin scans into native config and report behavior.
    /// </summary>
    [TestMethod]
    public async Task StdinProfilePicketUsesNativeConfigAndReports()
    {
        using TempDirectory root = TempDirectory.Create();
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-stdin-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            "native-only-secret",
            environment,
            "stdin",
            "--profile",
            "picket",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"native-stdin-rule\"", result.Stdout);
        Assert.Contains("\"validationState\":\"unknown\"", result.Stdout);
        Assert.DoesNotContain("\"RuleID\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that strict compatibility stdin scans ignore PICKET_CONFIG_TOML.
    /// </summary>
    [TestMethod]
    public async Task StdinScanIgnoresPicketConfigTomlEnvironmentVariable()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, ".gitleaks.toml"), CreateRuleConfig("compat-rule", "compat-only-secret"));
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            "native-only-secret",
            environment,
            "stdin").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
        Assert.DoesNotContain("native-rule", result.Stdout);
    }

    /// <summary>
    /// Verifies that unsupported stdin profiles are rejected before scanning.
    /// </summary>
    [TestMethod]
    public async Task StdinScanRejectsUnsupportedProfile()
    {
        CliResult result = await RunCliWithInputAsync("token-12345", "stdin", "--profile", "strict").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported profile: strict", result.Stderr);
    }

    /// <summary>
    /// Verifies that stdin scans discover .gitleaks.toml from the current directory.
    /// </summary>
    [TestMethod]
    public async Task StdinScanUsesCurrentDirectoryConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, "token-12345", "stdin").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that stdin scans honor .gitleaksignore fingerprints.
    /// </summary>
    [TestMethod]
    public async Task StdinScanHonorsGitleaksIgnoreFingerprint()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, ".gitleaksignore"), ":token:1\n");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, "token-12345", "stdin", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that stdin scans accept the Gitleaks-compatible timeout flag.
    /// </summary>
    [TestMethod]
    public async Task StdinScanAcceptsTimeoutFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithInputAsync("token-12345", "stdin", "-c", configPath, "--timeout=1").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that stdin scans accept the Gitleaks-compatible archive depth flag.
    /// </summary>
    [TestMethod]
    public async Task StdinScanAcceptsMaxArchiveDepthFlag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithInputAsync("token-12345", "stdin", "-c", configPath, "--max-archive-depth=1").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Secret\": \"token-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that stdin scans honor the Gitleaks-compatible max-target flag.
    /// </summary>
    [TestMethod]
    public async Task StdinScanHonorsMaxTargetMegabytes()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string input = new string('x', 2_000_001) + "token-12345";

        CliResult result = await RunCliWithInputAsync(input, "stdin", "-c", configPath, "--max-target-megabytes=1").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that required supporting rules gate normal CLI findings.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanReportsCompositeRuleWhenRequiredRuleMatches()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "primary-rule"
            regex = '''password="([^"]+)"'''

            [[rules.required]]
            id = "username-rule"

            [[rules]]
            id = "username-rule"
            regex = '''username="([^"]+)"'''
            skipReport = true
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "username=\"alice\"\npassword=\"secret\"");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"primary-rule\"", result.Stdout);
        Assert.Contains("\"Secret\": \"secret\"", result.Stdout);
        Assert.DoesNotContain("\"RuleID\": \"username-rule\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that directory scans honor rules inherited through Gitleaks extend.path configs.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanUsesExtendedConfigRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string baseConfigPath = Path.Combine(root.Path, "base.toml");
        string childConfigPath = Path.Combine(root.Path, "child.toml");
        File.WriteAllText(baseConfigPath, CreateRuleConfig("base-token", "base-[0-9]+"));
        File.WriteAllText(
            childConfigPath,
            $$"""
            [extend]
            path = {{CreateTomlLiteral(baseConfigPath)}}
            """);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "base-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", childConfigPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"base-token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"base-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git history scans report committed secrets with commit metadata and fingerprints.
    /// </summary>
    [TestMethod]
    public async Task GitScanReportsCommittedSecret()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.Contains($"\"Commit\": \"{commit}\"", result.Stdout);
        Assert.Contains("\"File\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"Author\": \"Picket Test\"", result.Stdout);
        Assert.Contains("\"Email\": \"picket@example.com\"", result.Stdout);
        Assert.Contains("\"Message\": \"add secret\"", result.Stdout);
        Assert.Contains($"\"Fingerprint\": \"{commit}:secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that --profile picket opts git scans into native config and report behavior.
    /// </summary>
    [TestMethod]
    public async Task GitProfilePicketUsesNativeConfigAndReports()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "native-only-secret\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add native secret").ConfigureAwait(false);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-git-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            environment,
            "git",
            root.Path,
            "--profile",
            "picket",
            "-f",
            "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"native-git-rule\"", result.Stdout);
        Assert.Contains("\"validationState\":\"unknown\"", result.Stdout);
        Assert.DoesNotContain("\"RuleID\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that strict compatibility git scans ignore PICKET_CONFIG_TOML.
    /// </summary>
    [TestMethod]
    public async Task GitScanIgnoresPicketConfigTomlEnvironmentVariable()
    {
        using TempDirectory root = TempDirectory.Create();
        File.WriteAllText(Path.Combine(root.Path, ".gitleaks.toml"), CreateRuleConfig("compat-rule", "compat-only-secret"));
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "native-only-secret\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add native secret").ConfigureAwait(false);
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            environment,
            "git",
            root.Path).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
        Assert.DoesNotContain("native-rule", result.Stdout);
    }

    /// <summary>
    /// Verifies that unsupported git profiles are rejected before scanning.
    /// </summary>
    [TestMethod]
    public async Task GitScanRejectsUnsupportedProfile()
    {
        CliResult result = await RunCliAsync("git", "--profile", "strict").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported profile: strict", result.Stderr);
    }

    /// <summary>
    /// Verifies that max-target filtering does not suppress path-only git findings.
    /// </summary>
    [TestMethod]
    public async Task GitScanKeepsPathOnlyRuleWhenMaxTargetMegabytesIsExceeded()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WritePathOnlyConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), new string('x', 2_000_001));
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add oversized path secret").ConfigureAwait(false);

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath, "--max-target-megabytes=1").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"RuleID\": \"path-secret\"", result.Stdout);
        Assert.Contains("\"Match\": \"file detected: secret.txt\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git history scans include Gitleaks-compatible source-control links.
    /// </summary>
    [TestMethod]
    public async Task GitScanReportsSourceControlLinks()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "remote", "add", "origin", "git@github.com:gitleaks/test.git").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();
        string expectedLink = $"https://github.com/gitleaks/test/blob/{commit}/secret.txt#L1";

        CliResult json = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult csv = await RunCliAsync("git", root.Path, "-c", configPath, "--platform", "github", "-f", "csv").ConfigureAwait(false);

        Assert.AreEqual(1, json.ExitCode);
        Assert.Contains($"\"Link\": \"{expectedLink}\"", json.Stdout);
        Assert.AreEqual(1, csv.ExitCode);
        Assert.Contains("RuleID,Commit,File,SymlinkFile,Secret,Match,StartLine,EndLine,StartColumn,EndColumn,Author,Message,Date,Email,Fingerprint,Tags,Link\n", csv.Stdout);
        Assert.Contains(expectedLink, csv.Stdout);
    }

    /// <summary>
    /// Verifies that --enable-rule limits git history scans to requested rule IDs.
    /// </summary>
    [TestMethod]
    public async Task GitScanEnableRuleFiltersConfiguredRules()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTwoRuleConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "alpha-12345\nbeta-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secrets").ConfigureAwait(false);

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath, "--enable-rule", "beta-token").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.DoesNotContain("\"RuleID\": \"alpha-token\"", result.Stdout);
        Assert.Contains("\"RuleID\": \"beta-token\"", result.Stdout);
        Assert.Contains("\"Secret\": \"beta-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that git scans honor Gitleaks-compatible global fingerprint ignore entries.
    /// </summary>
    [TestMethod]
    public async Task GitScanHonorsGlobalGitleaksIgnoreFingerprint()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, ".gitleaksignore"), "secret.txt:token:1\n");

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual("[]\n", result.Stdout);
    }

    /// <summary>
    /// Verifies that staged git scans report index additions without commit metadata.
    /// </summary>
    [TestMethod]
    public async Task GitScanReportsStagedSecret()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);

        CliResult result = await RunCliAsync("git", root.Path, "-c", configPath, "--staged").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"File\": \"secret.txt\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect shim maps to a git history scan by default.
    /// </summary>
    [TestMethod]
    public async Task DetectShimMapsDefaultToGitScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);
        string commit = (await RunGitCommandAsync(root.Path, "rev-parse", "HEAD").ConfigureAwait(false)).Trim();

        CliResult result = await RunCliAsync("detect", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains($"\"Commit\": \"{commit}\"", result.Stdout);
        Assert.Contains($"\"Fingerprint\": \"{commit}:secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect --no-git shim maps to a directory scan.
    /// </summary>
    [TestMethod]
    public async Task DetectShimNoGitMapsToDirectoryScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");

        CliResult result = await RunCliAsync("detect", "--no-git", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated detect --pipe shim maps to stdin scanning.
    /// </summary>
    [TestMethod]
    public async Task DetectShimPipeMapsToStdinScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliWithInputAsync("token-12345", "detect", "--pipe", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"File\": \"\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \":token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the deprecated protect shim maps to a pre-commit git diff scan.
    /// </summary>
    [TestMethod]
    public async Task ProtectShimMapsToPreCommitScan()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "clean\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "seed").ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");

        CliResult result = await RunCliAsync("protect", "--source", root.Path, "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"Commit\": \"\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"secret.txt:token:1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that the native hook installer writes a managed pre-commit hook that uses the existing protect workflow.
    /// </summary>
    [TestMethod]
    public async Task HooksInstallWritesManagedPreCommitHook()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);

        CliResult result = await RunCliAsync(
            "hooks",
            "install",
            "pre-commit",
            "--repo",
            root.Path,
            "--config",
            configPath,
            "--command",
            "picket-dev").ConfigureAwait(false);
        string hookPath = Path.Combine(root.Path, ".git", "hooks", "pre-commit");
        string hook = File.ReadAllText(hookPath);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("installed pre-commit:", result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.Contains("#!/bin/sh\n", hook);
        Assert.Contains("# managed by picket hooks install", hook);
        Assert.Contains("'picket-dev' protect --source \"$repo_root\"", hook);
        Assert.Contains("--config", hook);
        Assert.Contains(configPath, hook);
        Assert.Contains("'--redact=100'", hook);
    }

    /// <summary>
    /// Verifies that all hook installation covers pre-push and pre-receive range scans.
    /// </summary>
    [TestMethod]
    public async Task HooksInstallWritesPushAndReceiveHooks()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);

        CliResult result = await RunCliAsync("hooks", "install", "all", "--repo", root.Path).ConfigureAwait(false);
        string prePush = File.ReadAllText(Path.Combine(root.Path, ".git", "hooks", "pre-push"));
        string preReceive = File.ReadAllText(Path.Combine(root.Path, ".git", "hooks", "pre-receive"));

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("installed pre-commit:", result.Stdout);
        Assert.Contains("installed pre-push:", result.Stdout);
        Assert.Contains("installed pre-receive:", result.Stdout);
        Assert.Contains("while read local_ref local_sha remote_ref remote_sha", prePush);
        Assert.Contains("remote_sha..$local_sha", prePush);
        Assert.Contains("git \"$repo_root\" --log-opts \"$range\"", prePush);
        Assert.Contains("while read old_sha new_sha ref_name", preReceive);
        Assert.Contains("old_sha..$new_sha", preReceive);
        Assert.Contains("git \"$repo_root\" --log-opts \"$range\"", preReceive);
    }

    /// <summary>
    /// Verifies that hook installation does not overwrite unmanaged hooks unless forced.
    /// </summary>
    [TestMethod]
    public async Task HooksInstallRefusesUnmanagedHookWithoutForce()
    {
        using TempDirectory root = TempDirectory.Create();
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        string hookPath = Path.Combine(root.Path, ".git", "hooks", "pre-commit");
        File.WriteAllText(hookPath, "custom hook\n");

        CliResult refused = await RunCliAsync("hooks", "install", "pre-commit", "--repo", root.Path).ConfigureAwait(false);
        CliResult forced = await RunCliAsync("hooks", "install", "pre-commit", "--repo", root.Path, "--force").ConfigureAwait(false);
        string hook = File.ReadAllText(hookPath);

        Assert.AreEqual(1, refused.ExitCode);
        Assert.Contains("use --force to overwrite it", refused.Stderr);
        Assert.AreEqual(0, forced.ExitCode);
        Assert.Contains("# managed by picket hooks install", hook);
    }

    /// <summary>
    /// Verifies that hooks help advertises the installation workflow.
    /// </summary>
    [TestMethod]
    public async Task HooksHelpAdvertisesInstall()
    {
        CliResult result = await RunCliAsync("hooks", "--help").ConfigureAwait(false);
        CliResult install = await RunCliAsync("hooks", "install", "--help").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("picket hooks [command] [options]", result.Stdout);
        Assert.Contains("install <pre-commit|pre-push|pre-receive|all>", result.Stdout);
        Assert.AreEqual(0, install.ExitCode);
        Assert.Contains("picket hooks install", install.Stdout);
        Assert.Contains("pre-commit|pre-push|pre-receive|all", result.Stdout);
        Assert.Contains("Installs pre-commit when no hook name is provided", install.Stdout);
    }

    /// <summary>
    /// Verifies that the Gitleaks-compatible git platform set is accepted and native auto is rejected.
    /// </summary>
    [TestMethod]
    public async Task GitScanValidatesCompatiblePlatformValues()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        await InitializeGitRepositoryAsync(root.Path).ConfigureAwait(false);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345\n");
        await RunGitCommandAsync(root.Path, "add", "secret.txt").ConfigureAwait(false);
        await RunGitCommandAsync(root.Path, "commit", "-m", "add secret").ConfigureAwait(false);

        CliResult accepted = await RunCliAsync("git", root.Path, "-c", configPath, "--platform", "github").ConfigureAwait(false);
        CliResult rejected = await RunCliAsync("git", root.Path, "-c", configPath, "--platform", "auto").ConfigureAwait(false);

        Assert.AreEqual(1, accepted.ExitCode);
        Assert.AreEqual(126, rejected.ExitCode);
        Assert.Contains("invalid scm platform value: auto", rejected.Stderr);
    }

    /// <summary>
    /// Verifies that rules check accepts a valid Gitleaks-compatible config.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckAcceptsValidConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("rules ok: 1 rule", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects invalid Gitleaks-compatible configs.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsInvalidConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-([0-9]+'''
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("token: invalid regex pattern 'token-([0-9]+'", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects duplicate rule IDs before scanning.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsDuplicateRuleIds()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''alpha-[0-9]+'''

            [[rules]]
            id = "token"
            regex = '''beta-[0-9]+'''
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("duplicate rule ID: token", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check discovers a source-local Gitleaks-compatible config.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckDiscoversSourceConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteTokenConfig(root.Path, ".gitleaks.toml");

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "rules", "check").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("rules ok: 1 rule", result.Stdout);
    }

    /// <summary>
    /// Verifies that rules check uses Picket-native environment precedence by default.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckUsesPicketConfigTomlEnvironmentVariable()
    {
        using TempDirectory root = TempDirectory.Create();
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            environment,
            "rules",
            "check").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("rules ok: 1 rule", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check can print the Picket-native profile with layered rule packs.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckProfilePicketPrintsLayeredRulePacks()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult printed = await RunCliWithInputFromDirectoryAsync(
            root.Path,
            null,
            "rules",
            "check",
            "--profile",
            "picket",
            "--print-config").ConfigureAwait(false);

        Assert.AreEqual(0, printed.ExitCode, printed.Stderr);
        Assert.Contains("id = \"aws-access-token\"", printed.Stdout);
        Assert.Contains("id = \"picket-azure-storage-connection-string\"", printed.Stdout);
        Assert.Contains("rulePack = \"picket-default\"", printed.Stdout);
        Assert.Contains("provider = \"Azure\"", printed.Stdout);
        Assert.Contains("examples = [", printed.Stdout);
        Assert.Contains("negativeExamples = [", printed.Stdout);
    }

    /// <summary>
    /// Verifies that unsupported rules check profiles are rejected before validation.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsUnsupportedProfile()
    {
        using TempDirectory root = TempDirectory.Create();

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "rules", "check", "--profile", "strict").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("unsupported profile: strict", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check can print a resolved config that can be loaded again.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckPrintConfigWritesRoundTrippableResolvedConfig()
    {
        using TempDirectory root = TempDirectory.Create();
        string baseConfigPath = Path.Combine(root.Path, "base.toml");
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(baseConfigPath, CreateRuleConfig("base-token", "base-[0-9]+"));
        File.WriteAllText(
            configPath,
            $$"""
            [extend]
            path = '{{baseConfigPath}}'

            [[rules]]
            id = "picket-github-personal-access-token"
            regex = '''\b(ghp_[0-9A-Za-z]{36})\b'''
            secretGroup = 1
            keywords = ["ghp_"]
            severity = "high"
            confidence = "medium"
            rulePack = "picket-default"
            provider = "GitHub"
            documentationUrl = "https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
            validation = ["offline:github-classic-token", "live:github-rest-user-v1"]
            revocation = ["revocation:github-credentials-api"]
            deprecated = true
            examples = ["ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
            negativeExamples = ["ghp_invalid"]
            """);

        CliResult printed = await RunCliAsync("rules", "check", "-c", configPath, "--print-config").ConfigureAwait(false);
        string resolvedConfigPath = Path.Combine(root.Path, "resolved.toml");
        File.WriteAllText(resolvedConfigPath, printed.Stdout);
        CliResult checkedAgain = await RunCliAsync("rules", "check", "-c", resolvedConfigPath).ConfigureAwait(false);

        Assert.AreEqual(0, printed.ExitCode, printed.Stderr);
        Assert.DoesNotContain("rules ok", printed.Stdout);
        Assert.Contains("[[rules]]", printed.Stdout);
        Assert.Contains("id = \"base-token\"", printed.Stdout);
        Assert.Contains("id = \"picket-github-personal-access-token\"", printed.Stdout);
        Assert.Contains("severity = \"high\"", printed.Stdout);
        Assert.Contains("confidence = \"medium\"", printed.Stdout);
        Assert.Contains("rulePack = \"picket-default\"", printed.Stdout);
        Assert.Contains("provider = \"GitHub\"", printed.Stdout);
        Assert.Contains("documentationUrl = \"https://docs.github.com/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens\"", printed.Stdout);
        Assert.Contains("validation = [\"offline:github-classic-token\", \"live:github-rest-user-v1\"]", printed.Stdout);
        Assert.Contains("revocation = [\"revocation:github-credentials-api\"]", printed.Stdout);
        Assert.Contains("deprecated = true", printed.Stdout);
        Assert.Contains("examples = [\"ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\"]", printed.Stdout);
        Assert.Contains("negativeExamples = [\"ghp_invalid\"]", printed.Stdout);
        Assert.AreEqual(0, checkedAgain.ExitCode, checkedAgain.Stderr);
        Assert.Contains("rules ok: 2 rules", checkedAgain.Stdout);
    }

    /// <summary>
    /// Verifies that rules check rejects validation templates that cannot be honored by the current verifier.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsUnsupportedValidationTemplate()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''
            validation = ["offline:missing-validator"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("rule custom-token: unsupported validation template: offline:missing-validator", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects revocation templates that cannot be emitted by the current analyzer.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsUnsupportedRevocationTemplate()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "custom-token"
            regex = '''token-[0-9]+'''
            revocation = ["revocation:missing-provider"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("rule custom-token: unsupported revocation template: revocation:missing-provider", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check accepts rule examples that match and negative examples that do not.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckValidatesRuleExamples()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            examples = ["token-12345"]
            negativeExamples = ["token-value"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("rules ok: 1 rule", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects positive examples that do not produce findings.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsUnmatchedRuleExample()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            examples = ["token-value"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule token: example 1 did not produce a finding", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects negative examples that produce findings.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsMatchedNegativeRuleExample()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            negativeExamples = ["token-12345"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule token: negative example 1 produced a finding", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check requires positive examples for Picket-native rules.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsNativeRuleWithoutPositiveExample()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "picket-custom-token"
            regex = '''picket-[0-9]+'''
            keywords = ["picket"]
            rulePack = "picket-default"
            negativeExamples = ["picket-token"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule picket-custom-token: native rules require at least one positive example", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check requires negative examples for Picket-native rules.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsNativeRuleWithoutNegativeExample()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "custom-token"
            regex = '''picket-[0-9]+'''
            keywords = ["picket"]
            rulePack = "picket-default"
            examples = ["picket-12345"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule custom-token: native rules require at least one negative example", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check requires keyword prefilters for Picket-native content rules.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsNativeContentRuleWithoutKeywordPrefilter()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "picket-custom-token"
            regex = '''picket-[0-9]+'''
            rulePack = "picket-default"
            examples = ["picket-12345"]
            negativeExamples = ["picket-token"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("rule picket-custom-token: native content rules require at least one keyword prefilter", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects obvious unbounded wildcard spans in Picket-native content rules.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsNativeContentRuleWithUnboundedWildcard()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "picket-custom-token"
            regex = '''picket-.*'''
            keywords = ["picket"]
            rulePack = "picket-default"
            examples = ["picket-12345"]
            negativeExamples = ["token"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("rule picket-custom-token: regex contains an unbounded wildcard span", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects empty keyword entries during rule QA.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsEmptyKeyword()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            keywords = [""]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule token: keyword entries must not be empty", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects duplicate tag entries during rule QA.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsDuplicateTag()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            tags = ["credential", "credential"]
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule token: duplicate tag: credential", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects self-referential required rules during rule QA.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsSelfReferentialRequiredRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''

              [[rules.required]]
              id = "token"
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("rule token: required rule must not reference itself", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules check rejects required rules whose target rule does not exist.
    /// </summary>
    [TestMethod]
    public async Task RulesCheckRejectsMissingRequiredRuleTarget()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''

              [[rules.required]]
              id = "missing"
            """);

        CliResult result = await RunCliAsync("rules", "check", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("[[rules.required]] rule ID 'missing' does not exist", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules test scans sample text with a selected rule.
    /// </summary>
    [TestMethod]
    public async Task RulesTestWritesMatchingFindings()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync(
            "rules",
            "test",
            "token",
            "token-12345",
            "-c",
            configPath,
            "--path",
            "sample.txt").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.report.v1\"", result.Stdout);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"token\"", result.Stdout);
        Assert.Contains("\"file\":\"sample.txt\"", result.Stdout);
        Assert.Contains("\"fingerprint\":\"picket:v1:", result.Stdout);
        Assert.DoesNotContain("\"RuleID\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that rules test writes native JSONL reports on request.
    /// </summary>
    [TestMethod]
    public async Task RulesTestWritesJsonlReportFormat()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("rules", "test", "token", "token-12345", "-c", configPath, "-f", "jsonl").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(0, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", lines[0]);
        Assert.Contains("\"ruleId\":\"token\"", lines[0]);
        Assert.IsEmpty(result.Stderr);
    }

    /// <summary>
    /// Verifies that rules test can infer a native report format from a report path.
    /// </summary>
    [TestMethod]
    public async Task RulesTestWritesReportPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string reportPath = Path.Combine(root.Path, "report.jsonl");

        CliResult result = await RunCliAsync("rules", "test", "token", "token-12345", "-c", configPath, "-r", reportPath).ConfigureAwait(false);
        string report = File.ReadAllText(reportPath);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", report);
        Assert.Contains("\"ruleId\":\"token\"", report);
    }

    /// <summary>
    /// Verifies that rules test uses Picket-native config environment variables by default.
    /// </summary>
    [TestMethod]
    public async Task RulesTestUsesPicketConfigTomlEnvironmentVariable()
    {
        var environment = new Dictionary<string, string?>
        {
            ["PICKET_CONFIG_TOML"] = CreateRuleConfig("native-rule", "native-only-secret"),
        };

        CliResult result = await RunCliWithEnvironmentAsync(environment, "rules", "test", "native-rule", "native-only-secret", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"ruleId\":\"native-rule\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that rules test accepts dash-prefixed sample text after the option delimiter.
    /// </summary>
    [TestMethod]
    public async Task RulesTestAcceptsDashPrefixedInputAfterDelimiter()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = Path.Combine(root.Path, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "dash-secret"
            regex = '''---secret-[0-9]+'''
            """);

        CliResult result = await RunCliAsync("rules", "test", "dash-secret", "-c", configPath, "-f", "jsonl", "--", "---secret-12345").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"ruleId\":\"dash-secret\"", result.Stdout);
        Assert.Contains("\"secret\":\"---secret-12345\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that rules test can print the resolved selected rule config.
    /// </summary>
    [TestMethod]
    public async Task RulesTestPrintConfigWritesSelectedRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("rules", "test", "token", "token-12345", "-c", configPath, "--print-config").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("[[rules]]", result.Stdout);
        Assert.Contains("id = \"token\"", result.Stdout);
        Assert.DoesNotContain("\"schema\":\"picket.report.v1\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that rules test rejects missing selected rules.
    /// </summary>
    [TestMethod]
    public async Task RulesTestRejectsMissingRule()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);

        CliResult result = await RunCliAsync("rules", "test", "missing", "token-12345", "-c", configPath).ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Requested rule missing not found in rules", result.Stderr);
    }

    /// <summary>
    /// Verifies that rules test can exercise path-only rules with a logical path.
    /// </summary>
    [TestMethod]
    public async Task RulesTestHonorsLogicalPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WritePathOnlyConfig(root.Path);

        CliResult result = await RunCliAsync(
            "rules",
            "test",
            "path-secret",
            "",
            "-c",
            configPath,
            "--path=secret.txt").ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("\"ruleId\":\"path-secret\"", result.Stdout);
        Assert.Contains("\"file\":\"secret.txt\"", result.Stdout);
    }

    private static string WriteTokenConfig(string root, string fileName = "gitleaks.toml")
    {
        string configPath = Path.Combine(root, fileName);
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """);
        return configPath;
    }

    private static string WriteGitHubPatConfig(string root, string fileName = "gitleaks.toml")
    {
        string configPath = Path.Combine(root, fileName);
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "github-pat"
            regex = '''ghp_[0-9A-Za-z]{36}'''
            """);
        return configPath;
    }

    private static string WriteFindingWordConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "word"
            regex = '''finding'''
            """);
        return configPath;
    }

    private static string WriteVerificationFilterConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "github-pat"
            regex = '''ghp_[0-9A-Za-z_]+'''

            [[rules]]
            id = "custom-token"
            regex = '''custom-[0-9]+'''
            """);
        return configPath;
    }

    private static void WriteActiveGitHubValidationCache(string cachePath, string configPath, string token)
    {
        RuleSet ruleSet = GitleaksConfigLoader.LoadFile(configPath);
        CompiledRuleSet rules = CompiledRuleSet.Compile(ruleSet);
        GitHubSecretLiveValidatorOptions options = GitHubSecretLiveValidatorOptions.CreateDefault();
        SecretValidationCache cache = SecretValidationCache.Open(
            Path.Combine(cachePath, "validation"),
            string.Concat(
                "rules:",
                rules.Fingerprint,
                ";github:",
                options.UserEndpoint,
                ";github-proxy:",
                string.Empty,
                ";github-tls:",
                options.TlsMode.ToString()));
        SecretValidationCacheKey key = SecretValidationCacheKey.FromFinding(
            "github",
            "github-rest-user-v1",
            CreateGitHubPatFinding(token),
            options.UserEndpoint);
        cache.Write(
            key,
            new SecretValidationResult(SecretValidationState.Active, "GitHub accepted the token"),
            DateTimeOffset.UtcNow.AddHours(1));
    }

    private static Finding CreateGitHubPatFinding(string token)
    {
        return new Finding(
            "github-pat",
            string.Empty,
            1,
            1,
            1,
            token.Length,
            token,
            token,
            "secret.txt",
            string.Empty,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            [],
            "secret.txt:github-pat:1");
    }

    private static string WritePathOnlyConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "path-secret"
            path = '''secret\.txt$'''
            """);
        return configPath;
    }

    private static void WriteZipFile(string path, params (string Name, string Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, string content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
                using Stream entryStream = entry.Open();
                entryStream.Write(Encoding.UTF8.GetBytes(content));
            }
        }

        File.WriteAllBytes(path, stream.ToArray());
    }

    private static void WriteCompressedZipFile(string path, params (string Name, string Content)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string name, string content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
                using Stream entryStream = entry.Open();
                entryStream.Write(Encoding.UTF8.GetBytes(content));
            }
        }

        File.WriteAllBytes(path, stream.ToArray());
    }

    private static string WriteTwoRuleConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "alpha-token"
            regex = '''alpha-[0-9]+'''

            [[rules]]
            id = "beta-token"
            regex = '''beta-[0-9]+'''
            """);
        return configPath;
    }

    private static string WriteArchiveInnerAllowlistConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[allowlists]]
            paths = ['''^ignored\.txt$''']

            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """);
        return configPath;
    }

    private static string CreateRuleConfig(string id, string pattern)
    {
        return $$"""
            [[rules]]
            id = "{{id}}"
            regex = '''{{pattern}}'''
            """;
    }

    private static string CreateAzureStorageAccountKeyFixture()
    {
        return string.Concat(
            "MDEyMzQ1Njc4OUFCQ0RFRkdISktMTU5PUFFS",
            "U1RVVldYWVoxMjM0NTY3ODlBQkNERUZHSElK",
            "S0xNTk9QUVJTVA==");
    }

    private static string CreateAwsAccessKeyIdFixture()
    {
        return string.Concat("AKIA", "XYZDQCEN4B6JSJQI");
    }

    private static string CreateAwsSecretAccessKeyFixture()
    {
        return string.Concat("Tg0pz8Jii8hkLx4+", "PnUisM8GmKs3a2", "DK+9qz/lie");
    }

    private static string CreateDatabaseConnectionUrlFixture()
    {
        return "postgresql://app_user:picket-db-password-123@db.internal.local:5432/appdb?sslmode=require";
    }

    private static string CreateSourcegraphAccessTokenFixture()
    {
        return string.Concat("sgp_", "0123456789abcdef", "_", "0123456789abcdef0123456789abcdef01234567");
    }

    private static string CreateGcpServiceAccountKeyJsonFixture()
    {
        return """
            {
              "type": "service_account",
              "project_id": "picket-prod-123",
              "private_key_id": "0123456789abcdef0123456789abcdef01234567",
              "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Yz0123456789abcd\n-----END PRIVATE KEY-----\n",
              "client_email": "scanner-sa@picket-prod-123.iam.gserviceaccount.com",
              "client_id": "123456789012345678901",
              "auth_uri": "https://accounts.google.com/o/oauth2/auth",
              "token_uri": "https://oauth2.googleapis.com/token"
            }
            """;
    }

    private static string CreateGoogleApiKeyFixture()
    {
        return string.Concat("AIza", "SyDabcdefghijklmnopqrstuvwxyz123456");
    }

    private static string CreateGitHubPatFixture()
    {
        return CreateGitHubClassicTokenFixture("ghp_");
    }

    private static string CreateGitHubClassicTokenFixture(string prefix)
    {
        return string.Concat(prefix, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }

    private static string CreateTomlLiteral(string value)
    {
        if (value.Contains("'''", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Test path cannot be represented as a TOML literal string.");
        }

        return $"'''{value}'''";
    }

    private static string ComputeSha256(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private static string GetSingleCacheEntryPath(string cachePath)
    {
        string[] entries = Directory.GetFiles(Path.Combine(cachePath, "entries"), "*.cache", SearchOption.AllDirectories);
        Assert.HasCount(1, entries);
        return entries[0];
    }

    private static async Task InitializeGitRepositoryAsync(string root)
    {
        await RunGitCommandAsync(root, "init").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.name", "Picket Test").ConfigureAwait(false);
        await RunGitCommandAsync(root, "config", "user.email", "picket@example.com").ConfigureAwait(false);
    }

    private static async Task<string> RunGitCommandAsync(string workingDirectory, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo("git")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Assert.Fail($"git {string.Join(' ', arguments)} failed with exit code {process.ExitCode}: {stderr}");
        }

        return stdout;
    }

    private static async Task<CliResult> RunCliAsync(params string[] arguments)
    {
        return await RunCliWithInputAsync(null, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithEnvironmentAsync(IReadOnlyDictionary<string, string?> environment, params string[] arguments)
    {
        return await RunCliWithInputFromDirectoryAsync(GetRepositoryRoot(), null, environment, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputAsync(string? standardInput, params string[] arguments)
    {
        return await RunCliWithInputFromDirectoryAsync(GetRepositoryRoot(), standardInput, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputFromDirectoryAsync(string workingDirectory, string? standardInput, params string[] arguments)
    {
        return await RunCliWithInputFromDirectoryAsync(workingDirectory, standardInput, environment: null, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputFromDirectoryAsync(
        string workingDirectory,
        string? standardInput,
        IReadOnlyDictionary<string, string?>? environment,
        params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
        {
            RedirectStandardError = true,
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG");
        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG_TOML");
        process.StartInfo.Environment.Remove("PICKET_CONFIG");
        process.StartInfo.Environment.Remove("PICKET_CONFIG_TOML");
        if (environment is not null)
        {
            foreach (KeyValuePair<string, string?> variable in environment)
            {
                if (variable.Value is null)
                {
                    process.StartInfo.Environment.Remove(variable.Key);
                }
                else
                {
                    process.StartInfo.Environment[variable.Key] = variable.Value;
                }
            }
        }

        process.Start();
        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput).ConfigureAwait(false);
            await process.StandardInput.FlushAsync().ConfigureAwait(false);
            process.StandardInput.Close();
        }

        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
    }

    private static string GetCliExecutablePath()
    {
        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string executablePath = Path.Combine(
            GetRepositoryRoot(),
            "src",
            "Picket.Cli",
            "bin",
            GetBuildConfiguration(),
            "net10.0",
            RuntimeInformation.RuntimeIdentifier,
            executableName);

        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException("Could not locate built picket executable.", executablePath);
        }

        return executablePath;
    }

    private static string GetBuildConfiguration()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null)
        {
            var info = new DirectoryInfo(directory);
            if (info.Parent?.Name.Equals("bin", StringComparison.Ordinal) == true)
            {
                return info.Name;
            }

            directory = info.Parent?.FullName;
        }

        return "Debug";
    }

    private static string GetRepositoryRoot()
    {
        string? directory = AppContext.BaseDirectory;
        while (directory is not null && !File.Exists(Path.Combine(directory, "Picket.slnx")))
        {
            directory = Directory.GetParent(directory)?.FullName;
        }

        return directory ?? throw new DirectoryNotFoundException("Could not locate repository root.");
    }
}
