using System.Diagnostics;
using System.IO.Compression;
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
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,12,,,,,secret.txt:token:1,\n", result.Stdout);
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
        Assert.Contains("token,,secret.txt,,token-12345,token-12345,1,1,1,12,,,,,secret.txt:token:1,\n", File.ReadAllText(reportPath));
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
        Assert.Contains("Schema,RuleID,Description,File,SymlinkFile,StartLine,EndLine,StartColumn,EndColumn,Secret,SecretSha256,Match,MatchSha256,Line,Commit,Entropy,Author,Email,Date,Message,Fingerprint,ValidationState,Severity,Confidence,ProvenanceType,BaselineStatus,IgnoreReason,Tags,Link\n", result.Stdout);
        Assert.Contains("picket.finding.v1,token,,secret.txt,,1,1,1,12,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,,", result.Stdout);
        Assert.Contains(",unknown,critical,high,filesystem,new,,", result.Stdout);
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
        Assert.Contains("secret.txt:token:1", result.Stdout);
        Assert.Contains("Secret SHA-256", result.Stdout);
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
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"));

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "scan", "-f", "json").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
    }

    /// <summary>
    /// Verifies that native verification runs safe offline validators and writes native findings.
    /// </summary>
    [TestMethod]
    public async Task VerifyWritesOfflineValidationState()
    {
        using TempDirectory root = TempDirectory.Create();
        WriteGitHubPatConfig(root.Path, ".gitleaks.toml");
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"));

        CliResult result = await RunCliWithInputFromDirectoryAsync(root.Path, null, "verify", "--offline", "-f", "jsonl").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("\"schema\":\"picket.finding.v1\"", result.Stdout);
        Assert.Contains("\"ruleId\":\"github-pat\"", result.Stdout);
        Assert.Contains("\"validationState\":\"structurally-valid\"", result.Stdout);
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
            string.Concat("ghp", "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", Environment.NewLine, "custom-12345"));

        CliResult result = await RunCliAsync("verify", root.Path, "-c", configPath, "-f", "jsonl", "--only-verified").ConfigureAwait(false);
        string[] lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, result.ExitCode);
        Assert.HasCount(1, lines);
        Assert.Contains("\"ruleId\":\"github-pat\"", lines[0]);
        Assert.Contains("\"validationState\":\"structurally-valid\"", lines[0]);
        Assert.DoesNotContain("custom-token", result.Stdout);
    }

    /// <summary>
    /// Verifies that live verification does not silently run before the provider safety model exists.
    /// </summary>
    [TestMethod]
    public async Task VerifyRejectsLiveVerification()
    {
        CliResult result = await RunCliAsync("verify", "--live").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("live verification is not implemented yet", result.Stderr);
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
        Assert.Contains("--results", result.Stdout);
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
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "finding");

        CliResult first = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        CliResult second = await RunCliAsync("scan", root.Path, "-c", configPath, "--cache-dir", cachePath, "-f", "jsonl").ConfigureAwait(false);
        string[] secondLines = second.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(1, first.ExitCode);
        Assert.AreEqual(1, second.ExitCode);
        Assert.IsTrue(Directory.Exists(cachePath));
        Assert.HasCount(1, secondLines);
        Assert.Contains("\"file\":\"secret.txt\"", secondLines[0]);
        Assert.DoesNotContain(".picket/cache", second.Stdout);
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
        Assert.Contains("\"picketFingerprint\": \"secret.txt:token:1\"", result.Stdout);
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
        Assert.Contains("findings[1]{schema,ruleId,description,file,symlinkFile,startLine,endLine,startColumn,endColumn,match,secret,secretSha256,matchSha256,line,commit,entropy,author,email,date,message,fingerprint,validationState,severity,confidence,provenanceType,baselineStatus,ignoreReason,link}:", result.Stdout);
        Assert.Contains("  picket.finding.v1,token,\"\",secret.txt,\"\",1,1,1,12,token-12345,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,\"\",", result.Stdout);
        Assert.Contains(",unknown,critical,high,filesystem,new,\"\",\"\"", result.Stdout);
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
        Assert.Contains("picket.finding.v1,token,,secret.txt,,1,1,1,12,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,7cfd2b702f674578ad5c302ea365a6fb7ec9bbea316a89a776759f71f5b232ad,token-12345,,", File.ReadAllText(reportPath));
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
        Assert.Contains("picket baseline create", result.Stdout);
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
        Assert.Contains("token secret.txt:1 secret.txt:token:1", view.Stdout);
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
        using TempDirectory targetRoot = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        string targetPath = Path.Combine(targetRoot.Path, "target.txt");
        string linkPath = Path.Combine(root.Path, "link.txt");
        File.WriteAllText(targetPath, "token-12345");
        File.CreateSymbolicLink(linkPath, targetPath);

        CliResult disabled = await RunCliAsync("dir", root.Path, "-c", configPath).ConfigureAwait(false);
        CliResult enabled = await RunCliAsync("dir", root.Path, "-c", configPath, "--follow-symlinks").ConfigureAwait(false);

        Assert.AreEqual(0, disabled.ExitCode);
        Assert.AreEqual("[]\n", disabled.Stdout);
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
        Assert.Contains("\"diagnostic\": \"mem\"", memory);
        Assert.Contains("\"allocatedBytes\"", memory);
        Assert.Contains("\"event\":\"scan.start\"", trace);
        Assert.Contains("\"event\":\"scan.stop\"", trace);
    }

    /// <summary>
    /// Verifies that unsupported HTTP diagnostics fail explicitly.
    /// </summary>
    [TestMethod]
    public async Task DirectoryScanRejectsHttpDiagnostics()
    {
        using TempDirectory root = TempDirectory.Create();
        string configPath = WriteTokenConfig(root.Path);
        File.WriteAllText(Path.Combine(root.Path, "secret.txt"), "token-12345");

        CliResult result = await RunCliAsync("dir", root.Path, "-c", configPath, "--diagnostics=http").ConfigureAwait(false);

        Assert.AreEqual(126, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.Contains("--diagnostics=http is not supported yet", result.Stderr);
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
        File.WriteAllText(Path.Combine(root.Path, ".gitleaksignore"), "stdin:token:1\n");

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
        Assert.Contains("\"File\": \"stdin\"", result.Stdout);
        Assert.Contains("\"Fingerprint\": \"stdin:token:1\"", result.Stdout);
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
        Assert.Contains("\"RuleID\": \"token\"", result.Stdout);
        Assert.Contains("\"File\": \"sample.txt\"", result.Stdout);
        Assert.IsEmpty(result.Stderr);
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
        Assert.Contains("\"RuleID\": \"path-secret\"", result.Stdout);
        Assert.Contains("\"File\": \"secret.txt\"", result.Stdout);
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

    private static async Task<CliResult> RunCliWithInputAsync(string? standardInput, params string[] arguments)
    {
        return await RunCliWithInputFromDirectoryAsync(GetRepositoryRoot(), standardInput, arguments).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunCliWithInputFromDirectoryAsync(string workingDirectory, string? standardInput, params string[] arguments)
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
