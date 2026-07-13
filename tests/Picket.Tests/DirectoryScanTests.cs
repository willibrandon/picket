using Picket.Compat;
using Picket.Engine;
using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests the directory-source to scanner integration path.
/// </summary>
[TestClass]
public sealed class DirectoryScanTests
{
    /// <summary>
    /// Verifies that directory source paths flow into Gitleaks-compatible findings.
    /// </summary>
    [TestMethod]
    public void ScanFindsSecretWithRelativeDirectoryPath()
    {
        string root = CreateTempDirectory();
        try
        {
            string nested = Path.Combine(root, "nested");
            Directory.CreateDirectory(nested);
            File.WriteAllText(Path.Combine(nested, "secret.txt"), "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF");

            CompiledRuleSet rules = CompiledRuleSet.Compile(TestRuleSets.AwsAccessToken);
            var findings = new List<Finding>();
            foreach (SourceFile file in DirectorySource.Enumerate(new DirectoryScanOptions(root)))
            {
                byte[] input = file.ReadAllBytes();
                findings.AddRange(SecretScanner.Scan(new ScanRequest(input, file.DisplayPath, rules)));
            }

            Assert.HasCount(1, findings);
            Assert.AreEqual("nested/secret.txt", findings[0].File);
            Assert.AreEqual("nested/secret.txt:aws-access-token:1", findings[0].Fingerprint);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// Verifies that .gitleaksignore fingerprints suppress directory scan findings.
    /// </summary>
    [TestMethod]
    public void ScanFiltersIgnoredDirectoryFinding()
    {
        string root = CreateTempDirectory();
        try
        {
            File.WriteAllText(Path.Combine(root, "secret.txt"), "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF");
            File.WriteAllText(Path.Combine(root, ".gitleaksignore"), "secret.txt:aws-access-token:1");

            CompiledRuleSet rules = CompiledRuleSet.Compile(TestRuleSets.AwsAccessToken);
            GitleaksIgnore ignore = GitleaksIgnore.Load(Path.Combine(root, ".gitleaksignore"));
            var findings = new List<Finding>();
            foreach (SourceFile file in DirectorySource.Enumerate(new DirectoryScanOptions(root)))
            {
                byte[] input = file.ReadAllBytes();
                findings.AddRange(SecretScanner.Scan(new ScanRequest(input, file.DisplayPath, rules)));
            }

            IReadOnlyList<Finding> filtered = ignore.Filter(findings);

            Assert.IsEmpty(filtered);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
