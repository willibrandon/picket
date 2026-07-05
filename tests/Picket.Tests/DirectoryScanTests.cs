using Picket.Engine;
using Picket.Rules;
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

            var scanner = new SecretScanner();
            var findings = new List<Finding>();
            foreach (SourceFile file in new DirectorySource().Enumerate(new DirectoryScanOptions(root)))
            {
                byte[] input = File.ReadAllBytes(file.FullPath);
                findings.AddRange(scanner.Scan(new ScanRequest(input, file.DisplayPath, EmbeddedGitleaksRules.Bootstrap)));
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

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
