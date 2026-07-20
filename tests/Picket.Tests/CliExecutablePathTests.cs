namespace Picket.Tests;

/// <summary>
/// Tests explicit CLI executable selection for process-level tests.
/// </summary>
[TestClass]
[DoNotParallelize]
public sealed class CliExecutablePathTests
{
    private const string TestCliPathEnvironmentVariable = "PICKET_TEST_CLI_PATH";

    /// <summary>
    /// Verifies an explicit absolute executable path takes precedence over build output discovery.
    /// </summary>
    [TestMethod]
    public void ResolveUsesExplicitExecutablePath()
    {
        using TempDirectory root = TempDirectory.Create();
        string executablePath = Path.Combine(root.Path, "picket-test");
        File.WriteAllText(executablePath, string.Empty);
        string? originalValue = Environment.GetEnvironmentVariable(TestCliPathEnvironmentVariable);

        try
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, executablePath);

            string resolvedPath = CliExecutablePath.Resolve(root.Path, "Release");

            Assert.AreEqual(Path.GetFullPath(executablePath), resolvedPath);
        }
        finally
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, originalValue);
        }
    }

    /// <summary>
    /// Verifies a relative explicit executable path is rejected instead of being resolved against an ambiguous working directory.
    /// </summary>
    [TestMethod]
    public void ResolveRejectsRelativeExplicitExecutablePath()
    {
        string? originalValue = Environment.GetEnvironmentVariable(TestCliPathEnvironmentVariable);

        try
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, "picket-test");

            InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
                () => CliExecutablePath.Resolve(Path.GetTempPath(), "Release"));

            Assert.Contains("must be an absolute path", exception.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, originalValue);
        }
    }

    /// <summary>
    /// Verifies a missing explicit executable fails clearly instead of falling back to a different build.
    /// </summary>
    [TestMethod]
    public void ResolveRejectsMissingExplicitExecutablePath()
    {
        string missingPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "picket-test");
        string? originalValue = Environment.GetEnvironmentVariable(TestCliPathEnvironmentVariable);

        try
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, missingPath);

            FileNotFoundException exception = Assert.ThrowsExactly<FileNotFoundException>(
                () => CliExecutablePath.Resolve(Path.GetTempPath(), "Release"));

            Assert.AreEqual(Path.GetFullPath(missingPath), exception.FileName);
        }
        finally
        {
            Environment.SetEnvironmentVariable(TestCliPathEnvironmentVariable, originalValue);
        }
    }
}
