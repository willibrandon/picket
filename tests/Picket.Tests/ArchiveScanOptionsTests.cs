using Picket.Sources;

namespace Picket.Tests;

/// <summary>
/// Tests archive traversal safety defaults across source options.
/// </summary>
[TestClass]
public sealed class ArchiveScanOptionsTests
{
    /// <summary>
    /// Verifies that directory scan options keep archive traversal disabled but bounded when enabled by depth.
    /// </summary>
    [TestMethod]
    public void DirectoryScanOptionsUseBoundedArchiveBudgetsByDefault()
    {
        using TempDirectory root = TempDirectory.Create();

        var options = new DirectoryScanOptions(root.Path, maxArchiveDepth: 1);

        Assert.AreEqual(1, options.MaxArchiveDepth);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxEntries, options.MaxArchiveEntries);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxBytes, options.MaxArchiveBytes);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxCompressionRatio, options.MaxArchiveCompressionRatio);
    }

    /// <summary>
    /// Verifies that directory scan callers can explicitly disable archive budgets.
    /// </summary>
    [TestMethod]
    public void DirectoryScanOptionsAllowArchiveBudgetsToBeDisabled()
    {
        using TempDirectory root = TempDirectory.Create();

        var options = new DirectoryScanOptions(
            root.Path,
            maxArchiveDepth: 1,
            maxArchiveEntries: 0,
            maxArchiveBytes: null,
            maxArchiveCompressionRatio: 0);

        Assert.AreEqual(1, options.MaxArchiveDepth);
        Assert.AreEqual(0, options.MaxArchiveEntries);
        Assert.IsNull(options.MaxArchiveBytes);
        Assert.AreEqual(0, options.MaxArchiveCompressionRatio);
    }

    /// <summary>
    /// Verifies that git scan options keep archive traversal disabled but bounded when enabled by depth.
    /// </summary>
    [TestMethod]
    public void GitScanOptionsUseBoundedArchiveBudgetsByDefault()
    {
        using TempDirectory root = TempDirectory.Create();

        var options = new GitScanOptions(root.Path, maxArchiveDepth: 1);

        Assert.AreEqual(1, options.MaxArchiveDepth);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxEntries, options.MaxArchiveEntries);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxBytes, options.MaxArchiveBytes);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxCompressionRatio, options.MaxArchiveCompressionRatio);
    }

    /// <summary>
    /// Verifies that git scan callers can explicitly disable archive budgets.
    /// </summary>
    [TestMethod]
    public void GitScanOptionsAllowArchiveBudgetsToBeDisabled()
    {
        using TempDirectory root = TempDirectory.Create();

        var options = new GitScanOptions(
            root.Path,
            maxArchiveDepth: 1,
            maxArchiveEntries: 0,
            maxArchiveBytes: null,
            maxArchiveCompressionRatio: 0);

        Assert.AreEqual(1, options.MaxArchiveDepth);
        Assert.AreEqual(0, options.MaxArchiveEntries);
        Assert.IsNull(options.MaxArchiveBytes);
        Assert.AreEqual(0, options.MaxArchiveCompressionRatio);
    }

    /// <summary>
    /// Verifies that remote source defaults use the shared archive traversal budget constants.
    /// </summary>
    [TestMethod]
    public void RemoteSourceOptionsUseSharedArchiveBudgetsByDefault()
    {
        var gitHubOptions = new GitHubSourceOptions(GitHubSourceOptions.CreateDefaultEndpoint(), "owner/repo", "token");
        var organizationOptions = new GitHubOrganizationSourceOptions(GitHubSourceOptions.CreateDefaultEndpoint(), "owner", "token");
        var userOptions = new GitHubUserSourceOptions(GitHubSourceOptions.CreateDefaultEndpoint(), "owner", "token");
        var azureDevOpsOptions = new AzureDevOpsSourceOptions(AzureDevOpsSourceOptions.CreateServicesEndpoint("owner"), "token");

        AssertDefaultArchiveBudget(gitHubOptions.MaxArchiveDepth, gitHubOptions.MaxArchiveEntries, gitHubOptions.MaxArchiveBytes, gitHubOptions.MaxArchiveCompressionRatio);
        AssertDefaultArchiveBudget(organizationOptions.MaxArchiveDepth, organizationOptions.MaxArchiveEntries, organizationOptions.MaxArchiveBytes, organizationOptions.MaxArchiveCompressionRatio);
        AssertDefaultArchiveBudget(userOptions.MaxArchiveDepth, userOptions.MaxArchiveEntries, userOptions.MaxArchiveBytes, userOptions.MaxArchiveCompressionRatio);
        AssertDefaultArchiveBudget(azureDevOpsOptions.MaxArchiveDepth, azureDevOpsOptions.MaxArchiveEntries, azureDevOpsOptions.MaxArchiveBytes, azureDevOpsOptions.MaxArchiveCompressionRatio);
    }

    private static void AssertDefaultArchiveBudget(int depth, int entries, long? bytes, int compressionRatio)
    {
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxDepth, depth);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxEntries, entries);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxBytes, bytes);
        Assert.AreEqual(ArchiveScanDefaults.DefaultMaxCompressionRatio, compressionRatio);
    }
}
