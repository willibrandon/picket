using System.Diagnostics;

namespace Picket.Tests;

/// <summary>
/// Tests managed Git hooks through real commit, push, and receive operations.
/// </summary>
[TestClass]
public sealed class GitHookIntegrationTests
{
    private const int HookTestTimeoutMilliseconds = 60_000;

    /// <summary>
    /// Gets or sets the MSTest context for the current test.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies that pre-commit allows clean changes and blocks findings with a bounded, terminal-safe summary.
    /// </summary>
    [TestMethod]
    [Timeout(HookTestTimeoutMilliseconds, CooperativeCancellation = true)]
    public async Task PreCommitHookAllowsCleanChangesAndBlocksFindings()
    {
        using TempDirectory root = TempDirectory.Create();
        string repositoryPath = Path.Combine(root.Path, "repository");
        string configPath = WriteHookConfig(root.Path, "test-\u202e-rule");
        Directory.CreateDirectory(repositoryPath);
        await InitializeRepositoryAsync(repositoryPath).ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "seed.txt", "clean\n", "seed").ConfigureAwait(false);
        await InstallHookAsync(repositoryPath, configPath, "pre-commit").ConfigureAwait(false);

        await CommitFileAsync(repositoryPath, "clean.txt", "still clean\n", "clean").ConfigureAwait(false);
        string cleanHead = await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false);
        for (int i = 0; i < 25; i++)
        {
            string fileName = i == 0 ? "000-token-10000.txt" : $"secret-{i:D2}.txt";
            File.WriteAllText(
                Path.Combine(repositoryPath, fileName),
                $"token-{10_000 + i}\n");
        }

        await RunGitSuccessAsync(repositoryPath, "add", ".").ConfigureAwait(false);
        CliResult commit = await RunGitAsync(repositoryPath, "commit", "-m", "contains findings").ConfigureAwait(false);
        string output = string.Concat(commit.Stdout, commit.Stderr);

        Assert.AreNotEqual(0, commit.ExitCode);
        Assert.Contains("Picket blocked the commit: 25 findings in staged changes.", output);
        Assert.Contains("test-?-rule", output);
        Assert.Contains("000-REDACTED.txt:1", output);
        Assert.Contains("... 5 more findings", output);
        Assert.Contains("Secret values are not printed.", output);
        Assert.Contains("Resolve the findings or allowlist expected values, then retry the commit.", output);
        Assert.DoesNotContain("\u202e", output);
        Assert.DoesNotContain("token-10000", output);
        Assert.AreEqual(cleanHead, await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false));
    }

    /// <summary>
    /// Verifies that pre-push allows clean commits and blocks findings before the remote ref moves.
    /// </summary>
    [TestMethod]
    [Timeout(HookTestTimeoutMilliseconds, CooperativeCancellation = true)]
    public async Task PrePushHookAllowsCleanCommitsAndBlocksFindings()
    {
        using TempDirectory root = TempDirectory.Create();
        string repositoryPath = Path.Combine(root.Path, "repository");
        string remotePath = Path.Combine(root.Path, "remote.git");
        string configPath = WriteHookConfig(root.Path, "test-token");
        Directory.CreateDirectory(repositoryPath);
        Directory.CreateDirectory(remotePath);
        await InitializeRepositoryAsync(repositoryPath).ConfigureAwait(false);
        await InitializeBareRepositoryAsync(remotePath).ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "seed.txt", "clean\n", "seed").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "remote", "add", "origin", remotePath).ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "push", "--set-upstream", "origin", "main").ConfigureAwait(false);
        await InstallHookAsync(repositoryPath, configPath, "pre-push").ConfigureAwait(false);

        await CommitFileAsync(repositoryPath, "clean.txt", "still clean\n", "clean").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "push", "origin", "main").ConfigureAwait(false);
        string cleanRemoteHead = await RunGitSuccessAsync(remotePath, "rev-parse", "refs/heads/main").ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "secret.txt", "token-12345\n", "contains finding").ConfigureAwait(false);
        string findingCommit = await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false);

        CliResult push = await RunGitAsync(repositoryPath, "push", "origin", "main").ConfigureAwait(false);
        string output = string.Concat(push.Stdout, push.Stderr);

        Assert.AreNotEqual(0, push.ExitCode);
        Assert.Contains("Picket blocked the push: 1 finding in outgoing commits.", output);
        Assert.Contains($"commit {findingCommit[..12]}", output);
        Assert.Contains("secret.txt:1", output);
        Assert.DoesNotContain("token-12345", output);
        Assert.AreEqual(cleanRemoteHead, await RunGitSuccessAsync(remotePath, "rev-parse", "refs/heads/main").ConfigureAwait(false));
    }

    /// <summary>
    /// Verifies that pre-receive allows clean commits and rejects findings before the remote ref moves.
    /// </summary>
    [TestMethod]
    [Timeout(HookTestTimeoutMilliseconds, CooperativeCancellation = true)]
    public async Task PreReceiveHookAllowsCleanCommitsAndRejectsFindings()
    {
        using TempDirectory root = TempDirectory.Create();
        string repositoryPath = Path.Combine(root.Path, "repository");
        string remotePath = Path.Combine(root.Path, "remote.git");
        string configPath = WriteHookConfig(root.Path, "test-token");
        Directory.CreateDirectory(repositoryPath);
        Directory.CreateDirectory(remotePath);
        await InitializeRepositoryAsync(repositoryPath).ConfigureAwait(false);
        await InitializeBareRepositoryAsync(remotePath).ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "seed.txt", "clean\n", "seed").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "remote", "add", "origin", remotePath).ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "push", "--set-upstream", "origin", "main").ConfigureAwait(false);
        await InstallHookAsync(remotePath, configPath, "pre-receive").ConfigureAwait(false);

        await CommitFileAsync(repositoryPath, "clean.txt", "still clean\n", "clean").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "push", "origin", "main").ConfigureAwait(false);
        string cleanRemoteHead = await RunGitSuccessAsync(remotePath, "rev-parse", "refs/heads/main").ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "secret.txt", "token-12345\n", "contains finding").ConfigureAwait(false);
        string findingCommit = await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false);

        CliResult push = await RunGitAsync(repositoryPath, "push", "origin", "main").ConfigureAwait(false);
        string output = string.Concat(push.Stdout, push.Stderr);

        Assert.AreNotEqual(0, push.ExitCode);
        Assert.Contains("Picket rejected the push: 1 finding in received commits.", output);
        Assert.Contains($"commit {findingCommit[..12]}", output);
        Assert.Contains("secret.txt:1", output);
        Assert.DoesNotContain("token-12345", output);
        Assert.AreEqual(cleanRemoteHead, await RunGitSuccessAsync(remotePath, "rev-parse", "refs/heads/main").ConfigureAwait(false));
    }

    /// <summary>
    /// Verifies that scanner failures block the commit and are not mislabeled as secret findings.
    /// </summary>
    [TestMethod]
    [Timeout(HookTestTimeoutMilliseconds, CooperativeCancellation = true)]
    public async Task PreCommitHookDistinguishesScannerFailuresFromFindings()
    {
        using TempDirectory root = TempDirectory.Create();
        string repositoryPath = Path.Combine(root.Path, "repository");
        string configPath = WriteHookConfig(root.Path, "test-token");
        Directory.CreateDirectory(repositoryPath);
        await InitializeRepositoryAsync(repositoryPath).ConfigureAwait(false);
        await CommitFileAsync(repositoryPath, "seed.txt", "clean\n", "seed").ConfigureAwait(false);
        await InstallHookAsync(repositoryPath, configPath, "pre-commit").ConfigureAwait(false);
        File.Delete(configPath);
        File.WriteAllText(Path.Combine(repositoryPath, "clean.txt"), "still clean\n");
        await RunGitSuccessAsync(repositoryPath, "add", "clean.txt").ConfigureAwait(false);
        string originalHead = await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false);

        CliResult commit = await RunGitAsync(repositoryPath, "commit", "-m", "scanner failure").ConfigureAwait(false);
        string output = string.Concat(commit.Stdout, commit.Stderr);

        Assert.AreNotEqual(0, commit.ExitCode);
        Assert.Contains("Picket could not scan staged changes; commit blocked.", output);
        Assert.DoesNotContain("Picket blocked the commit:", output);
        Assert.DoesNotContain("Secret values are not printed.", output);
        Assert.AreEqual(originalHead, await RunGitSuccessAsync(repositoryPath, "rev-parse", "HEAD").ConfigureAwait(false));
    }

    /// <summary>
    /// Verifies that hook installation follows Git's effective hook directory from a nested worktree path.
    /// </summary>
    [TestMethod]
    [Timeout(HookTestTimeoutMilliseconds, CooperativeCancellation = true)]
    public async Task HookInstallationHonorsCoreHooksPath()
    {
        using TempDirectory root = TempDirectory.Create();
        string repositoryPath = Path.Combine(root.Path, "repository");
        string nestedPath = Path.Combine(repositoryPath, "src", "nested");
        Directory.CreateDirectory(repositoryPath);
        await InitializeRepositoryAsync(repositoryPath).ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "core.hooksPath", ".picket-hooks").ConfigureAwait(false);
        Directory.CreateDirectory(nestedPath);

        CliResult install = await RunPicketAsync(
            root.Path,
            "hooks",
            "install",
            "pre-commit",
            "--repo",
            nestedPath,
            "--command",
            GetCliExecutablePath()).ConfigureAwait(false);
        string expectedPath = Path.Combine(repositoryPath, ".picket-hooks", "pre-commit");

        Assert.AreEqual(0, install.ExitCode);
        Assert.Contains($"installed pre-commit: {expectedPath}", install.Stdout);
        Assert.IsTrue(File.Exists(expectedPath));
        Assert.IsFalse(File.Exists(Path.Combine(repositoryPath, ".git", "hooks", "pre-commit")));
    }

    private async Task CommitFileAsync(
        string repositoryPath,
        string relativePath,
        string content,
        string message)
    {
        File.WriteAllText(Path.Combine(repositoryPath, relativePath), content);
        await RunGitSuccessAsync(repositoryPath, "add", relativePath).ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "commit", "-m", message).ConfigureAwait(false);
    }

    private async Task InitializeBareRepositoryAsync(string repositoryPath)
    {
        await RunGitSuccessAsync(repositoryPath, "init", "--bare", "--initial-branch=main", ".").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "core.hooksPath", "hooks").ConfigureAwait(false);
    }

    private async Task InitializeRepositoryAsync(string repositoryPath)
    {
        await RunGitSuccessAsync(repositoryPath, "init", "--initial-branch=main", ".").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "commit.gpgSign", "false").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "core.autocrlf", "false").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "core.hooksPath", ".git/hooks").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "user.email", "picket-tests@example.invalid").ConfigureAwait(false);
        await RunGitSuccessAsync(repositoryPath, "config", "user.name", "Picket Tests").ConfigureAwait(false);
    }

    private async Task<CliResult> InstallHookAsync(string repositoryPath, string configPath, string hookName)
    {
        CliResult result = await RunPicketAsync(
            repositoryPath,
            "hooks",
            "install",
            hookName,
            "--repo",
            repositoryPath,
            "--config",
            configPath,
            "--command",
            GetCliExecutablePath()).ConfigureAwait(false);
        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        return result;
    }

    private async Task<CliResult> RunGitAsync(string workingDirectory, params string[] arguments)
    {
        return await RunProcessAsync(
            "git",
            workingDirectory,
            arguments,
            TestContext.CancellationToken).ConfigureAwait(false);
    }

    private async Task<string> RunGitSuccessAsync(string workingDirectory, params string[] arguments)
    {
        CliResult result = await RunGitAsync(workingDirectory, arguments).ConfigureAwait(false);
        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        return result.Stdout.Trim();
    }

    private async Task<CliResult> RunPicketAsync(string workingDirectory, params string[] arguments)
    {
        return await RunProcessAsync(
            GetCliExecutablePath(),
            workingDirectory,
            arguments,
            TestContext.CancellationToken).ConfigureAwait(false);
    }

    private static async Task<CliResult> RunProcessAsync(
        string executablePath,
        string workingDirectory,
        string[] arguments,
        CancellationToken cancellationToken)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(executablePath)
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

        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG");
        process.StartInfo.Environment.Remove("GITLEAKS_CONFIG_TOML");
        process.StartInfo.Environment.Remove("PICKET_CONFIG");
        process.StartInfo.Environment.Remove("PICKET_CONFIG_TOML");
        process.Start();
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                }
            }

            throw;
        }

        return new CliResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));
    }

    private static string WriteHookConfig(string directoryPath, string ruleId)
    {
        string configPath = Path.Combine(directoryPath, "hook-config.toml");
        File.WriteAllText(
            configPath,
            string.Concat(
                "title = \"Picket hook test\"\n\n",
                "[[rules]]\n",
                "id = \"",
                ruleId,
                "\"\n",
                "description = \"Detect a test token.\"\n",
                "regex = '''token-[0-9]{5}'''\n"));
        return configPath;
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

    private static string GetCliExecutablePath()
    {
        return CliExecutablePath.Resolve(GetRepositoryRoot(), GetBuildConfiguration());
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
