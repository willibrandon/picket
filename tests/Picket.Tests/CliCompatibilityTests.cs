using System.Diagnostics;

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

    private static string WriteTokenConfig(string root)
    {
        string configPath = Path.Combine(root, "gitleaks.toml");
        File.WriteAllText(
            configPath,
            """
            [[rules]]
            id = "token"
            regex = '''token-[0-9]+'''
            """);
        return configPath;
    }

    private static async Task<CliResult> RunCliAsync(params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo("dotnet")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            WorkingDirectory = GetRepositoryRoot(),
        };
        process.StartInfo.ArgumentList.Add("run");
        process.StartInfo.ArgumentList.Add("--project");
        process.StartInfo.ArgumentList.Add(Path.Combine("src", "Picket.Cli", "Picket.Cli.csproj"));
        process.StartInfo.ArgumentList.Add("--");
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        string stdout = await process.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync().ConfigureAwait(false);
        await process.WaitForExitAsync().ConfigureAwait(false);
        return new CliResult(process.ExitCode, stdout, stderr);
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
