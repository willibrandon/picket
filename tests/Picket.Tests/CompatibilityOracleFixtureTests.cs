using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Picket.Tests;

/// <summary>
/// Tests committed compatibility oracle fixtures.
/// </summary>
[TestClass]
public sealed class CompatibilityOracleFixtureTests
{
    /// <summary>
    /// Verifies that the basic directory JSON fixture still matches the promoted Gitleaks oracle report.
    /// </summary>
    [TestMethod]
    [Timeout(30000, CooperativeCancellation = true)]
    public async Task BasicDirectoryJsonReportMatchesPromotedGitleaksOracle()
    {
        string repositoryRoot = GetRepositoryRoot();
        string inputRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracle-inputs", "basic-dir-json");
        string oracleRoot = Path.Combine(repositoryRoot, "tests", "fixtures", "oracles", "basic-dir-json");
        string expectedReport = NormalizeLineEndings(File.ReadAllText(Path.Combine(oracleRoot, "gitleaks.json")));
        string promotedPicketReport = NormalizeLineEndings(File.ReadAllText(Path.Combine(oracleRoot, "picket.json")));
        using TempDirectory output = TempDirectory.Create();
        string reportPath = Path.Combine(output.Path, "report.json");

        Assert.AreEqual(expectedReport, promotedPicketReport);

        CliResult result = await RunCliWithInputFromDirectoryAsync(
            inputRoot,
            "dir",
            ".",
            "-c",
            ".gitleaks.toml",
            "-f",
            "json",
            "-r",
            reportPath,
            "--no-banner",
            "--no-color",
            "--redact=100").ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.IsEmpty(result.Stdout);
        Assert.IsEmpty(result.Stderr);
        Assert.AreEqual(expectedReport, NormalizeLineEndings(File.ReadAllText(reportPath)));
    }

    private static async Task<CliResult> RunCliWithInputFromDirectoryAsync(string workingDirectory, params string[] arguments)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(GetCliExecutablePath())
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

    private static string NormalizeLineEndings(string value)
    {
        return value.ReplaceLineEndings("\n");
    }
}
