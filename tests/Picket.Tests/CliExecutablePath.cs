using System.Runtime.InteropServices;

namespace Picket.Tests;

internal static class CliExecutablePath
{
    private const string TestCliPathEnvironmentVariable = "PICKET_TEST_CLI_PATH";

    internal static string Resolve(string repositoryRoot, string configuration)
    {
        string? explicitPath = Environment.GetEnvironmentVariable(TestCliPathEnvironmentVariable);
        if (explicitPath is not null)
        {
            if (string.IsNullOrWhiteSpace(explicitPath))
            {
                throw new InvalidOperationException($"{TestCliPathEnvironmentVariable} must name a built Picket executable.");
            }

            if (!Path.IsPathFullyQualified(explicitPath))
            {
                throw new InvalidOperationException($"{TestCliPathEnvironmentVariable} must be an absolute path.");
            }

            string resolvedExplicitPath = Path.GetFullPath(explicitPath);
            if (!File.Exists(resolvedExplicitPath))
            {
                throw new FileNotFoundException(
                    $"{TestCliPathEnvironmentVariable} does not name an existing Picket executable.",
                    resolvedExplicitPath);
            }

            return resolvedExplicitPath;
        }

        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string frameworkExecutablePath = Path.Combine(
            repositoryRoot,
            "src",
            "Picket.Cli",
            "bin",
            configuration,
            "net10.0",
            executableName);

        if (File.Exists(frameworkExecutablePath))
        {
            return frameworkExecutablePath;
        }

        string ridExecutablePath = Path.Combine(
            repositoryRoot,
            "src",
            "Picket.Cli",
            "bin",
            configuration,
            "net10.0",
            RuntimeInformation.RuntimeIdentifier,
            executableName);

        if (File.Exists(ridExecutablePath))
        {
            return ridExecutablePath;
        }

        throw new FileNotFoundException("Could not locate built picket executable.", frameworkExecutablePath);
    }
}
