using System.Runtime.InteropServices;

namespace Picket.Tests;

internal static class CliExecutablePath
{
    internal static string Resolve(string repositoryRoot, string configuration)
    {
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
