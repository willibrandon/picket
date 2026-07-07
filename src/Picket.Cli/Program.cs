namespace Picket;

internal static partial class Program
{
    private const int UnknownFlagExitCode = 126;
    private const int BinaryProbeLength = 8192;
    private const int DefaultNativeMaxArchiveDepth = 1;
    private const int DefaultNativeMaxArchiveEntries = 4096;
    private const long DefaultNativeMaxArchiveBytes = 512_000_000;
    private const int DefaultNativeMaxArchiveCompressionRatio = 1000;
    private const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
    private const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
    private const string ManagedHookMarker = "# managed by picket hooks install";
    private const string TimeoutErrorMessage = "context deadline exceeded";

    private static async Task<int> Main(string[] args)
    {
        return await RunCommandLineAsync(args).ConfigureAwait(false);
    }
}
