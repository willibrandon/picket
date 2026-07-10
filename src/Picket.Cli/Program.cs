namespace Picket;

internal static partial class Program
{
    private const int UnknownFlagExitCode = 126;
    private const int BinaryProbeLength = 8192;
    private const int DefaultNativeMaxArchiveDepth = Sources.ArchiveScanDefaults.DefaultMaxDepth;
    private const int DefaultNativeMaxArchiveEntries = Sources.ArchiveScanDefaults.DefaultMaxEntries;
    private const long DefaultNativeMaxArchiveBytes = Sources.ArchiveScanDefaults.DefaultMaxBytes;
    private const int DefaultNativeMaxArchiveCompressionRatio = Sources.ArchiveScanDefaults.DefaultMaxCompressionRatio;
    private const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
    private const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
    private const string IncompleteScanMessage = "scan incomplete: one or more inputs could not be scanned";
    private const string ManagedHookMarker = "# managed by picket hooks install";
    private const string TimeoutErrorMessage = "context deadline exceeded";

    private static async Task<int> Main(string[] args)
    {
        return await RunCommandLineAsync(args).ConfigureAwait(false);
    }
}
