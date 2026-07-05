namespace Picket;

internal static partial class Program
{
    private const int UnknownFlagExitCode = 126;
    private const int BinaryProbeLength = 8192;
    private const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
    private const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";
    private const string ManagedHookMarker = "# managed by picket hooks install";
    private const string TimeoutErrorMessage = "context deadline exceeded";

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteHelp();
            return 0;
        }

        string command = args[0];
        if (command.Equals("version", StringComparison.OrdinalIgnoreCase))
        {
            Console.Out.WriteLine("picket dev");
            return 0;
        }

        if (command.Equals("scan", StringComparison.OrdinalIgnoreCase))
        {
            return RunScan(args[1..]);
        }

        if (command.Equals("verify", StringComparison.OrdinalIgnoreCase))
        {
            return RunVerify(args[1..]);
        }

        if (command.Equals("analyze", StringComparison.OrdinalIgnoreCase))
        {
            return RunAnalyze(args[1..]);
        }

        if (command.Equals("baseline", StringComparison.OrdinalIgnoreCase))
        {
            return RunBaseline(args[1..]);
        }

        if (command.Equals("cache", StringComparison.OrdinalIgnoreCase))
        {
            return RunCache(args[1..]);
        }

        if (command.Equals("view", StringComparison.OrdinalIgnoreCase))
        {
            return RunView(args[1..]);
        }

        if (command.Equals("stdin", StringComparison.OrdinalIgnoreCase))
        {
            return await RunStdinAsync(args[1..]).ConfigureAwait(false);
        }

        if (command.Equals("detect", StringComparison.OrdinalIgnoreCase))
        {
            return await RunDetectAsync(args[1..]).ConfigureAwait(false);
        }

        if (command.Equals("protect", StringComparison.OrdinalIgnoreCase))
        {
            return RunProtect(args[1..]);
        }

        if (command.Equals("rules", StringComparison.OrdinalIgnoreCase))
        {
            return RunRules(args[1..]);
        }

        if (command.Equals("hooks", StringComparison.OrdinalIgnoreCase))
        {
            return RunHooks(args[1..]);
        }

        if (command.Equals("git", StringComparison.OrdinalIgnoreCase))
        {
            return RunGit(args[1..]);
        }

        if (IsDirectoryCommand(command))
        {
            return RunDirectory(args[1..]);
        }

        Console.Error.WriteLine($"unknown command: {command}");
        return UnknownFlagExitCode;
    }
}
