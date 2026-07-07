using System.CommandLine;

namespace Picket;

internal static partial class Program
{
    static void WriteHelp() => WriteCommandHelp("--help");

    static void WriteScanHelp() => WriteCommandHelp("scan", "--help");

    static void WriteVerifyHelp() => WriteCommandHelp("verify", "--help");

    static void WriteAnalyzeHelp() => WriteCommandHelp("analyze", "--help");

    static void WriteBaselineHelp() => WriteCommandHelp("baseline", "--help");

    static void WriteBaselineCreateHelp() => WriteCommandHelp("baseline", "create", "--help");

    static void WriteCacheHelp() => WriteCommandHelp("cache", "--help");

    static void WriteCacheStatsHelp() => WriteCommandHelp("cache", "stats", "--help");

    static void WriteCachePruneHelp() => WriteCommandHelp("cache", "prune", "--help");

    static void WriteCacheExportHelp() => WriteCommandHelp("cache", "export", "--help");

    static void WriteCacheImportHelp() => WriteCommandHelp("cache", "import", "--help");

    static void WriteGitHelp() => WriteCommandHelp("git", "--help");

    static void WriteDirectoryHelp() => WriteCommandHelp("dir", "--help");

    static void WriteStdinHelp() => WriteCommandHelp("stdin", "--help");

    static void WriteDetectHelp() => WriteCommandHelp("detect", "--help");

    static void WriteProtectHelp() => WriteCommandHelp("protect", "--help");

    static void WriteViewHelp() => WriteCommandHelp("view", "--help");

    static void WriteTuiHelp() => WriteCommandHelp("tui", "--help");

    static void WriteRulesHelp() => WriteCommandHelp("rules", "--help");

    static void WriteRulesCheckHelp() => WriteCommandHelp("rules", "check", "--help");

    static void WriteRulesTestHelp() => WriteCommandHelp("rules", "test", "--help");

    static void WriteHooksHelp() => WriteCommandHelp("hooks", "--help");

    static void WriteHooksInstallHelp() => WriteCommandHelp("hooks", "install", "--help");

    private static void WriteCommandHelp(params string[] args)
    {
        string[] normalizedArgs = NormalizeCommandLineArgs(args);
        RootCommand rootCommand = CreateRootCommand(args);
        ParseResult parseResult = rootCommand.Parse(normalizedArgs, s_commandLineParserConfiguration);
        _ = parseResult.Invoke();
    }
}
