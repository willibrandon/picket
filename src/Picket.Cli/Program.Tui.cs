using System.ComponentModel;
using System.Diagnostics;

namespace Picket;

internal static partial class Program
{
    static async Task<int> RunTuiAsync(string[] args)
    {
        if (args.Length > 0 && IsHelp(args[0]))
        {
            WriteTuiHelp();
            return 0;
        }

        string? reportPath = null;
        bool flow = false;
        bool scan = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteTuiHelp();
                return 0;
            }

            if (IsFlowFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--flow", out flow))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsTuiScanFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--scan", out scan))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }

            if (reportPath is not null)
            {
                Console.Error.WriteLine($"unexpected argument: {arg}");
                return UnknownFlagExitCode;
            }

            reportPath = arg;
        }

        if (scan && flow)
        {
            Console.Error.WriteLine("--scan cannot be combined with --flow");
            return UnknownFlagExitCode;
        }

        if (scan && !string.IsNullOrWhiteSpace(reportPath))
        {
            Console.Error.WriteLine("--scan cannot be combined with a report path");
            return UnknownFlagExitCode;
        }

        try
        {
            return await RunTuiCompanionAsync(args).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException)
        {
            Console.Error.WriteLine("picket tui requires the picket-tui companion executable on PATH or beside picket.");
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static async Task<int> RunTuiCompanionAsync(string[] args)
    {
        string executablePath = ResolveTuiCompanionPath();
        using var process = new Process();
        process.StartInfo.FileName = executablePath;
        process.StartInfo.UseShellExecute = false;
        for (int i = 0; i < args.Length; i++)
        {
            process.StartInfo.ArgumentList.Add(args[i]);
        }

        if (!process.Start())
        {
            throw new InvalidOperationException("could not start picket-tui");
        }

        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode;
    }

    private static string ResolveTuiCompanionPath()
    {
        string executableName = OperatingSystem.IsWindows() ? "picket-tui.exe" : "picket-tui";
        string besidePicket = Path.Combine(AppContext.BaseDirectory, executableName);
        return File.Exists(besidePicket) ? besidePicket : executableName;
    }

    private static bool IsFlowFlag(string arg)
    {
        return arg.Equals("--flow", StringComparison.Ordinal) || arg.StartsWith("--flow=", StringComparison.Ordinal);
    }

    private static bool IsTuiScanFlag(string arg)
    {
        return arg.Equals("--scan", StringComparison.Ordinal) || arg.StartsWith("--scan=", StringComparison.Ordinal);
    }
}
