using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;

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

            if (IsTuiTabFlag(arg))
            {
                if (!TryReadTuiTab(args, ref i))
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
        using var process = new Process
        {
            StartInfo = CreateTuiCompanionStartInfo(args),
        };

        if (!process.Start())
        {
            throw new InvalidOperationException("could not start picket-tui");
        }

        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode;
    }

    private static ProcessStartInfo CreateTuiCompanionStartInfo(string[] args)
    {
        string executablePath = ResolveTuiCompanionPath();
        ProcessStartInfo startInfo;
        if (OperatingSystem.IsWindows()
            && Path.GetExtension(executablePath) is ".cmd" or ".bat")
        {
            startInfo = new ProcessStartInfo(ResolveWindowsCommandProcessor())
            {
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add("/d");
            startInfo.ArgumentList.Add("/s");
            startInfo.ArgumentList.Add("/c");
            startInfo.ArgumentList.Add(executablePath);
        }
        else
        {
            startInfo = new ProcessStartInfo(executablePath)
            {
                UseShellExecute = false,
            };
        }

        SetTuiScannerPath(startInfo);
        for (int i = 0; i < args.Length; i++)
        {
            startInfo.ArgumentList.Add(args[i]);
        }

        return startInfo;
    }

    private static void SetTuiScannerPath(ProcessStartInfo startInfo)
    {
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PICKET_SCANNER")))
        {
            return;
        }

        string? processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath)
            || !Path.IsPathFullyQualified(processPath)
            || !File.Exists(processPath))
        {
            return;
        }

        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!Path.GetFileNameWithoutExtension(processPath).Equals("picket", comparison))
        {
            return;
        }

        startInfo.Environment["PICKET_SCANNER"] = Path.GetFullPath(processPath);
    }

    private static string ResolveTuiCompanionPath()
    {
        string executableName = OperatingSystem.IsWindows() ? "picket-tui.exe" : "picket-tui";
        string besidePicket = Path.Combine(AppContext.BaseDirectory, executableName);
        if (File.Exists(besidePicket))
        {
            return besidePicket;
        }

        if (!OperatingSystem.IsWindows())
        {
            return executableName;
        }

        string? path = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(path))
        {
            string[] extensions = [".exe", ".cmd", ".bat"];
            foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmedDirectory = directory.Trim().Trim('"');
                for (int extensionIndex = 0; extensionIndex < extensions.Length; extensionIndex++)
                {
                    string candidate = Path.Combine(trimmedDirectory, string.Concat("picket-tui", extensions[extensionIndex]));
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }

        return executableName;
    }

    private static string ResolveWindowsCommandProcessor()
    {
        string? commandProcessor = Environment.GetEnvironmentVariable("ComSpec");
        return string.IsNullOrWhiteSpace(commandProcessor)
            ? Path.Combine(Environment.SystemDirectory, "cmd.exe")
            : commandProcessor;
    }

    private static bool IsFlowFlag(string arg)
    {
        return arg.Equals("--flow", StringComparison.Ordinal) || arg.StartsWith("--flow=", StringComparison.Ordinal);
    }

    private static bool IsTuiScanFlag(string arg)
    {
        return arg.Equals("--scan", StringComparison.Ordinal) || arg.StartsWith("--scan=", StringComparison.Ordinal);
    }

    private static bool IsTuiTabFlag(string arg)
    {
        return arg.Equals("--tab", StringComparison.Ordinal)
            || arg.StartsWith("--tab=", StringComparison.Ordinal)
            || arg.Equals("-t", StringComparison.Ordinal)
            || arg.StartsWith("-t=", StringComparison.Ordinal);
    }

    private static bool TryReadTuiTab(string[] args, ref int index)
    {
        string arg = args[index];
        string? value;
        if (arg.StartsWith("--tab=", StringComparison.Ordinal))
        {
            value = arg["--tab=".Length..];
        }
        else if (arg.StartsWith("-t=", StringComparison.Ordinal))
        {
            value = arg["-t=".Length..];
        }
        else if (index + 1 < args.Length)
        {
            value = args[++index];
        }
        else
        {
            Console.Error.WriteLine($"{arg} requires a value");
            return false;
        }

        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int tab)
            && tab is >= 1 and <= 6)
        {
            return true;
        }

        Console.Error.WriteLine("--tab requires a value from 1 through 6.");
        return false;
    }
}
