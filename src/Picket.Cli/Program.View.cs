using Picket.Report;

namespace Picket;

internal static partial class Program
{
    static int RunView(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteViewHelp();
            return 0;
        }

        bool open = false;
        string? reportPath = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteViewHelp();
                return 0;
            }

            if (IsOpenFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--open", out open))
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

        if (string.IsNullOrWhiteSpace(reportPath))
        {
            Console.Error.WriteLine("view requires a report path");
            return UnknownFlagExitCode;
        }

        if (IsHtmlReportPath(reportPath))
        {
            if (!File.Exists(reportPath))
            {
                Console.Error.WriteLine($"could not open {reportPath}");
                return 1;
            }

            WriteHtmlViewSummary(reportPath);
            return open && !TryOpenReport(reportPath) ? 1 : 0;
        }

        ReportSummary summary;
        try
        {
            summary = ReportSummaryReader.Read(reportPath);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        WriteReportViewSummary(reportPath, summary);
        return open && !TryOpenReport(reportPath) ? 1 : 0;
    }
}
