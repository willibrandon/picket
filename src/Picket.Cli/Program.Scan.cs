namespace Picket;

internal static partial class Program
{
    static int RunScan(string[] args)
    {
        var forwardedArgs = new List<string>();
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteScanHelp();
                return 0;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            forwardedArgs.Add(arg);
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        return RunDirectory(
            [.. forwardedArgs],
            nativeReportFormats: true,
            diagnosticsCommand: "scan",
            defaultRoot: ".");
    }
}
