using Picket.Engine;
using Picket.Report;
using Picket.Rules;

const int UnknownFlagExitCode = 126;

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

if (command.Equals("stdin", StringComparison.OrdinalIgnoreCase))
{
    return await RunStdinAsync(args[1..]).ConfigureAwait(false);
}

Console.Error.WriteLine($"unknown command: {command}");
return UnknownFlagExitCode;

static async Task<int> RunStdinAsync(string[] args)
{
    string reportFormat = "json";
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (arg is "-f" or "--report-format")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            reportFormat = args[++i];
            continue;
        }

        Console.Error.WriteLine($"unknown flag: {arg}");
        return UnknownFlagExitCode;
    }

    if (!reportFormat.Equals("json", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine($"unsupported report format in bootstrap build: {reportFormat}");
        return UnknownFlagExitCode;
    }

    using var stream = new MemoryStream();
    await Console.OpenStandardInput().CopyToAsync(stream).ConfigureAwait(false);
    byte[] input = stream.ToArray();
    var scanner = new SecretScanner();
    IReadOnlyList<Finding> findings = scanner.Scan(new ScanRequest(input, "stdin", EmbeddedGitleaksRules.Bootstrap));
    Console.Out.Write(GitleaksJsonReportWriter.Write(findings));
    return findings.Count == 0 ? 0 : 1;
}

static bool IsHelp(string arg)
{
    return arg is "-h" or "--help" or "help";
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket stdin [-f json]");
    Console.Out.WriteLine("  picket version");
}
