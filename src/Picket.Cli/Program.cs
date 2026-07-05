using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Sources;

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

if (IsDirectoryCommand(command))
{
    return RunDirectory(args[1..]);
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
    CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);
    var scanner = new SecretScanner();
    IReadOnlyList<Finding> findings = scanner.Scan(new ScanRequest(input, "stdin", rules));
    Console.Out.Write(GitleaksJsonReportWriter.Write(findings));
    return findings.Count == 0 ? 0 : 1;
}

static int RunDirectory(string[] args)
{
    string reportFormat = "json";
    long? maxTargetBytes = null;
    string? root = null;
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

        if (arg is "--max-target-megabytes")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            if (!TryParseMegabytes(args[++i], out maxTargetBytes))
            {
                Console.Error.WriteLine($"{arg} requires a non-negative integer value");
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (arg.StartsWith("-", StringComparison.Ordinal))
        {
            Console.Error.WriteLine($"unknown flag: {arg}");
            return UnknownFlagExitCode;
        }

        if (root is not null)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return UnknownFlagExitCode;
        }

        root = arg;
    }

    if (!reportFormat.Equals("json", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine($"unsupported report format in bootstrap build: {reportFormat}");
        return UnknownFlagExitCode;
    }

    if (root is null)
    {
        Console.Error.WriteLine("dir requires a path");
        return UnknownFlagExitCode;
    }

    IReadOnlyList<SourceFile> files = new DirectorySource().Enumerate(new DirectoryScanOptions(root, maxTargetBytes));
    CompiledRuleSet rules = CompiledRuleSet.Compile(EmbeddedGitleaksRules.Bootstrap);
    var findings = new List<Finding>();
    var scanner = new SecretScanner();
    foreach (SourceFile file in files)
    {
        byte[] input = File.ReadAllBytes(file.FullPath);
        findings.AddRange(scanner.Scan(new ScanRequest(input, file.DisplayPath, rules)));
    }

    Console.Out.Write(GitleaksJsonReportWriter.Write(findings));
    return findings.Count == 0 ? 0 : 1;
}

static bool IsHelp(string arg)
{
    return arg is "-h" or "--help" or "help";
}

static bool IsDirectoryCommand(string command)
{
    return command.Equals("dir", StringComparison.OrdinalIgnoreCase)
        || command.Equals("file", StringComparison.OrdinalIgnoreCase)
        || command.Equals("directory", StringComparison.OrdinalIgnoreCase);
}

static bool TryParseMegabytes(string value, out long? bytes)
{
    if (!long.TryParse(value, out long megabytes) || megabytes < 0)
    {
        bytes = null;
        return false;
    }

    bytes = megabytes * 1_000_000;
    return true;
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket dir <path> [-f json] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket stdin [-f json]");
    Console.Out.WriteLine("  picket version");
}
