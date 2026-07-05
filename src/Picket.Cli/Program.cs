using System.Diagnostics.CodeAnalysis;
using Picket.Compat;
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
    string? configPath = null;
    string reportFormat = "json";
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (arg is "-c" or "--config")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            configPath = args[++i];
            continue;
        }

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
    if (!TryLoadRules(configPath, "stdin", out CompiledRuleSet? rules))
    {
        return 1;
    }

    IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(input, "stdin", rules));
    Console.Out.Write(GitleaksJsonReportWriter.Write(findings));
    return findings.Count == 0 ? 0 : 1;
}

static int RunDirectory(string[] args)
{
    string? configPath = null;
    string reportFormat = "json";
    string gitleaksIgnorePath = ".";
    long? maxTargetBytes = null;
    string? root = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (arg is "-c" or "--config")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            configPath = args[++i];
            continue;
        }

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

        if (arg is "-i" or "--gitleaks-ignore-path")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            gitleaksIgnorePath = args[++i];
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

        if (arg.StartsWith('-'))
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

    IReadOnlyList<SourceFile> files = DirectorySource.Enumerate(new DirectoryScanOptions(root, maxTargetBytes));
    GitleaksIgnore gitleaksIgnore = LoadGitleaksIgnore(gitleaksIgnorePath, root);
    if (!TryLoadRules(configPath, root, out CompiledRuleSet? rules))
    {
        return 1;
    }

    var findings = new List<Finding>();
    foreach (SourceFile file in files)
    {
        byte[] input = File.ReadAllBytes(file.FullPath);
        findings.AddRange(SecretScanner.Scan(new ScanRequest(input, file.DisplayPath, rules)));
    }

    IReadOnlyList<Finding> filteredFindings = gitleaksIgnore.Filter(findings);
    Console.Out.Write(GitleaksJsonReportWriter.Write(filteredFindings));
    return filteredFindings.Count == 0 ? 0 : 1;
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

static bool TryLoadRules(string? configPath, string source, [NotNullWhen(true)] out CompiledRuleSet? rules)
{
    try
    {
        RuleSet ruleSet = GitleaksConfigLoader.LoadRuleSet(configPath, source);
        rules = CompiledRuleSet.Compile(ruleSet);
        return true;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        rules = null;
        return false;
    }
}

static GitleaksIgnore LoadGitleaksIgnore(string gitleaksIgnorePath, string source)
{
    return GitleaksIgnore.LoadExisting([
        gitleaksIgnorePath,
        Path.Combine(gitleaksIgnorePath, ".gitleaksignore"),
        Path.Combine(source, ".gitleaksignore"),
    ]);
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket dir <path> [-c path] [-f json] [-i path] [--max-target-megabytes n]");
    Console.Out.WriteLine("  picket stdin [-c path] [-f json]");
    Console.Out.WriteLine("  picket version");
}
