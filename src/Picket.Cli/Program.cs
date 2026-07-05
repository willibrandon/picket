using Picket.Compat;
using Picket.Engine;
using Picket.Report;
using Picket.Rules;
using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

const int UnknownFlagExitCode = 126;
const string GitleaksConfigEnvironmentVariable = "GITLEAKS_CONFIG";
const string GitleaksConfigTomlEnvironmentVariable = "GITLEAKS_CONFIG_TOML";

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
    string? baselinePath = null;
    string? configPath = null;
    string? reportPath = null;
    string reportFormat = "json";
    int exitCode = 1;
    int redactionPercent = 0;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (arg is "-b" or "--baseline-path")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            baselinePath = args[++i];
            continue;
        }

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

        if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
        {
            if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
            {
                return UnknownFlagExitCode;
            }

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

        if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
        {
            if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
            {
                return UnknownFlagExitCode;
            }

            continue;
        }

        if (IsRedactFlag(arg))
        {
            if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
            {
                return UnknownFlagExitCode;
            }

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

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return 1;
    }

    IReadOnlyList<Finding> findings = baseline.Filter(
        SecretScanner.Scan(new ScanRequest(input, "stdin", rules)),
        redactionPercent);
    if (redactionPercent > 0)
    {
        findings = GitleaksFindingRedactor.Redact(findings, redactionPercent);
    }

    if (!TryWriteJsonReport(findings, reportPath))
    {
        return 1;
    }

    return findings.Count == 0 ? 0 : exitCode;
}

static int RunDirectory(string[] args)
{
    string? baselinePath = null;
    string? configPath = null;
    string? reportPath = null;
    string reportFormat = "json";
    string gitleaksIgnorePath = ".";
    int exitCode = 1;
    long? maxTargetBytes = null;
    int redactionPercent = 0;
    string? root = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (arg is "-b" or "--baseline-path")
        {
            if (i + 1 >= args.Length)
            {
                Console.Error.WriteLine($"{arg} requires a value");
                return UnknownFlagExitCode;
            }

            baselinePath = args[++i];
            continue;
        }

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

        if (arg.Equals("--exit-code", StringComparison.Ordinal) || arg.StartsWith("--exit-code=", StringComparison.Ordinal))
        {
            if (!TryReadIntFlag(args, ref i, "--exit-code", out exitCode))
            {
                return UnknownFlagExitCode;
            }

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

        if (arg is "-r" or "--report-path" || arg.StartsWith("--report-path=", StringComparison.Ordinal))
        {
            if (!TryReadStringFlag(args, ref i, "--report-path", out reportPath))
            {
                return UnknownFlagExitCode;
            }

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

        if (IsRedactFlag(arg))
        {
            if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
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

    if (!TryLoadBaseline(baselinePath, out GitleaksBaseline? baseline))
    {
        return 1;
    }

    string? baselineDisplayPath = CreateControlFileDisplayPath(root, baselinePath);
    string? configDisplayPath = CreateControlFileDisplayPath(root, ResolveConfigControlPath(configPath, root));
    string? reportDisplayPath = CreateControlFileDisplayPath(root, reportPath);
    var findings = new List<Finding>();
    bool hadScanError = false;
    foreach (SourceFile file in files)
    {
        if (IsControlFile(file, baselineDisplayPath, configDisplayPath, reportDisplayPath))
        {
            continue;
        }

        try
        {
            byte[] input = File.ReadAllBytes(file.FullPath);
            findings.AddRange(SecretScanner.Scan(new ScanRequest(input, file.DisplayPath, rules)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(ex.Message);
            hadScanError = true;
        }
    }

    IReadOnlyList<Finding> filteredFindings = baseline.Filter(gitleaksIgnore.Filter(findings), redactionPercent);
    if (redactionPercent > 0)
    {
        filteredFindings = GitleaksFindingRedactor.Redact(filteredFindings, redactionPercent);
    }

    if (!TryWriteJsonReport(filteredFindings, reportPath))
    {
        return 1;
    }

    if (hadScanError)
    {
        return 1;
    }

    return filteredFindings.Count == 0 ? 0 : exitCode;
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

static bool TryReadStringFlag(string[] args, ref int index, string longName, [NotNullWhen(true)] out string? value)
{
    string arg = args[index];
    string longNameWithEquals = string.Concat(longName, "=");
    if (arg.StartsWith(longNameWithEquals, StringComparison.Ordinal))
    {
        value = arg[longNameWithEquals.Length..];
        return true;
    }

    if (index + 1 >= args.Length)
    {
        Console.Error.WriteLine($"{arg} requires a value");
        value = null;
        return false;
    }

    value = args[++index];
    return true;
}

static bool TryReadIntFlag(string[] args, ref int index, string longName, out int value)
{
    if (TryReadStringFlag(args, ref index, longName, out string? text) && int.TryParse(text, out value))
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} requires an integer value");
    value = 0;
    return false;
}

static bool IsRedactFlag(string arg)
{
    return arg.Equals("--redact", StringComparison.Ordinal)
        || arg.StartsWith("--redact=", StringComparison.Ordinal);
}

static bool TryReadRedactionPercent(string[] args, ref int index, out int redactionPercent)
{
    string arg = args[index];
    if (arg.Equals("--redact", StringComparison.Ordinal))
    {
        if (index + 1 < args.Length && int.TryParse(args[index + 1], out int parsedRedactionPercent))
        {
            if (!IsValidRedactionPercent(parsedRedactionPercent))
            {
                Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
                redactionPercent = 0;
                return false;
            }

            redactionPercent = parsedRedactionPercent;
            index++;
            return true;
        }

        redactionPercent = 100;
        return true;
    }

    string value = arg["--redact=".Length..];
    if (TryParseRedactionPercent(value, out redactionPercent))
    {
        return true;
    }

    Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
    return false;
}

static bool TryParseRedactionPercent(string value, out int redactionPercent)
{
    if (!int.TryParse(value, out redactionPercent) || !IsValidRedactionPercent(redactionPercent))
    {
        redactionPercent = 0;
        return false;
    }

    return true;
}

static bool IsValidRedactionPercent(int redactionPercent)
{
    return redactionPercent is >= 0 and <= 100;
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

static bool TryLoadBaseline(string? baselinePath, [NotNullWhen(true)] out GitleaksBaseline? baseline)
{
    if (string.IsNullOrWhiteSpace(baselinePath))
    {
        baseline = GitleaksBaseline.Empty;
        return true;
    }

    try
    {
        baseline = GitleaksBaseline.Load(baselinePath);
        return true;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException)
    {
        Console.Error.WriteLine(ex.Message);
        baseline = null;
        return false;
    }
}

static bool TryWriteJsonReport(IReadOnlyList<Finding> findings, string? reportPath)
{
    string report = GitleaksJsonReportWriter.Write(findings);
    if (string.IsNullOrWhiteSpace(reportPath) || reportPath.Equals("-", StringComparison.Ordinal))
    {
        Console.Out.Write(report);
        return true;
    }

    try
    {
        File.WriteAllText(reportPath, report);
        return true;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"failed to write report: {ex.Message}");
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

static string? CreateControlFileDisplayPath(string root, string? path)
{
    if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(root))
    {
        return null;
    }

    string relativePath = Path.GetRelativePath(Path.GetFullPath(root), Path.GetFullPath(path));
    if (relativePath.Equals(".", StringComparison.Ordinal)
        || relativePath.StartsWith("..", StringComparison.Ordinal)
        || Path.IsPathRooted(relativePath))
    {
        return null;
    }

    return relativePath.Replace(Path.DirectorySeparatorChar, '/').Replace(Path.AltDirectorySeparatorChar, '/');
}

static string? ResolveConfigControlPath(string? configPath, string source)
{
    if (!string.IsNullOrWhiteSpace(configPath))
    {
        return configPath;
    }

    string? environmentPath = Environment.GetEnvironmentVariable(GitleaksConfigEnvironmentVariable);
    if (!string.IsNullOrWhiteSpace(environmentPath))
    {
        return environmentPath;
    }

    string? environmentToml = Environment.GetEnvironmentVariable(GitleaksConfigTomlEnvironmentVariable);
    return string.IsNullOrWhiteSpace(environmentToml) ? Path.Combine(source, ".gitleaks.toml") : null;
}

static bool IsControlFile(SourceFile file, params string?[] displayPaths)
{
    foreach (string? displayPath in displayPaths)
    {
        if (displayPath is not null && file.DisplayPath.Equals(displayPath, StringComparison.Ordinal))
        {
            return true;
        }
    }

    return false;
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket - bootstrap secrets scanner");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket dir <path> [-b path] [-c path] [-f json] [-r path] [-i path] [--exit-code n] [--max-target-megabytes n] [--redact[=n]]");
    Console.Out.WriteLine("  picket stdin [-b path] [-c path] [-f json] [-r path] [--exit-code n] [--redact[=n]]");
    Console.Out.WriteLine("  picket version");
}
