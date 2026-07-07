using Picket.Tui;

return await RunAsync(args).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args)
{
    if (args.Length == 0 || IsHelp(args[0]))
    {
        WriteHelp();
        return 0;
    }

    bool flow = false;
    string? reportPath = null;
    for (int i = 0; i < args.Length; i++)
    {
        string arg = args[i];
        if (IsHelp(arg))
        {
            WriteHelp();
            return 0;
        }

        if (IsFlowFlag(arg))
        {
            if (!TryReadBooleanFlag(arg, "--flow", out flow))
            {
                return 126;
            }

            continue;
        }

        if (arg.StartsWith('-'))
        {
            Console.Error.WriteLine($"unknown flag: {arg}");
            return 126;
        }

        if (reportPath is not null)
        {
            Console.Error.WriteLine($"unexpected argument: {arg}");
            return 126;
        }

        reportPath = arg;
    }

    if (!flow && string.IsNullOrWhiteSpace(reportPath))
    {
        Console.Error.WriteLine("picket-tui requires a report path");
        return 126;
    }

    try
    {
        return flow
            ? await PicketTuiFlowRunner.RunAsync(reportPath).ConfigureAwait(false)
            : await PicketTuiRunner.RunAsync(reportPath!).ConfigureAwait(false);
    }
    catch (OperationCanceledException)
    {
        return 130;
    }
    catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static bool IsHelp(string arg)
{
    return arg is "-h" or "--help" or "help";
}

static bool IsFlowFlag(string arg)
{
    return arg.Equals("--flow", StringComparison.Ordinal) || arg.StartsWith("--flow=", StringComparison.Ordinal);
}

static bool TryReadBooleanFlag(string arg, string longName, out bool value)
{
    if (arg.Equals(longName, StringComparison.Ordinal))
    {
        value = true;
        return true;
    }

    string prefix = string.Concat(longName, "=");
    if (!arg.StartsWith(prefix, StringComparison.Ordinal))
    {
        value = false;
        return false;
    }

    string text = arg[prefix.Length..];
    if (bool.TryParse(text, out value))
    {
        return true;
    }

    Console.Error.WriteLine($"{longName} requires a boolean value");
    return false;
}

static void WriteHelp()
{
    Console.Out.WriteLine("picket-tui - interactive report triage console");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Usage:");
    Console.Out.WriteLine("  picket-tui <report> [--flow]");
    Console.Out.WriteLine("  picket-tui --flow");
    Console.Out.WriteLine();
    Console.Out.WriteLine("Formats:");
    Console.Out.WriteLine("  Picket JSON/JSONL, Gitleaks JSON, TruffleHog JSON/JSONL, GitLab code-quality JSON, SARIF, HTML");
}
