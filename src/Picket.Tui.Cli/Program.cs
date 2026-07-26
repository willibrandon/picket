using Picket.Security;
using Picket.Tui;
using System.CommandLine;

return await RunAsync(args).ConfigureAwait(false);

static async Task<int> RunAsync(string[] args)
{
    RootCommand rootCommand = CreateRootCommand();
    ParseResult parseResult = rootCommand.Parse(args, new ParserConfiguration
    {
        EnablePosixBundling = false,
        ResponseFileTokenReplacer = null,
    });

    try
    {
        return await parseResult.InvokeAsync().ConfigureAwait(false);
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
    catch (Exception exception)
    {
        CrashDiagnosticWriter.Write(Console.Error, exception);
        return 1;
    }
    finally
    {
        RestoreTerminal();
    }
}

static RootCommand CreateRootCommand()
{
    var reportArgument = new Argument<string?>("report")
    {
        Arity = ArgumentArity.ZeroOrOne,
        Description = "Report file to summarize or open.",
    };
    var flowOption = new Option<bool>("--flow")
    {
        Description = "Run the report triage console as inline terminal steps.",
    };
    var scanOption = new Option<bool>("--scan")
    {
        Description = "Open the native scan workspace instead of loading an existing report.",
    };
    var tabOption = new Option<int>("--tab", "-t")
    {
        DefaultValueFactory = static _ => 1,
        Description = "Start on a tab by number: 1 Dashboard, 2 Scan, 3 Findings, 4 Rules, 5 Files, or 6 Logs.",
        HelpName = "1-6",
    };
    tabOption.Validators.Add(static result =>
    {
        int value = result.GetValueOrDefault<int>();
        if (value is < 1 or > 6)
        {
            result.AddError("--tab requires a value from 1 through 6.");
        }
    });

    var rootCommand = new RootCommand("Interactive Picket report triage and scan workspace.")
    {
        reportArgument,
        flowOption,
        scanOption,
        tabOption,
    };

    rootCommand.SetAction(parseResult => RunRootCommandActionAsync(
        parseResult,
        reportArgument,
        flowOption,
        scanOption,
        tabOption));

    return rootCommand;
}

static async Task<int> RunRootCommandActionAsync(
    ParseResult parseResult,
    Argument<string?> reportArgument,
    Option<bool> flowOption,
    Option<bool> scanOption,
    Option<int> tabOption)
{
    try
    {
        string? reportPath = parseResult.GetValue(reportArgument);
        bool flow = parseResult.GetValue(flowOption);
        bool scan = parseResult.GetValue(scanOption);
        int initialTab = parseResult.GetValue(tabOption);

        if (scan && flow)
        {
            Console.Error.WriteLine("--scan cannot be combined with --flow");
            return 126;
        }

        if (scan && !string.IsNullOrWhiteSpace(reportPath))
        {
            Console.Error.WriteLine("--scan cannot be combined with a report path");
            return 126;
        }

        if (scan)
        {
            return await PicketTuiRunner.RunScanWorkspaceAsync(initialTab).ConfigureAwait(false);
        }

        if (flow)
        {
            if (!string.IsNullOrWhiteSpace(reportPath) && !TryValidateReportPath(reportPath))
            {
                return 1;
            }

            return await PicketTuiFlowRunner.RunAsync(reportPath, initialTab).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(reportPath))
        {
            return await PicketTuiRunner.RunScanWorkspaceAsync(initialTab).ConfigureAwait(false);
        }

        if (!TryValidateReportPath(reportPath))
        {
            return 1;
        }

        return await PicketTuiRunner.RunAsync(reportPath, initialTab).ConfigureAwait(false);
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

static bool TryValidateReportPath(string reportPath)
{
    if (File.Exists(reportPath))
    {
        return true;
    }

    Console.Error.WriteLine(Directory.Exists(reportPath)
        ? string.Concat("report path is a directory: ", reportPath)
        : string.Concat("report not found: ", reportPath));
    return false;
}

static void RestoreTerminal()
{
    if (Console.IsOutputRedirected)
    {
        return;
    }

    Console.Out.Write("\u001b[?1000l\u001b[?1002l\u001b[?1003l\u001b[?1006l\u001b[?1015l\u001b[?25h\u001b[0m");
}
