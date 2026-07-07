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
    var rootCommand = new RootCommand("Interactive Picket report triage and scan workspace.")
    {
        reportArgument,
        flowOption,
        scanOption,
    };

    rootCommand.SetAction(async parseResult =>
    {
        string? reportPath = parseResult.GetValue(reportArgument);
        bool flow = parseResult.GetValue(flowOption);
        bool scan = parseResult.GetValue(scanOption);

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
            return await PicketTuiRunner.RunScanWorkspaceAsync().ConfigureAwait(false);
        }

        if (flow)
        {
            return await PicketTuiFlowRunner.RunAsync(reportPath).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(reportPath))
        {
            return await PicketTuiRunner.RunScanWorkspaceAsync().ConfigureAwait(false);
        }

        return await PicketTuiRunner.RunAsync(reportPath).ConfigureAwait(false);
    });

    return rootCommand;
}

static void RestoreTerminal()
{
    if (Console.IsOutputRedirected)
    {
        return;
    }

    Console.Out.Write("\u001b[?1000l\u001b[?1002l\u001b[?1003l\u001b[?1006l\u001b[?1015l\u001b[?25h\u001b[0m");
}
