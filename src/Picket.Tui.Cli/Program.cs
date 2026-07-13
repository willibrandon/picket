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
    var rootCommand = new RootCommand("Interactive Picket report triage and scan workspace.")
    {
        reportArgument,
        flowOption,
        scanOption,
    };

    rootCommand.SetAction(parseResult => RunRootCommandActionAsync(parseResult, reportArgument, flowOption, scanOption));

    return rootCommand;
}

static async Task<int> RunRootCommandActionAsync(
    ParseResult parseResult,
    Argument<string?> reportArgument,
    Option<bool> flowOption,
    Option<bool> scanOption)
{
    try
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
            if (!string.IsNullOrWhiteSpace(reportPath) && !TryValidateReportPath(reportPath))
            {
                return 1;
            }

            return await PicketTuiFlowRunner.RunAsync(reportPath).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(reportPath))
        {
            return await PicketTuiRunner.RunScanWorkspaceAsync().ConfigureAwait(false);
        }

        if (!TryValidateReportPath(reportPath))
        {
            return 1;
        }

        return await PicketTuiRunner.RunAsync(reportPath).ConfigureAwait(false);
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
