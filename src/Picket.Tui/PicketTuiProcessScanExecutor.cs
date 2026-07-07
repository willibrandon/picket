using System.Diagnostics;
using System.Text;

namespace Picket.Tui;

/// <summary>
/// Executes TUI scans by invoking the installed `picket` scanner executable.
/// </summary>
internal sealed class PicketTuiProcessScanExecutor : IPicketTuiScanExecutor
{
    private static readonly string[] s_emptyPrefixArguments = [];
    private readonly string _executablePath;
    private readonly string[] _prefixArguments;

    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiProcessScanExecutor" /> class.
    /// </summary>
    /// <param name="executablePath">The `picket` executable path or command name.</param>
    internal PicketTuiProcessScanExecutor(string executablePath)
        : this(executablePath, s_emptyPrefixArguments)
    {
    }

    private PicketTuiProcessScanExecutor(string executablePath, string[] prefixArguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(prefixArguments);

        _executablePath = executablePath;
        _prefixArguments = prefixArguments;
    }

    /// <summary>
    /// Creates an executor that resolves `picket` beside `picket-tui` or on PATH.
    /// </summary>
    /// <returns>The process-backed scan executor.</returns>
    internal static PicketTuiProcessScanExecutor CreateDefault()
    {
        string executablePath = ResolvePicketPath(out string[] prefixArguments);
        return new PicketTuiProcessScanExecutor(executablePath, prefixArguments);
    }

    /// <inheritdoc />
    public async ValueTask<PicketTuiScanExecutionResult> RunAsync(
        IReadOnlyList<string> arguments,
        string reportPath,
        Action<PicketTuiScanOutputEvent> output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        ArgumentNullException.ThrowIfNull(output);

        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(_executablePath)
        {
            RedirectStandardError = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        for (int i = 0; i < _prefixArguments.Length; i++)
        {
            process.StartInfo.ArgumentList.Add(_prefixArguments[i]);
        }

        for (int i = 0; i < arguments.Count; i++)
        {
            process.StartInfo.ArgumentList.Add(arguments[i]);
        }

        if (!process.Start())
        {
            throw new InvalidOperationException("could not start picket");
        }

        process.StandardInput.Close();

        using CancellationTokenRegistration registration = cancellationToken.Register(static state =>
        {
            var runningProcess = (Process)state!;
            try
            {
                if (!runningProcess.HasExited)
                {
                    runningProcess.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }
        }, process);

        var standardOutput = new StringBuilder();
        var standardError = new StringBuilder();
        Task standardOutputTask = ReadStreamAsync(process.StandardOutput, "stdout", standardOutput, output, cancellationToken);
        Task standardErrorTask = ReadStreamAsync(process.StandardError, "stderr", standardError, output, cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        await standardOutputTask.ConfigureAwait(false);
        await standardErrorTask.ConfigureAwait(false);
        DateTimeOffset completedAt = DateTimeOffset.UtcNow;

        return new PicketTuiScanExecutionResult(
            process.ExitCode,
            reportPath,
            standardOutput.ToString(),
            standardError.ToString(),
            startedAt,
            completedAt);
    }

    private static async Task ReadStreamAsync(
        StreamReader reader,
        string stream,
        StringBuilder builder,
        Action<PicketTuiScanOutputEvent> output,
        CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            builder.AppendLine(line);
            if (!string.IsNullOrWhiteSpace(line))
            {
                output(new PicketTuiScanOutputEvent(stream, line, DateTimeOffset.UtcNow));
            }
        }
    }

    private static string ResolvePicketPath(out string[] prefixArguments)
    {
        prefixArguments = s_emptyPrefixArguments;
        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string besideTui = Path.Combine(AppContext.BaseDirectory, executableName);
        if (File.Exists(besideTui))
        {
            return besideTui;
        }

        string? developmentProject = FindDevelopmentPicketProject(Directory.GetCurrentDirectory())
            ?? FindDevelopmentPicketProject(AppContext.BaseDirectory);
        if (developmentProject is not null)
        {
            prefixArguments = ["run", "--project", developmentProject, "--"];
            return "dotnet";
        }

        return executableName;
    }

    private static string? FindDevelopmentPicketProject(string startDirectory)
    {
        var directory = new DirectoryInfo(startDirectory);
        while (directory is not null)
        {
            string projectPath = Path.Combine(directory.FullName, "src", "Picket.Cli", "Picket.Cli.csproj");
            if (File.Exists(projectPath))
            {
                return projectPath;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
