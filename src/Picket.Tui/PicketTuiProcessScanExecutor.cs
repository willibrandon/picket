using System.Diagnostics;
using System.Text;

namespace Picket.Tui;

/// <summary>
/// Executes TUI scans by invoking the installed `picket` scanner executable.
/// </summary>
internal sealed class PicketTuiProcessScanExecutor : IPicketTuiScanExecutor
{
    private static readonly string[] s_defaultWindowsCommandExtensions = [string.Empty, ".exe", ".cmd", ".bat", ".com"];
    private static readonly string[] s_emptyCommandExtensions = [string.Empty];
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
        return new PicketTuiProcessScanExecutor(ResolvePicketPath(), s_emptyPrefixArguments);
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
        if (!Path.IsPathFullyQualified(_executablePath) || !File.Exists(_executablePath))
        {
            throw new FileNotFoundException(
                "Picket scanner was not found. Install picket, place it beside picket-tui, or set PICKET_SCANNER to its full path.");
        }

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

    /// <summary>
    /// Resolves the scanner from an explicit setting, the TUI installation directory, or absolute PATH entries.
    /// </summary>
    /// <returns>The absolute scanner path or the expected side-by-side path when no scanner is installed.</returns>
    internal static string ResolvePicketPath()
    {
        string executableName = OperatingSystem.IsWindows() ? "picket.exe" : "picket";
        string? configuredPath = Environment.GetEnvironmentVariable("PICKET_SCANNER");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            if (Path.IsPathFullyQualified(configuredPath) && File.Exists(configuredPath))
            {
                return Path.GetFullPath(configuredPath);
            }

            if (TryFindCommandOnPath(configuredPath, out string resolvedConfiguredPath))
            {
                return resolvedConfiguredPath;
            }
        }

        string besideTui = Path.Combine(AppContext.BaseDirectory, executableName);
        if (File.Exists(besideTui))
        {
            return besideTui;
        }

        if (TryFindCommandOnPath(executableName, out string resolvedPath))
        {
            return resolvedPath;
        }

        return besideTui;
    }

    private static bool TryFindCommandOnPath(string command, out string resolvedPath)
    {
        if (Path.IsPathFullyQualified(command))
        {
            if (File.Exists(command))
            {
                resolvedPath = Path.GetFullPath(command);
                return true;
            }

            resolvedPath = string.Empty;
            return false;
        }

        if (command.Contains(Path.DirectorySeparatorChar)
            || command.Contains(Path.AltDirectorySeparatorChar))
        {
            resolvedPath = string.Empty;
            return false;
        }

        string? pathEnvironment = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnvironment))
        {
            resolvedPath = string.Empty;
            return false;
        }

        string[] extensions = OperatingSystem.IsWindows()
            ? GetWindowsCommandExtensions()
            : s_emptyCommandExtensions;
        string[] directories = pathEnvironment.Split(
            Path.PathSeparator,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (int i = 0; i < directories.Length; i++)
        {
            string directory = directories[i].Trim('"');
            if (!Path.IsPathFullyQualified(directory))
            {
                continue;
            }

            for (int j = 0; j < extensions.Length; j++)
            {
                string candidate = Path.Combine(directory, string.Concat(command, extensions[j]));
                if (File.Exists(candidate))
                {
                    resolvedPath = Path.GetFullPath(candidate);
                    return true;
                }
            }
        }

        resolvedPath = string.Empty;
        return false;
    }

    private static string[] GetWindowsCommandExtensions()
    {
        string? pathExtensions = Environment.GetEnvironmentVariable("PATHEXT");
        return string.IsNullOrWhiteSpace(pathExtensions)
            ? s_defaultWindowsCommandExtensions
            : pathExtensions.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
