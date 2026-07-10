using Picket.Tui;

namespace Picket.Tests;

/// <summary>
/// Captures TUI scan requests and writes a deterministic report for tests.
/// </summary>
internal sealed class PicketTuiFakeScanExecutor : IPicketTuiScanExecutor
{
    private static readonly string s_reportJsonLine = string.Concat(
        "{\"ruleId\":\"fake-rule\",",
        "\"file\":\"src/app.cs\",",
        "\"startLine\":7,",
        "\"fingerprint\":\"fake-fingerprint\"}",
        Environment.NewLine);

    private readonly TaskCompletionSource _started = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Gets the arguments captured from the last scan request.
    /// </summary>
    internal List<string> CapturedArguments { get; } = [];

    /// <summary>
    /// Gets the report path captured from the last scan request.
    /// </summary>
    internal string CapturedReportPath { get; private set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether the fake scanner waits until cancellation.
    /// </summary>
    internal bool WaitForCancellation { get; set; }

    /// <summary>
    /// Gets or sets an optional line emitted before the fake scanner completes or waits.
    /// </summary>
    internal string InitialOutputLine { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the fake scanner exit code.
    /// </summary>
    internal int ExitCode { get; set; } = 1;

    /// <summary>
    /// Gets or sets the report content written by the fake scanner.
    /// </summary>
    internal string ReportContent { get; set; } = s_reportJsonLine;

    /// <summary>
    /// Gets or sets the fake scanner standard output.
    /// </summary>
    internal string StandardOutput { get; set; } = "scan complete";

    /// <summary>
    /// Gets or sets the fake scanner standard error.
    /// </summary>
    internal string StandardError { get; set; } = "1 finding";

    /// <summary>
    /// Gets or sets a value indicating whether the fake scanner writes its report.
    /// </summary>
    internal bool WriteReport { get; set; } = true;

    /// <summary>
    /// Gets a task that completes when the fake scanner has started.
    /// </summary>
    internal Task Started => _started.Task;

    /// <inheritdoc />
    public async ValueTask<PicketTuiScanExecutionResult> RunAsync(
        IReadOnlyList<string> arguments,
        string reportPath,
        Action<PicketTuiScanOutputEvent> output,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);

        cancellationToken.ThrowIfCancellationRequested();
        CapturedArguments.Clear();
        CapturedArguments.AddRange(arguments);
        CapturedReportPath = reportPath;
        _started.TrySetResult();
        if (!string.IsNullOrEmpty(InitialOutputLine))
        {
            output(new PicketTuiScanOutputEvent("stdout", InitialOutputLine, DateTimeOffset.UtcNow));
        }

        if (WaitForCancellation)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }

        if (WriteReport)
        {
            File.WriteAllText(reportPath, ReportContent);
        }

        DateTimeOffset timestamp = DateTimeOffset.UtcNow;
        if (StandardOutput.Length != 0)
        {
            output(new PicketTuiScanOutputEvent("stdout", StandardOutput, timestamp));
        }

        if (StandardError.Length != 0)
        {
            output(new PicketTuiScanOutputEvent("stderr", StandardError, timestamp));
        }

        return new PicketTuiScanExecutionResult(
            ExitCode,
            reportPath,
            StandardOutput,
            StandardError,
            timestamp,
            timestamp);
    }
}
