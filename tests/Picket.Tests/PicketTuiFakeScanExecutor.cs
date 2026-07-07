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

        File.WriteAllText(reportPath, s_reportJsonLine);
        DateTimeOffset timestamp = DateTimeOffset.UtcNow;
        output(new PicketTuiScanOutputEvent("stdout", "scan complete", timestamp));
        output(new PicketTuiScanOutputEvent("stderr", "1 finding", timestamp));
        return new PicketTuiScanExecutionResult(
            1,
            reportPath,
            "scan complete",
            "1 finding",
            timestamp,
            timestamp);
    }
}
