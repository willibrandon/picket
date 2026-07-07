namespace Picket.Tui;

/// <summary>
/// Describes the result of a TUI-initiated scanner process.
/// </summary>
internal sealed class PicketTuiScanExecutionResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiScanExecutionResult" /> class.
    /// </summary>
    /// <param name="exitCode">The scanner process exit code.</param>
    /// <param name="reportPath">The report path requested by the scan workspace.</param>
    /// <param name="standardOutput">The captured standard output.</param>
    /// <param name="standardError">The captured standard error.</param>
    /// <param name="startedAt">The time the scanner process started.</param>
    /// <param name="completedAt">The time the scanner process completed.</param>
    internal PicketTuiScanExecutionResult(
        int exitCode,
        string reportPath,
        string standardOutput,
        string standardError,
        DateTimeOffset startedAt,
        DateTimeOffset completedAt)
    {
        ExitCode = exitCode;
        ReportPath = reportPath;
        StandardOutput = standardOutput;
        StandardError = standardError;
        StartedAt = startedAt;
        CompletedAt = completedAt;
    }

    /// <summary>
    /// Gets the scanner process exit code.
    /// </summary>
    internal int ExitCode { get; }

    /// <summary>
    /// Gets the report path requested by the scan workspace.
    /// </summary>
    internal string ReportPath { get; }

    /// <summary>
    /// Gets the captured standard output.
    /// </summary>
    internal string StandardOutput { get; }

    /// <summary>
    /// Gets the captured standard error.
    /// </summary>
    internal string StandardError { get; }

    /// <summary>
    /// Gets the time the scanner process started.
    /// </summary>
    internal DateTimeOffset StartedAt { get; }

    /// <summary>
    /// Gets the time the scanner process completed.
    /// </summary>
    internal DateTimeOffset CompletedAt { get; }

    /// <summary>
    /// Gets the elapsed scanner process time.
    /// </summary>
    internal TimeSpan Elapsed => CompletedAt - StartedAt;
}
