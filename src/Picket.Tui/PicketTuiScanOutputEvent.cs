namespace Picket.Tui;

/// <summary>
/// Describes a single scanner output line observed while a TUI scan is running.
/// </summary>
internal sealed class PicketTuiScanOutputEvent
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PicketTuiScanOutputEvent" /> class.
    /// </summary>
    /// <param name="stream">The output stream name.</param>
    /// <param name="line">The scanner output line.</param>
    /// <param name="timestamp">The time the line was observed.</param>
    internal PicketTuiScanOutputEvent(string stream, string line, DateTimeOffset timestamp)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stream);
        ArgumentNullException.ThrowIfNull(line);

        Stream = stream;
        Line = line;
        Timestamp = timestamp;
    }

    /// <summary>
    /// Gets the output stream name.
    /// </summary>
    internal string Stream { get; }

    /// <summary>
    /// Gets the scanner output line.
    /// </summary>
    internal string Line { get; }

    /// <summary>
    /// Gets the time the line was observed.
    /// </summary>
    internal DateTimeOffset Timestamp { get; }
}
