namespace Picket.Sources;

/// <summary>
/// Removes provider-controlled archive paths from source diagnostics.
/// </summary>
internal static class SourceDiagnosticRedactor
{
    private const string ArchivePathMarker = " while reading ";

    /// <summary>
    /// Creates an archive warning sink that substitutes a fixed diagnostic target for provider-controlled paths.
    /// </summary>
    /// <param name="warningSink">The destination warning sink.</param>
    /// <param name="diagnosticTarget">The fixed target description safe for diagnostics.</param>
    /// <returns>The redacting warning sink, or <see langword="null" /> when no destination was supplied.</returns>
    internal static Action<string>? CreateArchiveWarningSink(
        Action<string>? warningSink,
        string diagnosticTarget)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(diagnosticTarget);

        return warningSink is null
            ? null
            : warning => warningSink(RedactArchiveWarning(warning, diagnosticTarget));
    }

    private static string RedactArchiveWarning(string warning, string diagnosticTarget)
    {
        ArgumentNullException.ThrowIfNull(warning);

        int markerIndex = warning.IndexOf(ArchivePathMarker, StringComparison.Ordinal);
        return markerIndex < 0
            ? string.Concat(diagnosticTarget, ": archive processing warning")
            : string.Concat(warning.AsSpan(0, markerIndex), ArchivePathMarker, diagnosticTarget);
    }
}
