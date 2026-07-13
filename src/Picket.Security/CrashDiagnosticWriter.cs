namespace Picket.Security;

/// <summary>
/// Writes bounded crash diagnostics without exposing exception messages or stack traces.
/// </summary>
internal static class CrashDiagnosticWriter
{
    /// <summary>
    /// Writes a non-secret diagnostic for an unexpected exception.
    /// </summary>
    /// <param name="writer">The destination for the diagnostic.</param>
    /// <param name="exception">The unexpected exception.</param>
    internal static void Write(TextWriter writer, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(exception);

        Type exceptionType = exception.GetType();
        writer.Write("unexpected Picket failure (");
        writer.Write(exceptionType.FullName ?? exceptionType.Name);
        writer.WriteLine("); exception details were withheld because scanned data may contain secrets");
    }
}
