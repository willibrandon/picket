using Picket.Security;

namespace Picket.Tests;

/// <summary>
/// Tests bounded unexpected-failure diagnostics.
/// </summary>
[TestClass]
public sealed class CrashDiagnosticWriterTests
{
    /// <summary>
    /// Verifies that crash diagnostics identify the exception type without exposing its message or stack trace.
    /// </summary>
    [TestMethod]
    public void WriteOmitsPotentiallySecretExceptionDetails()
    {
        const string Secret = "credential-value-that-must-not-escape";
        using var writer = new StringWriter();
        var exception = new InvalidOperationException(Secret);

        CrashDiagnosticWriter.Write(writer, exception);

        string diagnostic = writer.ToString();
        Assert.Contains(typeof(InvalidOperationException).FullName!, diagnostic);
        Assert.DoesNotContain(Secret, diagnostic);
        Assert.DoesNotContain(nameof(WriteOmitsPotentiallySecretExceptionDetails), diagnostic);
    }
}
