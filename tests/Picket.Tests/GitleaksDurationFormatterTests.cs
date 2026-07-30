using Picket.Compat;

namespace Picket.Tests;

/// <summary>
/// Tests the Gitleaks-compatible duration formatting contract.
/// </summary>
[TestClass]
public sealed class GitleaksDurationFormatterTests
{
    /// <summary>
    /// Verifies elapsed durations use Gitleaks magnitude rounding and Go duration units.
    /// </summary>
    /// <param name="ticks">The duration in 100-nanosecond ticks.</param>
    /// <param name="expected">The expected formatted duration.</param>
    [TestMethod]
    [DataRow(0L, "0s")]
    [DataRow(1L, "100ns")]
    [DataRow(1_234L, "123µs")]
    [DataRow(205_400L, "20.5ms")]
    [DataRow(12_350_000L, "1.24s")]
    [DataRow(599_600_000L, "1m0s")]
    [DataRow(691_400_000L, "1m9.1s")]
    [DataRow(999_600_000L, "1m40s")]
    [DataRow(4_184_032_411L, "6m58s")]
    [DataRow(36_000_000_000L, "1h0m0s")]
    [DataRow(900_610_000_000L, "25h1m1s")]
    public void FormatMatchesGitleaks(long ticks, string expected)
    {
        string actual = GitleaksDurationFormatter.Format(TimeSpan.FromTicks(ticks));

        Assert.AreEqual(expected, actual);
    }

    /// <summary>
    /// Verifies negative elapsed durations are rejected.
    /// </summary>
    [TestMethod]
    public void FormatRejectsNegativeDuration()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => GitleaksDurationFormatter.Format(TimeSpan.FromTicks(-1)));
    }
}
