namespace Picket.Tests;

/// <summary>
/// Tests GitHub Action scanner outcome classification.
/// </summary>
[TestClass]
public sealed class PicketActionFailurePolicyTests
{
    /// <summary>
    /// Verifies that an incomplete scan fails even when a partial report contains findings.
    /// </summary>
    [TestMethod]
    public void EvaluateIncompleteScanWithFindingsFails()
    {
        (bool shouldFail, int failureCode) = PicketActionFailurePolicy.Evaluate("never", 2, 7);

        Assert.IsTrue(shouldFail);
        Assert.AreEqual(2, failureCode);
    }

    /// <summary>
    /// Verifies that a normal finding exit remains subject to the configured failure policy.
    /// </summary>
    [TestMethod]
    public void EvaluateFindingExitHonorsFailurePolicy()
    {
        (bool shouldFail, int failureCode) = PicketActionFailurePolicy.Evaluate("never", 1, 7);

        Assert.IsFalse(shouldFail);
        Assert.AreEqual(0, failureCode);
    }

    /// <summary>
    /// Verifies that a nonzero scanner exit without findings always fails.
    /// </summary>
    [TestMethod]
    public void EvaluateNonzeroExitWithoutFindingsFails()
    {
        (bool shouldFail, int failureCode) = PicketActionFailurePolicy.Evaluate("never", 1, 0);

        Assert.IsTrue(shouldFail);
        Assert.AreEqual(1, failureCode);
    }
}
