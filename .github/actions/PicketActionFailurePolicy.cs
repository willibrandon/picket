/// <summary>
/// Classifies Picket scanner outcomes for the GitHub Action.
/// </summary>
internal static class PicketActionFailurePolicy
{
    /// <summary>
    /// Evaluates whether the action should fail after scanning.
    /// </summary>
    /// <param name="failOn">The configured failure mode.</param>
    /// <param name="scannerExitCode">The scanner exit code.</param>
    /// <param name="findingCount">The number of report findings.</param>
    /// <returns>The failure decision and process exit code.</returns>
    internal static (bool ShouldFail, int FailureCode) Evaluate(string failOn, int scannerExitCode, int findingCount)
    {
        if (scannerExitCode == 2 || (scannerExitCode != 0 && findingCount == 0))
        {
            return (true, scannerExitCode);
        }

        return failOn switch
        {
            "findings" when findingCount > 0 => (true, scannerExitCode != 0 ? scannerExitCode : 1),
            _ => (false, 0),
        };
    }
}
