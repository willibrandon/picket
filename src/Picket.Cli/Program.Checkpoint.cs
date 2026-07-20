using Picket.Engine;
using Picket.Store;
using System.Globalization;

namespace Picket;

internal static partial class Program
{
    private static void CompleteRemoteScanCheckpoint(RemoteScanCheckpoint checkpoint)
    {
        if (!checkpoint.Complete())
        {
            Console.Error.WriteLine($"warning: could not remove completed checkpoint: {checkpoint.Path}");
        }
    }

    private static string CreateRemoteCheckpointScanFingerprint(
        CompiledRuleSet rules,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool ignoreGitleaksAllow)
    {
        string material = string.Create(
            CultureInfo.InvariantCulture,
            $"picket.remote-scan-matching.v3\nmatching-behavior:{SecretScanner.MatchingBehaviorVersion}\nversion:{GetInformationalVersion()}\nrules:{rules.Fingerprint}\ndecode:{maxDecodeDepth}\ntarget:{maxTargetBytes ?? -1}\nignore-gitleaks-allow:{ignoreGitleaksAllow}");
        return BlobHasher.ComputeSha256Hex(material);
    }

    private static bool ReportPathsContainCheckpoint(string? reportPath, List<string> reportPaths, string checkpointPath)
    {
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        string fullCheckpointPath = Path.GetFullPath(checkpointPath);
        if (!string.IsNullOrWhiteSpace(reportPath)
            && !reportPath.Equals("-", StringComparison.Ordinal)
            && Path.GetFullPath(reportPath).Equals(fullCheckpointPath, comparison))
        {
            return true;
        }

        for (int i = 0; i < reportPaths.Count; i++)
        {
            string path = reportPaths[i];
            if (!path.Equals("-", StringComparison.Ordinal)
                && Path.GetFullPath(path).Equals(fullCheckpointPath, comparison))
            {
                return true;
            }
        }

        return false;
    }
}
