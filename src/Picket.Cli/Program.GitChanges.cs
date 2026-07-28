using Picket.Sources;

namespace Picket;

internal static partial class Program
{
    static bool IsGitChangesFlag(string argument)
    {
        return argument.Equals("--git-changes", StringComparison.Ordinal)
            || argument.StartsWith("--git-changes=", StringComparison.Ordinal);
    }

    static NativeSourceProvider CreateGitChangesSourceProvider(bool respectGitIgnoreFiles)
    {
        return (
            root,
            rules,
            maxTargetBytes,
            maxArchiveDepth,
            maxArchiveEntries,
            maxArchiveBytes,
            maxArchiveCompressionRatio,
            timeoutTimestamp,
            cancellationToken) =>
        {
            var options = new GitWorkingTreeScanOptions(
                root,
                maxTargetBytes,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                respectGitIgnoreFiles,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsScanStopped(timeoutTimestamp, cancellationToken));
            return [.. GitWorkingTreeSource.Enumerate(options)];
        };
    }
}
