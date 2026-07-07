using Picket.Sources;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    static bool IsDockerArchiveFlag(string arg)
    {
        return arg.Equals("--docker-archive", StringComparison.Ordinal)
            || arg.StartsWith("--docker-archive=", StringComparison.Ordinal);
    }

    static bool IsOciArchiveFlag(string arg)
    {
        return arg.Equals("--oci-archive", StringComparison.Ordinal)
            || arg.StartsWith("--oci-archive=", StringComparison.Ordinal);
    }

    static bool TryCreateContainerArchiveSourceProvider(
        string dockerArchivePath,
        string ociArchivePath,
        [NotNullWhen(true)] out NativeSourceProvider? sourceFileProvider)
    {
        sourceFileProvider = null;
        bool dockerArchiveSpecified = !string.IsNullOrWhiteSpace(dockerArchivePath);
        bool ociArchiveSpecified = !string.IsNullOrWhiteSpace(ociArchivePath);
        if (dockerArchiveSpecified == ociArchiveSpecified)
        {
            Console.Error.WriteLine("container archive source scan accepts either --docker-archive or --oci-archive");
            return false;
        }

        string archivePath = dockerArchiveSpecified ? dockerArchivePath : ociArchivePath;
        string displayPrefix = dockerArchiveSpecified ? "docker-archive" : "oci-archive";
        sourceFileProvider = (_, rules, maxTargetBytes, maxArchiveDepth, maxArchiveEntries, maxArchiveBytes, maxArchiveCompressionRatio, timeoutTimestamp) =>
        {
            return ContainerArchiveSource.Enumerate(
                archivePath,
                displayPrefix,
                maxArchiveDepth,
                maxArchiveEntries,
                maxArchiveBytes,
                maxArchiveCompressionRatio,
                maxTargetBytes,
                rules.IsGlobalPathAllowed,
                Console.Error.WriteLine,
                () => IsTimedOut(timeoutTimestamp));
        };

        return true;
    }
}
