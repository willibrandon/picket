using Picket.Engine;

namespace Picket.Store;

internal sealed class RemoteScanCheckpointEntry(
    int ordinal,
    string displayPath,
    string symlinkDisplayPath,
    string blobSha256,
    string recordSha256,
    List<Finding> findings)
{
    internal int Ordinal { get; } = ordinal;

    internal string DisplayPath { get; } = displayPath;

    internal string SymlinkDisplayPath { get; } = symlinkDisplayPath;

    internal string BlobSha256 { get; } = blobSha256;

    internal string RecordSha256 { get; } = recordSha256;

    internal List<Finding> Findings { get; } = findings;
}
