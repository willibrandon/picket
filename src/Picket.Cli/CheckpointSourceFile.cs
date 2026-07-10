using Picket.Sources;
using Picket.Store;

namespace Picket;

internal sealed class CheckpointSourceFile(SourceFile sourceFile, byte[] content)
{
    internal SourceFile SourceFile { get; } = sourceFile;

    internal byte[] Content { get; } = content;

    internal string BlobSha256 { get; } = BlobHasher.ComputeSha256Hex(content);
}
