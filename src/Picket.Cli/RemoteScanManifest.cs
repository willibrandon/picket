using Picket.Sources;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Picket;

internal static class RemoteScanManifest
{
    private static readonly byte[] s_schema = Encoding.UTF8.GetBytes("picket.remote-source-manifest.v1");

    internal static List<CheckpointSourceFile> CreateFiles(IReadOnlyList<SourceFile> files)
    {
        var checkpointFiles = new List<CheckpointSourceFile>(files.Count);
        for (int i = 0; i < files.Count; i++)
        {
            SourceFile file = files[i];
            checkpointFiles.Add(new CheckpointSourceFile(file, file.ReadAllBytes()));
        }

        checkpointFiles.Sort(CompareFiles);
        return checkpointFiles;
    }

    internal static string CreateFingerprint(IReadOnlyList<CheckpointSourceFile> files)
    {
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(s_schema);
        Span<byte> count = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(count, files.Count);
        hash.AppendData(count);
        for (int i = 0; i < files.Count; i++)
        {
            CheckpointSourceFile file = files[i];
            AppendText(hash, file.SourceFile.DisplayPath);
            AppendText(hash, file.SourceFile.SymlinkDisplayPath);
            AppendText(hash, file.BlobSha256);
        }

        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static int CompareFiles(CheckpointSourceFile left, CheckpointSourceFile right)
    {
        int pathComparison = StringComparer.Ordinal.Compare(left.SourceFile.DisplayPath, right.SourceFile.DisplayPath);
        if (pathComparison != 0)
        {
            return pathComparison;
        }

        int symlinkComparison = StringComparer.Ordinal.Compare(left.SourceFile.SymlinkDisplayPath, right.SourceFile.SymlinkDisplayPath);
        return symlinkComparison != 0
            ? symlinkComparison
            : StringComparer.Ordinal.Compare(left.BlobSha256, right.BlobSha256);
    }

    private static void AppendText(IncrementalHash hash, string value)
    {
        int byteCount = Encoding.UTF8.GetByteCount(value);
        Span<byte> length = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(length, byteCount);
        hash.AppendData(length);
        if (byteCount == 0)
        {
            return;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(value);
        hash.AppendData(bytes);
    }
}
