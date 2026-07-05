namespace Picket.Sources;

internal sealed class ArchiveEntry(string displayPath, byte[] content)
{
    internal string DisplayPath { get; } = displayPath;

    internal byte[] Content { get; } = content;
}
