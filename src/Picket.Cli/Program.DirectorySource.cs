using Picket.Sources;

namespace Picket;

internal static partial class Program
{
    static bool TryEnumerateDirectorySource(
        DirectoryScanOptions options,
        out IReadOnlyList<SourceFile> files)
    {
        try
        {
            files = DirectorySource.Enumerate(options);
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"failed to enumerate source: {ex.Message}");
            files = [];
            return false;
        }
    }
}
