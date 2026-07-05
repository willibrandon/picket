namespace Picket.Tests;

internal sealed class TempDirectory : IDisposable
{
    internal string Path { get; }

    private TempDirectory(string path)
    {
        Path = path;
    }

    internal static TempDirectory Create()
    {
        string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "picket-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return new TempDirectory(path);
    }

    void IDisposable.Dispose()
    {
        if (Directory.Exists(Path))
        {
            NormalizeAttributes(Path);
            Directory.Delete(Path, recursive: true);
        }
    }

    private static void NormalizeAttributes(string path)
    {
        foreach (string file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }

        foreach (string directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(directory, FileAttributes.Directory);
        }

        File.SetAttributes(path, FileAttributes.Directory);
    }
}
