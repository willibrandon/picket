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
            Directory.Delete(Path, recursive: true);
        }
    }
}
