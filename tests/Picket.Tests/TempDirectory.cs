namespace Picket.Tests;

internal sealed class TempDirectory : IDisposable
{
    private const int MaxDeleteAttempts = 5;

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
        DeleteWithRetry(Path);
    }

    private static void DeleteWithRetry(string path)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    NormalizeAttributes(path);
                    Directory.Delete(path, recursive: true);
                }

                return;
            }
            catch (Exception ex) when (attempt < MaxDeleteAttempts && ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(attempt * 50);
            }
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
