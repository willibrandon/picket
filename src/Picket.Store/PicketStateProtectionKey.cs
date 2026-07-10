using Picket.Security;
using System.Security.Cryptography;

namespace Picket.Store;

internal static class PicketStateProtectionKey
{
    private const int KeyByteLength = 32;
    private const string ProductDirectoryName = "Picket";

    internal static byte[] LoadOrCreate(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        string keyPath = GetKeyPath(fileName);
        string? keyDirectory = Path.GetDirectoryName(keyPath);
        if (!string.IsNullOrEmpty(keyDirectory))
        {
            OwnerOnlyFileSystem.CreateDirectory(keyDirectory);
        }

        try
        {
            if (File.Exists(keyPath))
            {
                byte[] existing = File.ReadAllBytes(keyPath);
                if (existing.Length == KeyByteLength)
                {
                    OwnerOnlyFileSystem.ProtectFile(keyPath);
                    return existing;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        byte[] key = RandomNumberGenerator.GetBytes(KeyByteLength);
        string tempPath = CreateTempPath(keyPath);
        try
        {
            using (FileStream stream = OwnerOnlyFileSystem.OpenNewFile(tempPath))
            {
                stream.Write(key);
            }

            try
            {
                File.Move(tempPath, keyPath, overwrite: false);
                OwnerOnlyFileSystem.ProtectFile(keyPath);
                return key;
            }
            catch (IOException)
            {
                byte[] existing = File.ReadAllBytes(keyPath);
                if (existing.Length == KeyByteLength)
                {
                    OwnerOnlyFileSystem.ProtectFile(keyPath);
                    CryptographicOperations.ZeroMemory(key);
                    return existing;
                }

                File.Move(tempPath, keyPath, overwrite: true);
                OwnerOnlyFileSystem.ProtectFile(keyPath);
                return key;
            }
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static string GetKeyPath(string fileName)
    {
        if (!OperatingSystem.IsWindows())
        {
            string? stateHome = Environment.GetEnvironmentVariable("XDG_STATE_HOME");
            if (!string.IsNullOrWhiteSpace(stateHome))
            {
                return Path.Combine(stateHome, "picket", fileName);
            }
        }

        string basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(basePath))
        {
            basePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        if (string.IsNullOrWhiteSpace(basePath))
        {
            basePath = Path.GetTempPath();
        }

        return Path.Combine(basePath, ProductDirectoryName, fileName);
    }

    private static string CreateTempPath(string path)
    {
        return string.Concat(path, ".", Environment.ProcessId, ".", Guid.NewGuid().ToString("N"), ".tmp");
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
