using Picket.Security;
using System.Security.Cryptography;

namespace Picket.Store;

internal static class PicketStateProtectionKey
{
    private const int FileOperationRetryCount = 200;
    private const int FileOperationRetryDelayMilliseconds = 25;
    private const int KeyByteLength = 32;
    private const string LockSuffix = ".lock";
    private const string ProductDirectoryName = "Picket";

    internal static byte[] LoadOrCreate(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        return LoadOrCreatePath(GetKeyPath(fileName));
    }

    internal static byte[] LoadOrCreatePath(string keyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyPath);

        string fullKeyPath = Path.GetFullPath(keyPath);
        byte[]? existing = TryReadKey(fullKeyPath);
        if (existing is not null)
        {
            OwnerOnlyFileSystem.ProtectFile(fullKeyPath);
            return existing;
        }

        string? keyDirectory = Path.GetDirectoryName(fullKeyPath);
        if (!string.IsNullOrEmpty(keyDirectory))
        {
            OwnerOnlyFileSystem.CreateDirectory(keyDirectory);
        }

        string lockPath = string.Concat(fullKeyPath, LockSuffix);
        using FileStream _ = OpenLock(lockPath);
        OwnerOnlyFileSystem.ProtectFile(lockPath);

        existing = TryReadKey(fullKeyPath);
        if (existing is not null)
        {
            OwnerOnlyFileSystem.ProtectFile(fullKeyPath);
            return existing;
        }

        return CreateKey(fullKeyPath);
    }

    private static byte[] CreateKey(string keyPath)
    {
        byte[] key = RandomNumberGenerator.GetBytes(KeyByteLength);
        string tempPath = CreateTempPath(keyPath);
        try
        {
            using (FileStream stream = OwnerOnlyFileSystem.OpenNewFile(tempPath))
            {
                stream.Write(key);
                stream.Flush(flushToDisk: true);
            }

            MoveIntoPlace(tempPath, keyPath);
            OwnerOnlyFileSystem.ProtectFile(keyPath);
            return key;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static FileStream OpenLock(string lockPath)
    {
        IOException? lastException = null;
        for (int attempt = 0; attempt < FileOperationRetryCount; attempt++)
        {
            try
            {
                return OwnerOnlyFileSystem.OpenFile(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            }
            catch (IOException exception)
            {
                lastException = exception;
                Thread.Sleep(FileOperationRetryDelayMilliseconds);
            }
        }

        throw new IOException("Timed out while acquiring the state-protection key lock.", lastException);
    }

    private static byte[]? TryReadKey(string keyPath)
    {
        string? keyDirectory = Path.GetDirectoryName(keyPath);
        if (!string.IsNullOrEmpty(keyDirectory) && !Directory.Exists(keyDirectory))
        {
            return null;
        }

        try
        {
            if (!File.Exists(keyPath))
            {
                return null;
            }

            using FileStream stream = OpenKeyForRead(keyPath);
            if (stream.Length != KeyByteLength)
            {
                return null;
            }

            byte[] existing = GC.AllocateUninitializedArray<byte>(KeyByteLength);
            try
            {
                stream.ReadExactly(existing);
                return existing;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(existing);
                throw;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }

        return null;
    }

    private static FileStream OpenKeyForRead(string keyPath)
    {
        var options = new FileStreamOptions
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Share = FileShare.Read | FileShare.Delete,
            Options = FileOptions.SequentialScan,
        };
        return new FileStream(keyPath, options);
    }

    private static void MoveIntoPlace(string tempPath, string keyPath)
    {
        Exception? lastException = null;
        for (int attempt = 0; attempt < FileOperationRetryCount; attempt++)
        {
            try
            {
                File.Move(tempPath, keyPath, overwrite: true);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                lastException = exception;
                Thread.Sleep(FileOperationRetryDelayMilliseconds);
            }
        }

        throw new IOException("Timed out while replacing the state-protection key.", lastException);
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
