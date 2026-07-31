using System.Runtime.InteropServices;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Resolves symbolic links through the native Unix filesystem contract.
/// </summary>
internal static unsafe partial class UnixSymbolicLink
{
    private const int ReadLinkBufferSize = 4096;

    /// <summary>
    /// Tries to resolve a Unix symbolic link to its final target.
    /// </summary>
    /// <param name="path">The symbolic link path.</param>
    /// <param name="targetPath">Receives the fully qualified final target path.</param>
    /// <returns><see langword="true" /> when <paramref name="path" /> is a resolvable symbolic link.</returns>
    internal static bool TryResolveFinalTarget(string path, out string targetPath)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            targetPath = string.Empty;
            return false;
        }

        string fullPath = Path.GetFullPath(path);
        if (!TryReadTarget(fullPath, out _))
        {
            targetPath = string.Empty;
            return false;
        }

        return TryCanonicalizeExistingPath(fullPath, out targetPath);
    }

    /// <summary>
    /// Tries to resolve every symbolic-link component in an existing Unix path.
    /// </summary>
    /// <param name="path">The existing file or directory path.</param>
    /// <param name="canonicalPath">Receives the canonical fully qualified path.</param>
    /// <returns><see langword="true" /> when the path can be canonicalized.</returns>
    internal static bool TryCanonicalizeExistingPath(string path, out string canonicalPath)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            canonicalPath = string.Empty;
            return false;
        }

        nint resolvedPath = RealPath(Path.GetFullPath(path), 0);
        if (resolvedPath == 0)
        {
            canonicalPath = string.Empty;
            return false;
        }

        try
        {
            canonicalPath = Marshal.PtrToStringUTF8(resolvedPath) ?? string.Empty;
            return canonicalPath.Length != 0;
        }
        finally
        {
            Free(resolvedPath);
        }
    }

    private static bool TryReadTarget(string path, out string target)
    {
        byte* buffer = stackalloc byte[ReadLinkBufferSize];
        nint length = ReadLink(path, buffer, ReadLinkBufferSize);
        if (length < 0 || length >= ReadLinkBufferSize)
        {
            target = string.Empty;
            return false;
        }

        target = Encoding.UTF8.GetString(new ReadOnlySpan<byte>(buffer, (int)length));
        return true;
    }

    [LibraryImport(
        "libc",
        EntryPoint = "readlink",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint ReadLink(string path, byte* buffer, nuint bufferLength);

    [LibraryImport(
        "libc",
        EntryPoint = "realpath",
        SetLastError = true,
        StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint RealPath(string path, nint resolvedPath);

    [LibraryImport("libc", EntryPoint = "free")]
    private static partial void Free(nint pointer);
}
