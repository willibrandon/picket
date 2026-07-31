using System.Runtime.InteropServices;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Resolves symbolic links through the native Unix filesystem contract.
/// </summary>
internal static unsafe partial class UnixSymbolicLink
{
    private const int MaxLinkDepth = 64;
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

        string currentPath = Path.GetFullPath(path);
        var visitedPaths = new HashSet<string>(StringComparer.Ordinal);
        for (int depth = 0; depth < MaxLinkDepth; depth++)
        {
            if (!TryReadTarget(currentPath, out string linkTarget))
            {
                targetPath = depth == 0 ? string.Empty : currentPath;
                return depth != 0;
            }

            if (!visitedPaths.Add(currentPath))
            {
                break;
            }

            string? parentPath = Path.GetDirectoryName(currentPath);
            currentPath = Path.GetFullPath(
                Path.IsPathFullyQualified(linkTarget)
                    ? linkTarget
                    : Path.Combine(parentPath ?? Path.DirectorySeparatorChar.ToString(), linkTarget));
        }

        targetPath = string.Empty;
        return false;
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
}
