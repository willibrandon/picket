using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Enumerates staged index, unstaged working-tree, and untracked non-ignored Git snapshots.
/// </summary>
public static class GitWorkingTreeSource
{
    private const int CopyBufferSize = 64 * 1024;
    private const int MaximumGitPathBytes = 1024 * 1024;
    private const string IndexProvenance = "git-index";
    private const string UntrackedProvenance = "git-untracked";
    private const string WorktreeProvenance = "git-worktree";

    /// <summary>
    /// Enumerates changed Git source snapshots selected by the supplied options.
    /// </summary>
    /// <param name="options">The Git working-tree scan options.</param>
    /// <returns>The source snapshots in deterministic repository-path and state order.</returns>
    public static IReadOnlyList<SourceFile> Enumerate(GitWorkingTreeScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (IsCancellationRequested(options))
        {
            return [];
        }

        (string repositoryRoot, string pathspec) = ResolveSelection(options);
        var files = new List<SourceFile>();
        EnumeratePaths(
            options,
            repositoryRoot,
            ["diff", "--cached", "--name-only", "-z", "--diff-filter=d", "--", pathspec],
            path => AddIndexSnapshot(options, files, repositoryRoot, path));
        EnumeratePaths(
            options,
            repositoryRoot,
            ["diff", "--name-only", "-z", "--diff-filter=d", "--", pathspec],
            path => AddWorktreeSnapshot(options, files, repositoryRoot, path, WorktreeProvenance));
        EnumeratePaths(
            options,
            repositoryRoot,
            options.RespectGitIgnoreFiles
                ? ["ls-files", "--others", "--exclude-standard", "-z", "--", pathspec]
                : ["ls-files", "--others", "-z", "--", pathspec],
            path => AddWorktreeSnapshot(options, files, repositoryRoot, path, UntrackedProvenance));
        files.Sort(CompareFiles);
        return files;
    }

    private static (string RepositoryRoot, string Pathspec) ResolveSelection(GitWorkingTreeScanOptions options)
    {
        bool isFile = File.Exists(options.Root);
        if (!isFile && !Directory.Exists(options.Root))
        {
            throw new DirectoryNotFoundException(options.Root);
        }

        string workingDirectory = isFile
            ? Path.GetDirectoryName(options.Root)!
            : options.Root;
        string repositoryRoot = RunGitText(
            options,
            workingDirectory,
            ["rev-parse", "--show-toplevel"],
            failureMessage: $"path is not inside a Git working tree: {options.Root}").Trim();
        if (repositoryRoot.Length == 0)
        {
            throw new InvalidOperationException($"path is not inside a Git working tree: {options.Root}");
        }

        repositoryRoot = Path.GetFullPath(repositoryRoot);
        if (!IsPathWithinRoot(repositoryRoot, options.Root))
        {
            throw new InvalidOperationException($"selected path is outside the Git working tree: {options.Root}");
        }

        string pathspec = Path.GetRelativePath(repositoryRoot, options.Root)
            .Replace(Path.DirectorySeparatorChar, '/')
            .Replace(Path.AltDirectorySeparatorChar, '/');
        return (repositoryRoot, pathspec);
    }

    private static void EnumeratePaths(
        GitWorkingTreeScanOptions options,
        string repositoryRoot,
        string[] arguments,
        Action<string> pathSink)
    {
        if (IsCancellationRequested(options))
        {
            return;
        }

        using Process process = CreateGitProcess(repositoryRoot, arguments);
        StartGit(process);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        var pathBytes = new ArrayBufferWriter<byte>();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            int read;
            while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (IsCancellationRequested(options))
                {
                    TryKill(process);
                    break;
                }

                for (int index = 0; index < read; index++)
                {
                    byte value = buffer[index];
                    if (value == 0)
                    {
                        EmitPath(pathBytes, pathSink);
                        pathBytes.Clear();
                        continue;
                    }

                    if (pathBytes.WrittenCount >= MaximumGitPathBytes)
                    {
                        TryKill(process);
                        throw new InvalidDataException("Git returned a path longer than the supported one-megabyte limit.");
                    }

                    pathBytes.GetSpan(1)[0] = value;
                    pathBytes.Advance(1);
                }
            }

            if (pathBytes.WrittenCount != 0)
            {
                EmitPath(pathBytes, pathSink);
            }
        }
        catch
        {
            StopGit(process);
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        WaitForGit(options, process, stderrTask);
    }

    private static void EmitPath(ArrayBufferWriter<byte> pathBytes, Action<string> pathSink)
    {
        if (pathBytes.WrittenCount == 0)
        {
            return;
        }

        string path = Encoding.UTF8.GetString(pathBytes.WrittenSpan);
        if (path.Length != 0)
        {
            pathSink(path);
        }
    }

    private static void AddIndexSnapshot(
        GitWorkingTreeScanOptions options,
        List<SourceFile> files,
        string repositoryRoot,
        string displayPath)
    {
        if (ShouldSkipPath(options, displayPath))
        {
            return;
        }

        byte[]? content = ReadIndexBytes(options, repositoryRoot, displayPath);
        if (content is not null)
        {
            AddSnapshot(options, files, repositoryRoot, displayPath, content, IndexProvenance);
        }
    }

    private static void AddWorktreeSnapshot(
        GitWorkingTreeScanOptions options,
        List<SourceFile> files,
        string repositoryRoot,
        string displayPath,
        string provenanceType)
    {
        if (ShouldSkipPath(options, displayPath))
        {
            return;
        }

        string fullPath = CreateContainedFullPath(repositoryRoot, displayPath);
        byte[]? content = ReadWorktreeBytes(options, fullPath, displayPath, provenanceType);
        if (content is not null)
        {
            AddSnapshot(options, files, repositoryRoot, displayPath, content, provenanceType);
        }
    }

    private static byte[]? ReadIndexBytes(
        GitWorkingTreeScanOptions options,
        string repositoryRoot,
        string displayPath)
    {
        using Process process = CreateGitProcess(repositoryRoot, ["show", string.Concat(":", displayPath)]);
        StartGit(process);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        byte[]? content;
        string stderr;
        try
        {
            content = ReadBoundedProcessOutput(options, process, displayPath, IndexProvenance);
            stderr = WaitForGit(options, process, stderrTask, allowNonZeroExit: content is null);
        }
        catch
        {
            StopGit(process);
            throw;
        }

        if (content is null)
        {
            return null;
        }

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(CreateGitFailureMessage(process.ExitCode, stderr));
        }

        return content;
    }

    private static byte[]? ReadWorktreeBytes(
        GitWorkingTreeScanOptions options,
        string fullPath,
        string displayPath,
        string provenanceType)
    {
        if (Directory.Exists(fullPath))
        {
            return null;
        }

        var file = new FileInfo(fullPath);
        file.Refresh();
        if (!file.Exists)
        {
            throw new IOException($"Git source changed while it was being enumerated: {displayPath}");
        }

        string? linkTarget = file.LinkTarget;
        if (linkTarget is not null)
        {
            byte[] linkBytes = Encoding.UTF8.GetBytes(linkTarget);
            if (IsOverTargetLimit(options, linkBytes.LongLength, displayPath, provenanceType))
            {
                return null;
            }

            return linkBytes;
        }

        if (IsOverTargetLimit(options, file.Length, displayPath, provenanceType))
        {
            return null;
        }

        using var stream = new FileStream(fullPath, new FileStreamOptions
        {
            Access = FileAccess.Read,
            BufferSize = CopyBufferSize,
            Mode = FileMode.Open,
            Options = FileOptions.SequentialScan,
            Share = FileShare.Read,
        });
        return ReadBoundedStream(options, stream, displayPath, provenanceType);
    }

    private static byte[]? ReadBoundedProcessOutput(
        GitWorkingTreeScanOptions options,
        Process process,
        string displayPath,
        string provenanceType)
    {
        using var content = new MemoryStream();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            int read;
            while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (IsCancellationRequested(options))
                {
                    TryKill(process);
                    return null;
                }

                if (options.MaxTargetBytes.HasValue
                    && content.Length + read > options.MaxTargetBytes.Value)
                {
                    TryKill(process);
                    WriteTargetLimitWarning(options, displayPath, provenanceType);
                    return null;
                }

                content.Write(buffer, 0, read);
            }

            return content.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static byte[]? ReadBoundedStream(
        GitWorkingTreeScanOptions options,
        Stream stream,
        string displayPath,
        string provenanceType)
    {
        using var content = new MemoryStream();
        byte[] buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (IsCancellationRequested(options))
                {
                    return null;
                }

                if (options.MaxTargetBytes.HasValue
                    && content.Length + read > options.MaxTargetBytes.Value)
                {
                    WriteTargetLimitWarning(options, displayPath, provenanceType);
                    return null;
                }

                content.Write(buffer, 0, read);
            }

            return content.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static void AddSnapshot(
        GitWorkingTreeScanOptions options,
        List<SourceFile> files,
        string repositoryRoot,
        string displayPath,
        byte[] content,
        string provenanceType)
    {
        string fullPath = CreateContainedFullPath(repositoryRoot, displayPath);
        if (ArchiveReader.IsArchiveContent(content))
        {
            if (options.MaxArchiveDepth == 0)
            {
                return;
            }

            var entries = new List<ArchiveEntry>();
            if (ArchiveReader.TryReadBytesEntries(
                content,
                displayPath,
                options.MaxArchiveDepth,
                options.MaxArchiveEntries,
                options.MaxArchiveBytes,
                options.MaxArchiveCompressionRatio,
                options.MaxTargetBytes,
                options.IsPathAllowed,
                options.WarningSink,
                options.IsCancellationRequested,
                entries))
            {
                foreach (ArchiveEntry entry in entries)
                {
                    files.Add(new SourceFile(
                        fullPath,
                        entry.DisplayPath,
                        string.Empty,
                        entry.Content,
                        provenanceType));
                }
            }

            return;
        }

        files.Add(new SourceFile(fullPath, displayPath, string.Empty, content, provenanceType));
    }

    private static bool ShouldSkipPath(GitWorkingTreeScanOptions options, string displayPath)
    {
        return IsCancellationRequested(options)
            || IsPathOrAncestorAllowed(options.IsPathAllowed, displayPath);
    }

    private static bool IsPathOrAncestorAllowed(Func<string, bool>? isPathAllowed, string displayPath)
    {
        if (isPathAllowed is null)
        {
            return false;
        }

        if (isPathAllowed(displayPath))
        {
            return true;
        }

        int separatorIndex = displayPath.Length;
        while ((separatorIndex = displayPath.LastIndexOf('/', separatorIndex - 1)) > 0)
        {
            if (isPathAllowed(displayPath[..separatorIndex]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsOverTargetLimit(
        GitWorkingTreeScanOptions options,
        long length,
        string displayPath,
        string provenanceType)
    {
        if (!options.MaxTargetBytes.HasValue || length <= options.MaxTargetBytes.Value)
        {
            return false;
        }

        WriteTargetLimitWarning(options, displayPath, provenanceType);
        return true;
    }

    private static void WriteTargetLimitWarning(
        GitWorkingTreeScanOptions options,
        string displayPath,
        string provenanceType)
    {
        options.WarningSink?.Invoke(
            $"source byte limit reached while reading {provenanceType} snapshot: {displayPath}");
    }

    private static Process CreateGitProcess(string workingDirectory, string[] arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                WorkingDirectory = workingDirectory,
            },
        };
        process.StartInfo.ArgumentList.Add("--literal-pathspecs");
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        return process;
    }

    private static void StartGit(Process process)
    {
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("could not start Git");
            }
        }
        catch (Win32Exception exception)
        {
            throw new InvalidOperationException("could not start Git", exception);
        }
    }

    private static string RunGitText(
        GitWorkingTreeScanOptions options,
        string workingDirectory,
        string[] arguments,
        string failureMessage)
    {
        using Process process = CreateGitProcess(workingDirectory, arguments);
        StartGit(process);
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        string stderr = WaitForGit(options, process, stderrTask, allowNonZeroExit: true);
        string stdout = stdoutTask.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(stderr.Length == 0 ? failureMessage : $"{failureMessage}: {stderr}");
        }

        return stdout;
    }

    private static string WaitForGit(
        GitWorkingTreeScanOptions options,
        Process process,
        Task<string> stderrTask,
        bool allowNonZeroExit = false)
    {
        if (IsCancellationRequested(options))
        {
            TryKill(process);
        }

        while (!process.WaitForExit(milliseconds: 50))
        {
            if (IsCancellationRequested(options))
            {
                TryKill(process);
            }
        }

        string stderr = stderrTask.GetAwaiter().GetResult().Trim();
        if (!allowNonZeroExit && !IsCancellationRequested(options) && process.ExitCode != 0)
        {
            throw new InvalidOperationException(CreateGitFailureMessage(process.ExitCode, stderr));
        }

        return stderr;
    }

    private static string CreateGitFailureMessage(int exitCode, string stderr)
    {
        return stderr.Length == 0 ? $"Git exited with code {exitCode}" : stderr;
    }

    private static string CreateContainedFullPath(string repositoryRoot, string displayPath)
    {
        string fullPath = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            displayPath.Replace('/', Path.DirectorySeparatorChar)));
        if (!IsPathWithinRoot(repositoryRoot, fullPath))
        {
            throw new InvalidDataException($"Git returned a path outside the working tree: {displayPath}");
        }

        return fullPath;
    }

    private static bool IsPathWithinRoot(string root, string path)
    {
        string normalizedRoot = Path.GetFullPath(root);
        string normalizedPath = Path.GetFullPath(path);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        return normalizedPath.Equals(normalizedRoot, comparison)
            || normalizedPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison);
    }

    private static int CompareFiles(SourceFile left, SourceFile right)
    {
        int pathComparison = StringComparer.Ordinal.Compare(left.DisplayPath, right.DisplayPath);
        if (pathComparison != 0)
        {
            return pathComparison;
        }

        return GetProvenanceOrder(left.ProvenanceType).CompareTo(GetProvenanceOrder(right.ProvenanceType));
    }

    private static int GetProvenanceOrder(string provenanceType)
    {
        return provenanceType switch
        {
            IndexProvenance => 0,
            WorktreeProvenance => 1,
            UntrackedProvenance => 2,
            _ => 3,
        };
    }

    private static bool IsCancellationRequested(GitWorkingTreeScanOptions options)
    {
        return options.IsCancellationRequested is not null && options.IsCancellationRequested();
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or Win32Exception)
        {
        }
    }

    private static void StopGit(Process process)
    {
        TryKill(process);
        try
        {
            process.WaitForExit();
        }
        catch (InvalidOperationException)
        {
        }
    }
}
