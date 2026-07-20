using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Picket.Sources;

/// <summary>
/// Enumerates git patch fragments for compatibility-mode scans.
/// </summary>
public static class GitSource
{
    /// <summary>
    /// Enumerates added git patch fragments selected by the supplied options.
    /// </summary>
    /// <param name="options">The git scan options.</param>
    /// <returns>The added patch fragments in git output order.</returns>
    public static IReadOnlyList<GitPatchFragment> Enumerate(GitScanOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        using Process process = CreateGitProcess(options);
        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("could not start git");
            }
        }
        catch (Win32Exception exception)
        {
            throw new InvalidOperationException("could not start git", exception);
        }

        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        List<GitPatchFragment> fragments = ParsePatch(process.StandardOutput.BaseStream, options);
        bool cancelled = IsCancellationRequested(options);
        if (cancelled)
        {
            TryKill(process);
        }

        process.WaitForExit();
        string stderr = stderrTask.GetAwaiter().GetResult().Trim();
        if (!cancelled && process.ExitCode != 0)
        {
            throw new InvalidOperationException(stderr.Length == 0 ? $"git exited with code {process.ExitCode}" : stderr);
        }

        return fragments;
    }

    private static Process CreateGitProcess(GitScanOptions options)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                StandardErrorEncoding = Encoding.UTF8,
                UseShellExecute = false,
            },
        };

        if (options.Staged || options.PreCommit)
        {
            AddArguments(process.StartInfo, "-C", options.Root, "diff", "-U0", "--no-ext-diff");
            if (options.Staged)
            {
                process.StartInfo.ArgumentList.Add("--staged");
            }

            process.StartInfo.ArgumentList.Add(".");
            return process;
        }

        AddArguments(process.StartInfo, "-C", options.Root, "log", "-p", "-U0", "--date=iso-strict", "--no-ext-diff");
        if (options.LogOptions.Length == 0)
        {
            AddArguments(process.StartInfo, "--full-history", "--all", "--diff-filter=tuxdb");
            return process;
        }

        foreach (string argument in options.LogOptions.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!IsSafeLogOptionArgument(argument))
            {
                throw new InvalidOperationException($"unsafe git log option: {argument}");
            }

            process.StartInfo.ArgumentList.Add(argument);
        }

        return process;
    }

    private static bool IsSafeLogOptionArgument(string argument)
    {
        if (!argument.StartsWith('-'))
        {
            return true;
        }

        if (argument is "--all"
            or "--branches"
            or "--tags"
            or "--remotes"
            or "--full-history"
            or "--first-parent"
            or "--ancestry-path"
            or "--no-merges"
            or "--merges"
            or "--regexp-ignore-case"
            or "--fixed-strings"
            or "--extended-regexp")
        {
            return true;
        }

        if (argument is "--since"
            or "--after"
            or "--until"
            or "--before"
            or "--author"
            or "--committer"
            or "--grep"
            or "--max-count"
            or "--skip"
            or "--diff-filter")
        {
            return true;
        }

        if (argument.StartsWith("--branches=", StringComparison.Ordinal)
            || argument.StartsWith("--tags=", StringComparison.Ordinal)
            || argument.StartsWith("--remotes=", StringComparison.Ordinal)
            || argument.StartsWith("--since=", StringComparison.Ordinal)
            || argument.StartsWith("--after=", StringComparison.Ordinal)
            || argument.StartsWith("--until=", StringComparison.Ordinal)
            || argument.StartsWith("--before=", StringComparison.Ordinal)
            || argument.StartsWith("--author=", StringComparison.Ordinal)
            || argument.StartsWith("--committer=", StringComparison.Ordinal)
            || argument.StartsWith("--grep=", StringComparison.Ordinal)
            || argument.StartsWith("--max-count=", StringComparison.Ordinal)
            || argument.StartsWith("--skip=", StringComparison.Ordinal)
            || argument.StartsWith("--diff-filter=", StringComparison.Ordinal))
        {
            return true;
        }

        return IsSafeShortMaxCountOption(argument);
    }

    private static bool IsSafeShortMaxCountOption(string argument)
    {
        if (argument.Equals("-n", StringComparison.Ordinal))
        {
            return true;
        }

        if (!argument.StartsWith("-n", StringComparison.Ordinal) || argument.Length == 2)
        {
            return false;
        }

        for (int i = 2; i < argument.Length; i++)
        {
            if (!char.IsDigit(argument[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static void AddArguments(ProcessStartInfo startInfo, params string[] arguments)
    {
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    /// <summary>
    /// Parses raw git patch output into scan fragments.
    /// </summary>
    /// <param name="stream">The raw git patch stream.</param>
    /// <param name="options">The active git scan options.</param>
    /// <returns>The parsed added-line fragments.</returns>
    internal static List<GitPatchFragment> ParsePatch(Stream stream, GitScanOptions options)
    {
        using var reader = new GitPatchLineReader(stream, () => IsCancellationRequested(options));
        var fragments = new List<GitPatchFragment>();
        string commit = string.Empty;
        string author = string.Empty;
        string email = string.Empty;
        string date = string.Empty;
        string message = string.Empty;
        string? diffFilePath = null;
        string? filePath = null;
        int hunkStartLine = 0;
        var messageLines = new List<string>();
        var addedBytes = new ArrayBufferWriter<byte>();
        bool hasAddedLines = false;
        bool readingMessage = false;
        bool diffBinaryProcessed = false;
        bool diffDeleted = false;

        byte[]? rawLine;
        while ((rawLine = reader.ReadLine()) is not null)
        {
            if (IsCancellationRequested(options))
            {
                break;
            }

            ReadOnlySpan<byte> line = TrimLineEnding(rawLine);
            if (line.StartsWith("commit "u8))
            {
                FlushFragment();
                commit = DecodeText(line["commit ".Length..]).Trim();
                author = string.Empty;
                email = string.Empty;
                date = string.Empty;
                message = string.Empty;
                diffFilePath = null;
                filePath = null;
                hunkStartLine = 0;
                messageLines.Clear();
                readingMessage = false;
                diffBinaryProcessed = false;
                diffDeleted = false;
                continue;
            }

            if (line.StartsWith("Author: "u8))
            {
                (author, email) = ParseAuthor(DecodeText(line["Author: ".Length..]));
                continue;
            }

            if (line.StartsWith("Date: "u8))
            {
                date = FormatGitDate(DecodeText(line["Date: ".Length..]).Trim());
                readingMessage = true;
                continue;
            }

            if (line.StartsWith("diff --git "u8))
            {
                FlushFragment();
                message = CreateMessage(messageLines);
                readingMessage = false;
                diffFilePath = ParseDiffNewFilePath(DecodeText(line));
                filePath = null;
                hunkStartLine = 0;
                diffBinaryProcessed = false;
                diffDeleted = false;
                continue;
            }

            if (line.StartsWith("deleted file mode "u8))
            {
                diffDeleted = true;
                continue;
            }

            if (readingMessage)
            {
                if (line.IsEmpty)
                {
                    continue;
                }

                if (line.StartsWith("    "u8))
                {
                    messageLines.Add(DecodeText(line[4..]));
                    continue;
                }
            }

            if (hunkStartLine == 0 && line.StartsWith("+++ "u8))
            {
                FlushFragment();
                filePath = ParseNewFilePath(DecodeText(line));
                diffFilePath = filePath ?? diffFilePath;
                hunkStartLine = 0;
                continue;
            }

            if (IsBinaryDiffLine(line))
            {
                if (!diffDeleted && !diffBinaryProcessed && diffFilePath is not null)
                {
                    AddArchiveFragments(options, fragments, diffFilePath, commit, author, email, date, message);
                    diffBinaryProcessed = true;
                }

                continue;
            }

            if (line.StartsWith("@@ "u8))
            {
                FlushFragment();
                hunkStartLine = ParseNewStartLineBytes(line);
                continue;
            }

            if (hunkStartLine != 0 && filePath is not null && line.Length != 0 && line[0] == (byte)'+')
            {
                ReadOnlySpan<byte> addedLine = rawLine.AsSpan(1);
                addedLine.CopyTo(addedBytes.GetSpan(addedLine.Length));
                addedBytes.Advance(addedLine.Length);
                hasAddedLines = true;
            }
        }

        FlushFragment();
        return fragments;

        void FlushFragment()
        {
            if (filePath is null || hunkStartLine == 0 || !hasAddedLines)
            {
                addedBytes.Clear();
                hasAddedLines = false;
                return;
            }

            fragments.Add(new GitPatchFragment(
                addedBytes.WrittenSpan.ToArray(),
                filePath,
                hunkStartLine,
                commit,
                author,
                email,
                date,
                message));
            addedBytes.Clear();
            hasAddedLines = false;
        }
    }

    private static void AddArchiveFragments(
        GitScanOptions options,
        List<GitPatchFragment> fragments,
        string filePath,
        string commit,
        string author,
        string email,
        string date,
        string message)
    {
        if (options.MaxArchiveDepth == 0)
        {
            return;
        }

        if (IsCancellationRequested(options))
        {
            return;
        }

        if (!options.IdentifyArchivesByContent && !ArchiveReader.IsArchivePath(filePath))
        {
            return;
        }

        byte[]? blob = ReadGitBlob(options, commit, filePath);
        if (blob is null || !ArchiveReader.IsArchiveContent(blob))
        {
            return;
        }

        var entries = new List<ArchiveEntry>();
        if (!ArchiveReader.TryReadBytesEntries(
            blob,
            filePath,
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
            return;
        }

        foreach (ArchiveEntry entry in entries)
        {
            fragments.Add(new GitPatchFragment(
                entry.Content,
                entry.DisplayPath,
                1,
                commit,
                author,
                email,
                date,
                message));
        }
    }

    private static byte[]? ReadGitBlob(GitScanOptions options, string commit, string filePath)
    {
        if (commit.Length == 0 && options.PreCommit && !options.Staged)
        {
            return ReadWorktreeBlob(options.Root, filePath);
        }

        string revision = commit.Length == 0 ? $":{filePath}" : $"{commit}:{filePath}";
        using Process process = CreateGitShowProcess(options.Root, revision);
        try
        {
            if (!process.Start())
            {
                return null;
            }
        }
        catch (Win32Exception)
        {
            return null;
        }

        Task<string> stderrTask = process.StandardError.ReadToEndAsync();
        using var stream = new MemoryStream();
        byte[] buffer = new byte[81920];
        int read;
        while ((read = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) != 0)
        {
            if (IsCancellationRequested(options))
            {
                TryKill(process);
                break;
            }

            stream.Write(buffer, 0, read);
        }

        if (IsCancellationRequested(options))
        {
            TryKill(process);
        }

        process.WaitForExit();
        _ = stderrTask.GetAwaiter().GetResult();
        return process.ExitCode == 0 && !IsCancellationRequested(options) ? stream.ToArray() : null;
    }

    private static Process CreateGitShowProcess(string root, string revision)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("git")
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            },
        };
        AddArguments(process.StartInfo, "-C", root, "show", revision);
        return process;
    }

    private static byte[]? ReadWorktreeBlob(string root, string filePath)
    {
        string path = Path.GetFullPath(Path.Combine(root, filePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!IsPathWithinRoot(root, path) || !File.Exists(path))
        {
            return null;
        }

        return File.ReadAllBytes(path);
    }

    private static bool IsPathWithinRoot(string root, string path)
    {
        string normalizedRoot = Path.GetFullPath(root);
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return path.Equals(normalizedRoot, comparison)
            || path.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, comparison);
    }

    private static bool IsCancellationRequested(GitScanOptions options)
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
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
        {
        }
    }

    private static (string Author, string Email) ParseAuthor(string value)
    {
        int emailStart = value.LastIndexOf(" <", StringComparison.Ordinal);
        if (emailStart < 0 || !value.EndsWith('>'))
        {
            return (value.Trim(), string.Empty);
        }

        string author = value[..emailStart].Trim();
        string email = value[(emailStart + 2)..^1].Trim();
        return (author, email);
    }

    private static string FormatGitDate(string value)
    {
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces,
            out DateTimeOffset date)
            ? date.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
            : value;
    }

    private static string CreateMessage(List<string> messageLines)
    {
        return messageLines.Count == 0 ? string.Empty : string.Join("\n", messageLines).TrimEnd();
    }

    private static string? ParseNewFilePath(string line)
    {
        string path = ParseGitPath(line.AsSpan("+++ ".Length));
        if (path.Equals("/dev/null", StringComparison.Ordinal))
        {
            return null;
        }

        return path.StartsWith("b/", StringComparison.Ordinal) ? path[2..] : path;
    }

    private static string? ParseDiffNewFilePath(string line)
    {
        ReadOnlySpan<char> text = line.AsSpan("diff --git ".Length);
        if (!text.IsEmpty && text[0] == '"')
        {
            if (!TryParseQuotedGitPath(text, out _, out int firstPathLength))
            {
                return null;
            }

            text = text[firstPathLength..].TrimStart();
            if (!TryParseQuotedGitPath(text, out string? quotedPath, out _))
            {
                return null;
            }

            return quotedPath.StartsWith("b/", StringComparison.Ordinal) ? quotedPath[2..] : quotedPath;
        }

        int newPathIndex = text.IndexOf(" b/", StringComparison.Ordinal);
        if (newPathIndex < 0)
        {
            return null;
        }

        return text[(newPathIndex + 3)..].Trim().ToString();
    }

    private static bool IsBinaryDiffLine(ReadOnlySpan<byte> line)
    {
        return line.StartsWith("Binary files "u8)
            || line.SequenceEqual("GIT binary patch"u8);
    }

    private static int ParseNewStartLine(string line)
    {
        return ParseNewStartLineBytes(Encoding.UTF8.GetBytes(line));
    }

    private static int ParseNewStartLineBytes(ReadOnlySpan<byte> line)
    {
        int plusIndex = line.IndexOf((byte)'+');
        if (plusIndex < 0)
        {
            return 0;
        }

        int start = plusIndex + 1;
        int end = start;
        while (end < line.Length && line[end] is >= (byte)'0' and <= (byte)'9')
        {
            end++;
        }

        return end != start && int.TryParse(Encoding.ASCII.GetString(line[start..end]), CultureInfo.InvariantCulture, out int startLine)
            ? startLine
            : 0;
    }

    private static ReadOnlySpan<byte> TrimLineEnding(ReadOnlySpan<byte> line)
    {
        if (!line.IsEmpty && line[^1] == (byte)'\n')
        {
            line = line[..^1];
        }

        return !line.IsEmpty && line[^1] == (byte)'\r' ? line[..^1] : line;
    }

    private static string DecodeText(ReadOnlySpan<byte> value)
    {
        return Encoding.UTF8.GetString(value);
    }

    private static string ParseGitPath(ReadOnlySpan<char> value)
    {
        value = value.Trim();
        return !value.IsEmpty && value[0] == '"' && TryParseQuotedGitPath(value, out string? path, out _)
            ? path
            : value.ToString();
    }

    private static bool TryParseQuotedGitPath(ReadOnlySpan<char> value, out string path, out int consumed)
    {
        path = string.Empty;
        consumed = 0;
        if (value.Length < 2 || value[0] != '"')
        {
            return false;
        }

        var bytes = new ArrayBufferWriter<byte>(value.Length);
        for (int i = 1; i < value.Length; i++)
        {
            char current = value[i];
            if (current == '"')
            {
                path = Encoding.UTF8.GetString(bytes.WrittenSpan);
                consumed = i + 1;
                return true;
            }

            if (current == '\\' && i + 1 < value.Length)
            {
                char escaped = value[++i];
                if (escaped is >= '0' and <= '7')
                {
                    int octal = escaped - '0';
                    int digits = 1;
                    while (digits < 3 && i + 1 < value.Length && value[i + 1] is >= '0' and <= '7')
                    {
                        octal = (octal * 8) + value[++i] - '0';
                        digits++;
                    }

                    AppendByte(bytes, (byte)octal);
                    continue;
                }

                AppendByte(bytes, escaped switch
                {
                    'a' => 0x07,
                    'b' => 0x08,
                    't' => (byte)'\t',
                    'n' => (byte)'\n',
                    'v' => 0x0B,
                    'f' => 0x0C,
                    'r' => (byte)'\r',
                    _ => (byte)escaped,
                });
                continue;
            }

            int charCount = i + 1 < value.Length && char.IsSurrogatePair(current, value[i + 1]) ? 2 : 1;
            int byteCount = Encoding.UTF8.GetBytes(value.Slice(i, charCount), bytes.GetSpan(4));
            bytes.Advance(byteCount);
            i += charCount - 1;
        }

        return false;
    }

    private static void AppendByte(ArrayBufferWriter<byte> bytes, byte value)
    {
        bytes.GetSpan(1)[0] = value;
        bytes.Advance(1);
    }
}
