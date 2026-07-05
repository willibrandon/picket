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
        List<GitPatchFragment> fragments = Parse(process.StandardOutput);
        process.WaitForExit();
        string stderr = stderrTask.GetAwaiter().GetResult().Trim();
        if (process.ExitCode != 0)
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
                StandardOutputEncoding = Encoding.UTF8,
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

        AddArguments(process.StartInfo, "-C", options.Root, "log", "-p", "-U0", "--date=iso-strict");
        if (options.LogOptions.Length == 0)
        {
            AddArguments(process.StartInfo, "--full-history", "--all", "--diff-filter=tuxdb");
            return process;
        }

        foreach (string argument in options.LogOptions.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        return process;
    }

    private static void AddArguments(ProcessStartInfo startInfo, params string[] arguments)
    {
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    private static List<GitPatchFragment> Parse(TextReader reader)
    {
        var fragments = new List<GitPatchFragment>();
        string commit = string.Empty;
        string author = string.Empty;
        string email = string.Empty;
        string date = string.Empty;
        string message = string.Empty;
        string? filePath = null;
        int hunkStartLine = 0;
        var messageLines = new List<string>();
        var addedLines = new List<string>();
        bool readingMessage = false;

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.StartsWith("commit ", StringComparison.Ordinal))
            {
                FlushFragment();
                commit = line["commit ".Length..].Trim();
                author = string.Empty;
                email = string.Empty;
                date = string.Empty;
                message = string.Empty;
                filePath = null;
                hunkStartLine = 0;
                messageLines.Clear();
                readingMessage = false;
                continue;
            }

            if (line.StartsWith("Author: ", StringComparison.Ordinal))
            {
                (author, email) = ParseAuthor(line["Author: ".Length..]);
                continue;
            }

            if (line.StartsWith("Date: ", StringComparison.Ordinal))
            {
                date = FormatGitDate(line["Date: ".Length..].Trim());
                readingMessage = true;
                continue;
            }

            if (line.StartsWith("diff --git ", StringComparison.Ordinal))
            {
                FlushFragment();
                message = CreateMessage(messageLines);
                readingMessage = false;
                filePath = null;
                hunkStartLine = 0;
                continue;
            }

            if (readingMessage)
            {
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith("    ", StringComparison.Ordinal))
                {
                    messageLines.Add(line[4..]);
                    continue;
                }
            }

            if (line.StartsWith("+++ ", StringComparison.Ordinal))
            {
                FlushFragment();
                filePath = ParseNewFilePath(line);
                hunkStartLine = 0;
                continue;
            }

            if (line.StartsWith("@@ ", StringComparison.Ordinal))
            {
                FlushFragment();
                hunkStartLine = ParseNewStartLine(line);
                continue;
            }

            if (hunkStartLine != 0 && filePath is not null && line.StartsWith('+') && !line.StartsWith("+++", StringComparison.Ordinal))
            {
                addedLines.Add(line[1..]);
            }
        }

        FlushFragment();
        return fragments;

        void FlushFragment()
        {
            if (filePath is null || hunkStartLine == 0 || addedLines.Count == 0)
            {
                addedLines.Clear();
                return;
            }

            string text = string.Join("\n", addedLines);
            fragments.Add(new GitPatchFragment(
                Encoding.UTF8.GetBytes(text),
                filePath,
                hunkStartLine,
                commit,
                author,
                email,
                date,
                message));
            addedLines.Clear();
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
        string path = line["+++ ".Length..].Trim();
        if (path.Equals("/dev/null", StringComparison.Ordinal))
        {
            return null;
        }

        return path.StartsWith("b/", StringComparison.Ordinal) ? path[2..] : path;
    }

    private static int ParseNewStartLine(string line)
    {
        int plusIndex = line.IndexOf('+');
        if (plusIndex < 0)
        {
            return 0;
        }

        int start = plusIndex + 1;
        int end = start;
        while (end < line.Length && char.IsDigit(line[end]))
        {
            end++;
        }

        return end == start ? 0 : int.Parse(line.AsSpan(start, end - start), CultureInfo.InvariantCulture);
    }
}
