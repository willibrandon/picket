using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Picket.Tui;

/// <summary>
/// Opens local files with a developer editor or the operating system default handler.
/// </summary>
internal sealed class PicketTuiProcessFileLauncher : IPicketTuiFileLauncher
{
    private static readonly string[] s_defaultWindowsCommandExtensions = [string.Empty, ".exe", ".cmd", ".bat", ".com"];
    private static readonly string[] s_editorEnvironmentVariables = ["PICKET_EDITOR", "VISUAL", "EDITOR"];
    private static readonly string[] s_emptyCommandExtensions = [string.Empty];

    /// <inheritdoc />
    public bool TryOpen(string path, int? line, out string message)
    {
        if (!TryResolveLocalFile(path, out string resolvedPath, out message))
        {
            return false;
        }

        string? configuredEditor = GetConfiguredEditor();
        if (!string.IsNullOrWhiteSpace(configuredEditor)
            && IsTerminalEditorCommand(configuredEditor, out string editorName))
        {
            message = string.Concat(
                "Cannot open terminal editor '",
                editorName,
                "' from the full-screen TUI. Set PICKET_EDITOR to a GUI editor such as 'code -g', or yank the path and open it in another shell.");
            return false;
        }

        ProcessStartInfo startInfo = CreateStartInfo(resolvedPath, line);
        try
        {
            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                message = string.Concat("Unable to open file: ", path);
                return false;
            }

            message = line.HasValue
                ? string.Concat("Opened ", path, " at line ", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
                : string.Concat("Opened ", path);
            return true;
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidOperationException)
        {
            message = string.Concat("Unable to open file: ", ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Creates process start information for a local file.
    /// </summary>
    /// <param name="path">The resolved local file path.</param>
    /// <param name="line">The optional one-based line number.</param>
    /// <returns>The process start information.</returns>
    internal static ProcessStartInfo CreateStartInfo(string path, int? line)
    {
        string? configuredEditor = GetConfiguredEditor();
        if (!string.IsNullOrWhiteSpace(configuredEditor)
            && TryCreateEditorStartInfo(configuredEditor, path, line, out ProcessStartInfo editorStartInfo))
        {
            return editorStartInfo;
        }

        if (line.HasValue
            && TryFindCommand("code", out string codePath)
            && TryCreateKnownEditorStartInfo(codePath, path, line, out ProcessStartInfo codeStartInfo))
        {
            return codeStartInfo;
        }

        return new ProcessStartInfo(path)
        {
            UseShellExecute = true,
        };
    }

    private static string? GetConfiguredEditor()
    {
        for (int i = 0; i < s_editorEnvironmentVariables.Length; i++)
        {
            string? value = Environment.GetEnvironmentVariable(s_editorEnvironmentVariables[i]);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool TryResolveLocalFile(string path, out string resolvedPath, out string message)
    {
        resolvedPath = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || string.Equals(path, "unknown", StringComparison.Ordinal))
        {
            message = "No local file path is available for this row";
            return false;
        }

        if (Uri.TryCreate(path, UriKind.Absolute, out Uri? uri))
        {
            if (!uri.IsFile)
            {
                message = "This report path is remote or synthetic and cannot be opened locally";
                return false;
            }

            path = uri.LocalPath;
        }

        try
        {
            resolvedPath = Path.GetFullPath(path);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            message = string.Concat("Invalid local file path: ", ex.Message);
            return false;
        }

        if (!File.Exists(resolvedPath))
        {
            message = string.Concat("File is not available locally: ", path);
            return false;
        }

        message = string.Empty;
        return true;
    }

    private static bool TryCreateEditorStartInfo(
        string editorCommand,
        string path,
        int? line,
        out ProcessStartInfo startInfo)
    {
        List<string> parts = SplitCommandLine(editorCommand);
        if (parts.Count == 0)
        {
            startInfo = null!;
            return false;
        }

        startInfo = new ProcessStartInfo(parts[0])
        {
            UseShellExecute = false,
        };

        bool hasPlaceholders = false;
        for (int i = 1; i < parts.Count; i++)
        {
            string argument = ReplacePlaceholders(parts[i], path, line);
            hasPlaceholders |= !string.Equals(argument, parts[i], StringComparison.Ordinal);
            startInfo.ArgumentList.Add(argument);
        }

        if (!hasPlaceholders)
        {
            AddDefaultEditorArguments(startInfo, parts[0], path, line);
        }

        return true;
    }

    private static bool TryCreateKnownEditorStartInfo(
        string editorPath,
        string path,
        int? line,
        out ProcessStartInfo startInfo)
    {
        if (string.IsNullOrWhiteSpace(editorPath))
        {
            startInfo = null!;
            return false;
        }

        startInfo = new ProcessStartInfo(editorPath)
        {
            UseShellExecute = false,
        };
        AddDefaultEditorArguments(startInfo, editorPath, path, line);
        return true;
    }

    private static void AddDefaultEditorArguments(ProcessStartInfo startInfo, string editorPath, string path, int? line)
    {
        string editorName = Path.GetFileNameWithoutExtension(editorPath);
        if (line.HasValue && IsCodeEditor(editorName))
        {
            AddArgumentIfMissing(startInfo, "-g");
            startInfo.ArgumentList.Add(string.Concat(path, ":", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture)));
            return;
        }

        if (line.HasValue && IsRiderEditor(editorName))
        {
            startInfo.ArgumentList.Add("--line");
            startInfo.ArgumentList.Add(line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture));
            startInfo.ArgumentList.Add(path);
            return;
        }

        if (line.HasValue && IsVimEditor(editorName))
        {
            startInfo.ArgumentList.Add(string.Concat("+", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture)));
            startInfo.ArgumentList.Add(path);
            return;
        }

        if (string.Equals(editorName, "devenv", StringComparison.OrdinalIgnoreCase))
        {
            startInfo.ArgumentList.Add("/edit");
            startInfo.ArgumentList.Add(path);
            return;
        }

        startInfo.ArgumentList.Add(path);
    }

    private static void AddArgumentIfMissing(ProcessStartInfo startInfo, string argument)
    {
        for (int i = 0; i < startInfo.ArgumentList.Count; i++)
        {
            if (string.Equals(startInfo.ArgumentList[i], argument, StringComparison.Ordinal))
            {
                return;
            }
        }

        startInfo.ArgumentList.Add(argument);
    }

    private static string ReplacePlaceholders(string value, string path, int? line)
    {
        return value
            .Replace("{file}", path, StringComparison.Ordinal)
            .Replace("{path}", path, StringComparison.Ordinal)
            .Replace("{line}", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static bool IsCodeEditor(string value)
    {
        return string.Equals(value, "code", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "code-insiders", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "codium", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "cursor", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRiderEditor(string value)
    {
        return string.Equals(value, "rider", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "rider64", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsVimEditor(string value)
    {
        return string.Equals(value, "vim", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "nvim", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "vi", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTerminalEditorCommand(string editorCommand, out string editorName)
    {
        List<string> parts = SplitCommandLine(editorCommand);
        if (parts.Count == 0)
        {
            editorName = string.Empty;
            return false;
        }

        editorName = Path.GetFileNameWithoutExtension(parts[0]);
        return IsVimEditor(editorName)
            || string.Equals(editorName, "nano", StringComparison.OrdinalIgnoreCase)
            || string.Equals(editorName, "micro", StringComparison.OrdinalIgnoreCase)
            || string.Equals(editorName, "hx", StringComparison.OrdinalIgnoreCase)
            || string.Equals(editorName, "helix", StringComparison.OrdinalIgnoreCase)
            || string.Equals(editorName, "kak", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsDirectorySeparator(string value)
    {
        if (value.Contains(Path.DirectorySeparatorChar))
        {
            return true;
        }

        return Path.AltDirectorySeparatorChar != Path.DirectorySeparatorChar
            && value.Contains(Path.AltDirectorySeparatorChar);
    }

    private static bool TryFindCommand(string command, out string resolvedPath)
    {
        if (Path.IsPathFullyQualified(command) || ContainsDirectorySeparator(command))
        {
            if (File.Exists(command))
            {
                resolvedPath = command;
                return true;
            }

            resolvedPath = null!;
            return false;
        }

        string? pathEnvironment = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnvironment))
        {
            resolvedPath = null!;
            return false;
        }

        string[] extensions = OperatingSystem.IsWindows()
            ? GetWindowsCommandExtensions()
            : s_emptyCommandExtensions;
        string[] directories = pathEnvironment.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (int i = 0; i < directories.Length; i++)
        {
            for (int j = 0; j < extensions.Length; j++)
            {
                string candidate = Path.Combine(directories[i], string.Concat(command, extensions[j]));
                if (File.Exists(candidate))
                {
                    resolvedPath = candidate;
                    return true;
                }
            }
        }

        resolvedPath = null!;
        return false;
    }

    private static string[] GetWindowsCommandExtensions()
    {
        string? pathExtensions = Environment.GetEnvironmentVariable("PATHEXT");
        return string.IsNullOrWhiteSpace(pathExtensions)
            ? s_defaultWindowsCommandExtensions
            : pathExtensions.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static List<string> SplitCommandLine(string commandLine)
    {
        var parts = new List<string>();
        var current = new StringBuilder();
        char quote = '\0';

        for (int i = 0; i < commandLine.Length; i++)
        {
            char currentChar = commandLine[i];
            if ((currentChar == '"' || currentChar == '\'') && (quote == '\0' || quote == currentChar))
            {
                quote = quote == '\0' ? currentChar : '\0';
                continue;
            }

            if (char.IsWhiteSpace(currentChar) && quote == '\0')
            {
                AddCommandPart(parts, current);
                continue;
            }

            current.Append(currentChar);
        }

        AddCommandPart(parts, current);
        return parts;
    }

    private static void AddCommandPart(List<string> parts, StringBuilder current)
    {
        if (current.Length == 0)
        {
            return;
        }

        parts.Add(current.ToString());
        current.Clear();
    }
}
