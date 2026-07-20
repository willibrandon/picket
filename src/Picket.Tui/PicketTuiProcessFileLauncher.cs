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
    public bool TryOpen(string path, int? line, int? column, out string message)
    {
        if (!TryResolveLocalFile(path, out string resolvedPath, out message))
        {
            return false;
        }

        ProcessStartInfo startInfo = CreateStartInfo(resolvedPath, line, column);
        try
        {
            using Process? process = Process.Start(startInfo);
            if (process is null)
            {
                message = string.Concat("Unable to open file: ", path);
                return false;
            }

            if (ShouldWaitForProcess(startInfo))
            {
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    message = string.Concat(
                        "Editor exited with code ",
                        process.ExitCode.ToString(CultureInfo.InvariantCulture));
                    return false;
                }
            }

            message = CreateOpenedMessage(path, line, column);
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 2)
        {
            message = string.Concat("Unable to open file: command not found: ", startInfo.FileName);
            return false;
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
    /// <param name="column">The optional one-based column number.</param>
    /// <returns>The process start information.</returns>
    internal static ProcessStartInfo CreateStartInfo(string path, int? line, int? column = null)
    {
        string? configuredEditor = GetConfiguredEditor();
        if (!string.IsNullOrWhiteSpace(configuredEditor)
            && TryCreateEditorStartInfo(configuredEditor, path, line, column, out ProcessStartInfo editorStartInfo))
        {
            return editorStartInfo;
        }

        if (line.HasValue
            && TryFindCommand("code", out string codePath)
            && TryCreateKnownEditorStartInfo(codePath, path, line, column, out ProcessStartInfo codeStartInfo))
        {
            return codeStartInfo;
        }

        throw new InvalidOperationException(
            "No editor was found. Set PICKET_EDITOR, VISUAL, or EDITOR to an editor command.");
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
        int? column,
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
            string argument = ReplacePlaceholders(parts[i], path, line, column);
            hasPlaceholders |= !string.Equals(argument, parts[i], StringComparison.Ordinal);
            startInfo.ArgumentList.Add(argument);
        }

        if (!hasPlaceholders)
        {
            AddDefaultEditorArguments(startInfo, parts[0], path, line, column);
        }

        return true;
    }

    private static bool TryCreateKnownEditorStartInfo(
        string editorPath,
        string path,
        int? line,
        int? column,
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
        AddDefaultEditorArguments(startInfo, editorPath, path, line, column);
        return true;
    }

    private static void AddDefaultEditorArguments(
        ProcessStartInfo startInfo,
        string editorPath,
        string path,
        int? line,
        int? column)
    {
        string editorName = Path.GetFileNameWithoutExtension(editorPath);
        if (line.HasValue && IsCodeEditor(editorName))
        {
            AddArgumentIfMissing(startInfo, "-g");
            startInfo.ArgumentList.Add(CreateCodeLocationArgument(path, line.GetValueOrDefault(), column));
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
            startInfo.ArgumentList.Add(CreateVimLocationArgument(editorName, line.GetValueOrDefault(), column));
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

    private static string ReplacePlaceholders(string value, string path, int? line, int? column)
    {
        return value
            .Replace("{file}", path, StringComparison.Ordinal)
            .Replace("{path}", path, StringComparison.Ordinal)
            .Replace("{line}", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
            .Replace("{column}", column.GetValueOrDefault().ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)
            .Replace("{col}", column.GetValueOrDefault().ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static string CreateOpenedMessage(string path, int? line, int? column)
    {
        if (line.HasValue && column.HasValue)
        {
            return string.Concat(
                "Opened ",
                path,
                " at line ",
                line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture),
                ", column ",
                column.GetValueOrDefault().ToString(CultureInfo.InvariantCulture));
        }

        return line.HasValue
            ? string.Concat("Opened ", path, " at line ", line.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
            : string.Concat("Opened ", path);
    }

    private static string CreateCodeLocationArgument(string path, int line, int? column)
    {
        int? editorColumn = CreateEditorColumn(line, column);
        return column.HasValue
            ? string.Concat(
                path,
                ":",
                line.ToString(CultureInfo.InvariantCulture),
                ":",
                editorColumn.GetValueOrDefault().ToString(CultureInfo.InvariantCulture))
            : string.Concat(path, ":", line.ToString(CultureInfo.InvariantCulture));
    }

    private static string CreateVimLocationArgument(string editorName, int line, int? column)
    {
        int? editorColumn = CreateEditorColumn(line, column);
        return column.HasValue && SupportsVimCursorFunction(editorName)
            ? string.Concat(
                "+call cursor(",
                line.ToString(CultureInfo.InvariantCulture),
                ", ",
                editorColumn.GetValueOrDefault().ToString(CultureInfo.InvariantCulture),
                ")")
            : string.Concat("+", line.ToString(CultureInfo.InvariantCulture));
    }

    private static int? CreateEditorColumn(int line, int? column)
    {
        if (!column.HasValue)
        {
            return null;
        }

        // Gitleaks-compatible reports count the first byte after a newline as column two.
        return line > 1
            ? Math.Max(1, column.GetValueOrDefault() - 1)
            : column.GetValueOrDefault();
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

    private static bool SupportsVimCursorFunction(string value)
    {
        return string.Equals(value, "vim", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "nvim", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldWaitForProcess(ProcessStartInfo startInfo)
    {
        if (startInfo.UseShellExecute)
        {
            return false;
        }

        string editorName = Path.GetFileNameWithoutExtension(startInfo.FileName);
        return IsTerminalEditorName(editorName);
    }

    private static bool IsTerminalEditorName(string editorName)
    {
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
