using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// Provides shared helpers for Picket file-based utility apps.
/// </summary>
internal static class ScriptSupport
{
    /// <summary>
    /// JSON writer options used by script output files.
    /// </summary>
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
    };

    /// <summary>
    /// UTF-8 without a byte order mark.
    /// </summary>
    private static readonly UTF8Encoding s_utf8NoBom = new(false);

    /// <summary>
    /// Parses PowerShell-style command-line options used by the previous script surface.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <param name="valueOptions">Option names that accept a single value.</param>
    /// <param name="arrayOptions">Option names that accept one or more values.</param>
    /// <param name="switchOptions">Option names that behave as switches.</param>
    /// <returns>The parsed option values and switches.</returns>
    internal static (Dictionary<string, List<string>> Values, HashSet<string> Switches) ParseArguments(
        string[] args,
        string[] valueOptions,
        string[] arrayOptions,
        string[] switchOptions)
    {
        var values = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var switches = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var knownOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var valueOptionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var arrayOptionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var switchOptionSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string option in valueOptions)
        {
            string key = NormalizeOptionName(option);
            valueOptionSet.Add(key);
            knownOptions.Add(key);
        }

        foreach (string option in arrayOptions)
        {
            string key = NormalizeOptionName(option);
            arrayOptionSet.Add(key);
            knownOptions.Add(key);
        }

        foreach (string option in switchOptions)
        {
            string key = NormalizeOptionName(option);
            switchOptionSet.Add(key);
            knownOptions.Add(key);
        }

        for (int i = 0; i < args.Length; i++)
        {
            string token = args[i];
            if (token.Equals("--", StringComparison.Ordinal))
            {
                string additionalArguments = NormalizeOptionName("AdditionalArguments");
                while (++i < args.Length)
                {
                    AddValue(values, additionalArguments, args[i]);
                }

                break;
            }

            if (!TryParseOptionToken(token, knownOptions, out string name, out string? inlineValue))
            {
                throw new ArgumentException($"Unexpected argument '{token}'.");
            }

            if (switchOptionSet.Contains(name))
            {
                if (inlineValue is null || ParseBoolean(inlineValue, token))
                {
                    switches.Add(name);
                }

                continue;
            }

            if (valueOptionSet.Contains(name))
            {
                string value = inlineValue ?? ReadRequiredValue(args, ref i, token);
                AddValue(values, name, value);
                continue;
            }

            if (!arrayOptionSet.Contains(name))
            {
                throw new ArgumentException($"Unsupported argument '{token}'.");
            }

            if (inlineValue is not null)
            {
                AddValue(values, name, inlineValue);
                continue;
            }

            bool consumed = false;
            while (i + 1 < args.Length && !LooksLikeKnownOption(args[i + 1], knownOptions))
            {
                i++;
                AddValue(values, name, args[i]);
                consumed = true;
            }

            if (!consumed)
            {
                throw new ArgumentException($"Argument '{token}' requires at least one value.");
            }
        }

        return (values, switches);
    }

    /// <summary>
    /// Reads whether a parsed switch was present.
    /// </summary>
    /// <param name="switches">The parsed switches.</param>
    /// <param name="name">The switch name.</param>
    /// <returns><see langword="true"/> when the switch was present.</returns>
    internal static bool GetSwitch(HashSet<string> switches, string name)
    {
        return switches.Contains(NormalizeOptionName(name));
    }

    /// <summary>
    /// Reads the last value for an option.
    /// </summary>
    /// <param name="values">The parsed option values.</param>
    /// <param name="name">The option name.</param>
    /// <param name="defaultValue">The value to return when the option is absent.</param>
    /// <returns>The option value or default value.</returns>
    internal static string GetString(Dictionary<string, List<string>> values, string name, string defaultValue = "")
    {
        return values.TryGetValue(NormalizeOptionName(name), out List<string>? optionValues) && optionValues.Count != 0
            ? optionValues[^1]
            : defaultValue;
    }

    /// <summary>
    /// Reads array values for an option.
    /// </summary>
    /// <param name="values">The parsed option values.</param>
    /// <param name="name">The option name.</param>
    /// <param name="defaultValue">The value to return when the option is absent.</param>
    /// <param name="splitCommas">Whether comma-delimited values should be split.</param>
    /// <returns>The option values.</returns>
    internal static string[] GetStringArray(Dictionary<string, List<string>> values, string name, string[]? defaultValue = null, bool splitCommas = true)
    {
        if (!values.TryGetValue(NormalizeOptionName(name), out List<string>? optionValues) || optionValues.Count == 0)
        {
            return defaultValue ?? [];
        }

        var result = new List<string>();
        foreach (string value in optionValues)
        {
            if (!splitCommas)
            {
                result.Add(value);
                continue;
            }

            foreach (string part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                result.Add(part);
            }
        }

        return [.. result];
    }

    /// <summary>
    /// Requires a value to be present in a known set.
    /// </summary>
    /// <param name="name">The option name for diagnostics.</param>
    /// <param name="value">The option value.</param>
    /// <param name="allowedValues">The allowed values.</param>
    internal static void RequireValueInSet(string name, string value, string[] allowedValues)
    {
        foreach (string allowedValue in allowedValues)
        {
            if (allowedValue.Equals(value, StringComparison.Ordinal))
            {
                return;
            }
        }

        throw new ArgumentException($"{name} must be one of: {string.Join(", ", allowedValues)}.");
    }

    /// <summary>
    /// Requires each value to be present in a known set.
    /// </summary>
    /// <param name="name">The option name for diagnostics.</param>
    /// <param name="values">The option values.</param>
    /// <param name="allowedValues">The allowed values.</param>
    internal static void RequireValuesInSet(string name, string[] values, string[] allowedValues)
    {
        foreach (string value in values)
        {
            RequireValueInSet(name, value, allowedValues);
        }
    }

    /// <summary>
    /// Finds the repository root for a file-based app.
    /// </summary>
    /// <param name="sourceFilePath">The caller source file path supplied by the compiler.</param>
    /// <returns>The repository root path.</returns>
    internal static string FindRepositoryRoot([CallerFilePath] string sourceFilePath = "")
    {
        string? sourceDirectory = Path.GetDirectoryName(sourceFilePath);
        DirectoryInfo? directory = !string.IsNullOrWhiteSpace(sourceDirectory)
            ? new DirectoryInfo(sourceDirectory)
            : new DirectoryInfo(Directory.GetCurrentDirectory());

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Picket.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        directory = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Picket.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not find repository root.");
    }

    /// <summary>
    /// Resolves a local reference clone path through environment variables or sibling clone names.
    /// </summary>
    /// <param name="repositoryRoot">The current repository root.</param>
    /// <param name="environmentVariable">The environment variable name.</param>
    /// <param name="siblingName">The sibling clone directory name.</param>
    /// <returns>The configured or sibling clone path.</returns>
    internal static string ResolveReferencePath(string repositoryRoot, string environmentVariable, string siblingName)
    {
        string? configuredPath = Environment.GetEnvironmentVariable(environmentVariable);
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return configuredPath;
        }

        string parent = Directory.GetParent(repositoryRoot)?.FullName
            ?? throw new DirectoryNotFoundException($"Could not find parent directory for '{repositoryRoot}'.");
        return Path.Combine(parent, siblingName);
    }

    /// <summary>
    /// Resolves a required path relative to a base directory.
    /// </summary>
    /// <param name="pathValue">The input path.</param>
    /// <param name="description">The path description for diagnostics.</param>
    /// <param name="baseDirectory">The base directory for relative paths.</param>
    /// <returns>The full resolved path, or an empty string when the input is empty.</returns>
    internal static string ResolveExistingPath(string pathValue, string description, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(pathValue))
        {
            return string.Empty;
        }

        string resolvedPathValue = Path.IsPathFullyQualified(pathValue)
            ? pathValue
            : Path.Combine(baseDirectory, pathValue);
        if (File.Exists(resolvedPathValue) || Directory.Exists(resolvedPathValue))
        {
            return Path.GetFullPath(resolvedPathValue);
        }

        throw new FileNotFoundException($"{description} '{pathValue}' does not exist.");
    }

    /// <summary>
    /// Resolves an existing directory.
    /// </summary>
    /// <param name="pathValue">The directory path.</param>
    /// <param name="description">The directory description for diagnostics.</param>
    /// <returns>The full directory path.</returns>
    internal static string ResolveExistingDirectory(string pathValue, string description)
    {
        if (!Directory.Exists(pathValue))
        {
            throw new DirectoryNotFoundException($"{description} '{pathValue}' does not exist.");
        }

        return Path.GetFullPath(pathValue);
    }

    /// <summary>
    /// Resolves an optional file path.
    /// </summary>
    /// <param name="pathValue">The file path.</param>
    /// <param name="description">The file description for diagnostics.</param>
    /// <returns>The full file path, or an empty string when the input is empty.</returns>
    internal static string ResolveOptionalFile(string pathValue, string description)
    {
        if (string.IsNullOrWhiteSpace(pathValue))
        {
            return string.Empty;
        }

        if (!File.Exists(pathValue))
        {
            throw new FileNotFoundException($"{description} '{pathValue}' does not exist.");
        }

        return Path.GetFullPath(pathValue);
    }

    /// <summary>
    /// Resolves the requested process working directory.
    /// </summary>
    /// <param name="workingDirectory">The requested working directory.</param>
    /// <returns>The resolved working directory.</returns>
    internal static string ResolveWorkingDirectory(string workingDirectory)
    {
        if (string.IsNullOrWhiteSpace(workingDirectory))
        {
            return Directory.GetCurrentDirectory();
        }

        if (!Directory.Exists(workingDirectory))
        {
            throw new DirectoryNotFoundException($"working directory '{workingDirectory}' does not exist.");
        }

        return Path.GetFullPath(workingDirectory);
    }

    /// <summary>
    /// Resolves an executable path from a literal path or the process PATH.
    /// </summary>
    /// <param name="commandPath">The command path or command name.</param>
    /// <param name="description">The command description for diagnostics.</param>
    /// <returns>The resolved executable path.</returns>
    internal static string ResolveCommandPath(string commandPath, string description)
    {
        if (File.Exists(commandPath))
        {
            return Path.GetFullPath(commandPath);
        }

        string? resolved = FindOnPath(commandPath);
        if (resolved is not null)
        {
            return resolved;
        }

        throw new FileNotFoundException($"Could not find {description} '{commandPath}'.");
    }

    /// <summary>
    /// Runs an external process and captures stdout and stderr.
    /// </summary>
    /// <param name="filePath">The process executable.</param>
    /// <param name="arguments">The process arguments.</param>
    /// <param name="workingDirectory">The process working directory.</param>
    /// <param name="standardInputPath">The optional file to pipe to standard input.</param>
    /// <returns>The exit code, stdout, and stderr.</returns>
    internal static (int ExitCode, string Stdout, string Stderr) RunProcess(
        string filePath,
        IEnumerable<string> arguments,
        string workingDirectory,
        string standardInputPath = "")
    {
        var startInfo = new ProcessStartInfo(filePath)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            RedirectStandardInput = !string.IsNullOrWhiteSpace(standardInputPath),
            UseShellExecute = false,
            WorkingDirectory = workingDirectory,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Failed to start '{filePath}'.");
        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stderrTask = process.StandardError.ReadToEndAsync();

        if (!string.IsNullOrWhiteSpace(standardInputPath))
        {
            using FileStream input = File.OpenRead(standardInputPath);
            input.CopyTo(process.StandardInput.BaseStream);
            process.StandardInput.Close();
        }

        process.WaitForExit();
        string stdout = stdoutTask.GetAwaiter().GetResult();
        string stderr = stderrTask.GetAwaiter().GetResult();

        return (process.ExitCode, stdout, stderr);
    }

    /// <summary>
    /// Runs git in a repository and returns trimmed stdout.
    /// </summary>
    /// <param name="repositoryPath">The repository path.</param>
    /// <param name="arguments">The git arguments.</param>
    /// <returns>The trimmed stdout.</returns>
    internal static string RunGit(string repositoryPath, params string[] arguments)
    {
        var gitArguments = new List<string>
        {
            "-C",
            repositoryPath,
        };
        gitArguments.AddRange(arguments);

        (int exitCode, string stdout, _) = RunProcess("git", gitArguments, Directory.GetCurrentDirectory());
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"git {string.Join(' ', arguments)} failed for '{repositoryPath}'.");
        }

        return stdout.Trim();
    }

    /// <summary>
    /// Computes a file SHA-256 hash.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <returns>The lowercase hexadecimal hash, or an empty string when the file is absent.</returns>
    internal static string GetFileSha256(string path)
    {
        if (!File.Exists(path))
        {
            return string.Empty;
        }

        using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Compares two files byte-for-byte.
    /// </summary>
    /// <param name="leftPath">The first file path.</param>
    /// <param name="rightPath">The second file path.</param>
    /// <returns><see langword="true"/> when both files exist and have identical bytes.</returns>
    internal static bool FileBytesEqual(string leftPath, string rightPath)
    {
        if (!File.Exists(leftPath) || !File.Exists(rightPath))
        {
            return false;
        }

        byte[] left = File.ReadAllBytes(leftPath);
        byte[] right = File.ReadAllBytes(rightPath);
        if (left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Reads a JSON object from disk.
    /// </summary>
    /// <param name="path">The JSON file path.</param>
    /// <returns>The parsed JSON object.</returns>
    internal static JsonObject ReadJsonObject(string path)
    {
        JsonNode? node = JsonNode.Parse(File.ReadAllText(path));
        return node as JsonObject ?? throw new InvalidDataException($"Expected JSON object in '{path}'.");
    }

    /// <summary>
    /// Reads a JSON Lines file into an array.
    /// </summary>
    /// <param name="path">The JSON Lines file path.</param>
    /// <returns>The parsed JSON values.</returns>
    internal static JsonArray ReadJsonLines(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Picket report '{path}' does not exist.");
        }

        var findings = new JsonArray();
        foreach (string line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            AddNode(findings, JsonNode.Parse(line));
        }

        return findings;
    }

    /// <summary>
    /// Writes a JSON value to disk.
    /// </summary>
    /// <param name="path">The destination path.</param>
    /// <param name="node">The JSON value.</param>
    internal static void WriteJsonFile(string path, JsonNode node)
    {
        EnsureParentDirectory(path);
        File.WriteAllText(path, node.ToJsonString(s_jsonOptions), s_utf8NoBom);
    }

    /// <summary>
    /// Writes text to disk as UTF-8 without a byte order mark.
    /// </summary>
    /// <param name="path">The destination path.</param>
    /// <param name="contents">The text contents.</param>
    internal static void WriteTextFile(string path, string contents)
    {
        EnsureParentDirectory(path);
        File.WriteAllText(path, contents, s_utf8NoBom);
    }

    /// <summary>
    /// Reads all text from a file.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <returns>The file contents.</returns>
    internal static string ReadTextFile(string path)
    {
        return File.ReadAllText(path);
    }

    /// <summary>
    /// Creates the parent directory for a path when one is present.
    /// </summary>
    /// <param name="path">The target path.</param>
    internal static void EnsureParentDirectory(string path)
    {
        string? directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    /// <summary>
    /// Converts strings to a JSON array.
    /// </summary>
    /// <param name="values">The values to convert.</param>
    /// <returns>The JSON array.</returns>
    internal static JsonArray ToJsonArray(IEnumerable<string> values)
    {
        var array = new JsonArray();
        foreach (string value in values)
        {
            AddString(array, value);
        }

        return array;
    }

    /// <summary>
    /// Adds a string value to a JSON array without using the trim-unsafe generic helper.
    /// </summary>
    /// <param name="array">The array to update.</param>
    /// <param name="value">The value to add.</param>
    internal static void AddString(JsonArray array, string value)
    {
        AddNode(array, JsonNode.Parse(EscapeJsonString(value)));
    }

    /// <summary>
    /// Adds an integer value to a JSON array without using the trim-unsafe generic helper.
    /// </summary>
    /// <param name="array">The array to update.</param>
    /// <param name="value">The value to add.</param>
    internal static void AddInt32(JsonArray array, int value)
    {
        AddNode(array, JsonNode.Parse(value.ToString(CultureInfo.InvariantCulture)));
    }

    /// <summary>
    /// Adds a node to a JSON array without using the trim-unsafe generic helper.
    /// </summary>
    /// <param name="array">The array to update.</param>
    /// <param name="node">The node to add.</param>
    internal static void AddNode(JsonArray array, JsonNode? node)
    {
        array.Add(node);
    }

    /// <summary>
    /// Reads a string property from a JSON object.
    /// </summary>
    /// <param name="node">The JSON object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The string property value, or an empty string when absent.</returns>
    internal static string GetString(JsonNode? node, string name)
    {
        JsonNode? value = node?[name];
        if (value is null)
        {
            return string.Empty;
        }

        return value.GetValue<string>() ?? string.Empty;
    }

    /// <summary>
    /// Reads an integer property from a JSON object.
    /// </summary>
    /// <param name="node">The JSON object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The integer property value, or zero when absent.</returns>
    internal static int GetInt(JsonNode? node, string name)
    {
        JsonNode? value = node?[name];
        if (value is null)
        {
            return 0;
        }

        if (value.GetValueKind() == JsonValueKind.Number && value.AsValue().TryGetValue(out int integer))
        {
            return integer;
        }

        string text = value.GetValue<string>() ?? string.Empty;
        return int.TryParse(text, out int parsed) ? parsed : 0;
    }

    /// <summary>
    /// Reads an array property from a JSON object.
    /// </summary>
    /// <param name="node">The JSON object.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The array value, or an empty array when absent.</returns>
    internal static JsonArray GetArray(JsonNode? node, string name)
    {
        return node?[name] as JsonArray ?? [];
    }

    /// <summary>
    /// Normalizes path separators to forward slashes.
    /// </summary>
    /// <param name="path">The path to normalize.</param>
    /// <returns>The normalized path.</returns>
    internal static string NormalizePathSeparators(string path)
    {
        return path.Replace('\\', '/');
    }

    /// <summary>
    /// Parses an option token into a normalized option name and optional inline value.
    /// </summary>
    /// <param name="token">The command-line token.</param>
    /// <param name="knownOptions">The known option names.</param>
    /// <param name="name">The parsed option name.</param>
    /// <param name="inlineValue">The parsed inline option value.</param>
    /// <returns><see langword="true"/> when the token is a known option.</returns>
    private static bool TryParseOptionToken(
        string token,
        HashSet<string> knownOptions,
        out string name,
        out string? inlineValue)
    {
        name = string.Empty;
        inlineValue = null;
        string option = token.TrimStart('-', '/');
        if (option.Length == token.Length || option.Length == 0)
        {
            return false;
        }

        int separatorIndex = option.IndexOf('=');
        if (separatorIndex < 0)
        {
            separatorIndex = option.IndexOf(':');
        }

        if (separatorIndex >= 0)
        {
            inlineValue = option[(separatorIndex + 1)..];
            option = option[..separatorIndex];
        }

        name = NormalizeOptionName(option);
        return knownOptions.Contains(name);
    }

    /// <summary>
    /// Determines whether a token looks like a known option.
    /// </summary>
    /// <param name="token">The command-line token.</param>
    /// <param name="knownOptions">The known option names.</param>
    /// <returns><see langword="true"/> when the token is a known option.</returns>
    private static bool LooksLikeKnownOption(string token, HashSet<string> knownOptions)
    {
        return TryParseOptionToken(token, knownOptions, out _, out _);
    }

    /// <summary>
    /// Reads the next command-line token as a required option value.
    /// </summary>
    /// <param name="args">The command-line arguments.</param>
    /// <param name="index">The current argument index.</param>
    /// <param name="optionToken">The option token for diagnostics.</param>
    /// <returns>The required option value.</returns>
    private static string ReadRequiredValue(string[] args, ref int index, string optionToken)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Argument '{optionToken}' requires a value.");
        }

        index++;
        return args[index];
    }

    /// <summary>
    /// Parses an inline switch value.
    /// </summary>
    /// <param name="value">The switch value.</param>
    /// <param name="optionToken">The option token for diagnostics.</param>
    /// <returns>The parsed boolean value.</returns>
    private static bool ParseBoolean(string value, string optionToken)
    {
        if (bool.TryParse(value, out bool result))
        {
            return result;
        }

        throw new ArgumentException($"Argument '{optionToken}' expects a boolean value.");
    }

    /// <summary>
    /// Adds a parsed option value.
    /// </summary>
    /// <param name="values">The option value map.</param>
    /// <param name="name">The normalized option name.</param>
    /// <param name="value">The option value.</param>
    private static void AddValue(Dictionary<string, List<string>> values, string name, string value)
    {
        if (!values.TryGetValue(name, out List<string>? optionValues))
        {
            optionValues = [];
            values.Add(name, optionValues);
        }

        optionValues.Add(value);
    }

    /// <summary>
    /// Normalizes an option name by removing option prefixes and separators.
    /// </summary>
    /// <param name="name">The option name.</param>
    /// <returns>The normalized option name.</returns>
    private static string NormalizeOptionName(string name)
    {
        var builder = new StringBuilder(name.Length);
        foreach (char character in name.TrimStart('-', '/'))
        {
            if (character is not '-' and not '_')
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Finds an executable on PATH.
    /// </summary>
    /// <param name="commandPath">The command name.</param>
    /// <returns>The executable path, or <see langword="null"/> when it cannot be found.</returns>
    private static string? FindOnPath(string commandPath)
    {
        if (commandPath.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || commandPath.Contains(Path.AltDirectorySeparatorChar, StringComparison.Ordinal))
        {
            return null;
        }

        string? path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        string[] extensions = OperatingSystem.IsWindows()
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries)
            : [string.Empty];

        foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (string extension in extensions)
            {
                string candidate = Path.Combine(directory, string.Concat(commandPath, extension));
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Escapes a string as a JSON string literal.
    /// </summary>
    /// <param name="value">The value to escape.</param>
    /// <returns>The JSON string literal.</returns>
    private static string EscapeJsonString(string value)
    {
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (char character in value)
        {
            switch (character)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (character < ' ')
                    {
                        builder.Append("\\u");
                        builder.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(character);
                    }

                    break;
            }
        }

        builder.Append('"');
        return builder.ToString();
    }
}
