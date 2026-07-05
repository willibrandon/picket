using System.Globalization;
using System.Text;

namespace Picket;

internal static partial class Program
{
    static int RunHooks(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteHooksHelp();
            return 0;
        }

        string subcommand = args[0];
        if (subcommand.Equals("install", StringComparison.OrdinalIgnoreCase))
        {
            return RunHooksInstall(args[1..]);
        }

        Console.Error.WriteLine($"unknown hooks command: {subcommand}");
        return UnknownFlagExitCode;
    }

    static int RunHooksInstall(string[] args)
    {
        if (args.Length != 0 && IsHelp(args[0]))
        {
            WriteHooksInstallHelp();
            return 0;
        }

        string? baselinePath = null;
        string? configPath = null;
        string? maxTargetMegabytes = null;
        string commandPath = "picket";
        string repo = ".";
        int redactionPercent = 100;
        bool force = false;
        List<string> hookNames = [];
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsBaselinePathFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--baseline-path", out baselinePath))
                {
                    return UnknownFlagExitCode;
                }

                baselinePath = Path.GetFullPath(baselinePath);
                continue;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return UnknownFlagExitCode;
                }

                configPath = Path.GetFullPath(configPath);
                continue;
            }

            if (IsHookCommandFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--command", out string? commandValue))
                {
                    return UnknownFlagExitCode;
                }

                commandPath = commandValue;
                if (commandPath.Length == 0)
                {
                    Console.Error.WriteLine("--command requires a non-empty value");
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsForceFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--force", out force))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsHooksRepoFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--repo", out string? repoValue))
                {
                    return UnknownFlagExitCode;
                }

                repo = repoValue.Length == 0 ? "." : repoValue;
                continue;
            }

            if (IsMaxTargetMegabytesFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--max-target-megabytes", out maxTargetMegabytes)
                    || !TryParseMegabytes(maxTargetMegabytes, out _))
                {
                    Console.Error.WriteLine("--max-target-megabytes requires a non-negative integer value");
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsRedactFlag(arg))
            {
                if (!TryReadRedactionPercent(args, ref i, out redactionPercent))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }

            if (!TryAddHookName(hookNames, arg))
            {
                return UnknownFlagExitCode;
            }
        }

        if (hookNames.Count == 0)
        {
            hookNames.Add("pre-commit");
        }

        string hooksDirectory;
        try
        {
            hooksDirectory = ResolveHooksDirectory(repo);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        var options = (
            CommandPath: commandPath,
            ConfigPath: configPath,
            BaselinePath: baselinePath,
            MaxTargetMegabytes: maxTargetMegabytes,
            RedactionPercent: redactionPercent);
        foreach (string hookName in hookNames)
        {
            string script = CreateHookScript(hookName, options);
            if (!TryWriteHook(hooksDirectory, hookName, script, force))
            {
                return 1;
            }
        }

        return 0;
    }

    static bool TryAddHookName(List<string> hookNames, string hookName)
    {
        string normalizedHookName = hookName.ToLowerInvariant();
        if (normalizedHookName.Equals("all", StringComparison.Ordinal))
        {
            return TryAddHookName(hookNames, "pre-commit")
                && TryAddHookName(hookNames, "pre-push")
                && TryAddHookName(hookNames, "pre-receive");
        }

        if (normalizedHookName is not ("pre-commit" or "pre-push" or "pre-receive"))
        {
            Console.Error.WriteLine($"unsupported hook: {hookName}");
            return false;
        }

        if (!hookNames.Contains(normalizedHookName, StringComparer.Ordinal))
        {
            hookNames.Add(normalizedHookName);
        }

        return true;
    }

    static string ResolveHooksDirectory(string repo)
    {
        string repositoryPath = Path.GetFullPath(repo.Length == 0 ? "." : repo);
        string dotGitPath = Path.Combine(repositoryPath, ".git");
        if (Directory.Exists(dotGitPath))
        {
            return Path.Combine(dotGitPath, "hooks");
        }

        if (File.Exists(dotGitPath))
        {
            string gitDir = ReadGitDirectoryFile(repositoryPath, dotGitPath);
            return Path.Combine(gitDir, "hooks");
        }

        if (File.Exists(Path.Combine(repositoryPath, "HEAD"))
            && Directory.Exists(Path.Combine(repositoryPath, "objects")))
        {
            return Path.Combine(repositoryPath, "hooks");
        }

        throw new DirectoryNotFoundException($"{repositoryPath} is not a git repository or bare repository");
    }

    static string ReadGitDirectoryFile(string repositoryPath, string dotGitPath)
    {
        string text = File.ReadAllText(dotGitPath).Trim();
        const string Prefix = "gitdir:";
        if (!text.StartsWith(Prefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{dotGitPath} is not a supported gitdir file");
        }

        string gitDir = text[Prefix.Length..].Trim();
        if (Path.IsPathRooted(gitDir))
        {
            return Path.GetFullPath(gitDir);
        }

        return Path.GetFullPath(Path.Combine(repositoryPath, gitDir));
    }

    static bool TryWriteHook(string hooksDirectory, string hookName, string script, bool force)
    {
        Directory.CreateDirectory(hooksDirectory);
        string hookPath = Path.Combine(hooksDirectory, hookName);
        if (File.Exists(hookPath) && !force && !File.ReadAllText(hookPath).Contains(ManagedHookMarker, StringComparison.Ordinal))
        {
            Console.Error.WriteLine($"{hookPath} already exists and was not created by Picket; use --force to overwrite it");
            return false;
        }

        File.WriteAllText(hookPath, script, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        TrySetHookExecutable(hookPath);
        Console.Out.WriteLine($"installed {hookName}: {hookPath}");
        return true;
    }

    static void TrySetHookExecutable(string hookPath)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                hookPath,
                UnixFileMode.UserRead
                    | UnixFileMode.UserWrite
                    | UnixFileMode.UserExecute
                    | UnixFileMode.GroupRead
                    | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead
                    | UnixFileMode.OtherExecute);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    static string CreateHookScript(
        string hookName,
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        return hookName switch
        {
            "pre-commit" => CreatePreCommitHookScript(options),
            "pre-push" => CreatePrePushHookScript(options),
            "pre-receive" => CreatePreReceiveHookScript(options),
            _ => throw new InvalidOperationException($"unsupported hook: {hookName}"),
        };
    }

    static string CreatePreCommitHookScript(
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        var builder = new StringBuilder();
        AppendHookHeader(builder);
        builder.Append("repo_root=$(git rev-parse --show-toplevel)\n");
        builder.Append("exec ");
        builder.Append(QuoteShell(options.CommandPath));
        builder.Append(" protect --source \"$repo_root\"");
        AppendHookScanOptions(builder, options);
        builder.Append('\n');
        return builder.ToString();
    }

    static string CreatePrePushHookScript(
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        var builder = new StringBuilder();
        AppendHookHeader(builder);
        builder.Append("repo_root=$(git rev-parse --show-toplevel)\n");
        AppendHookRangeLoop(builder, options, "local_ref local_sha remote_ref remote_sha", "remote_sha", "local_sha");
        return builder.ToString();
    }

    static string CreatePreReceiveHookScript(
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        var builder = new StringBuilder();
        AppendHookHeader(builder);
        builder.Append("git_dir=$(git rev-parse --git-dir)\n");
        builder.Append("case \"$git_dir\" in\n");
        builder.Append("  /*) repo_root=$git_dir ;;\n");
        builder.Append("  *) repo_root=$(pwd -P)/$git_dir ;;\n");
        builder.Append("esac\n");
        AppendHookRangeLoop(builder, options, "old_sha new_sha ref_name", "old_sha", "new_sha");
        return builder.ToString();
    }

    static void AppendHookHeader(StringBuilder builder)
    {
        builder.Append("#!/bin/sh\n");
        builder.Append(ManagedHookMarker);
        builder.Append('\n');
        builder.Append("set -eu\n");
        builder.Append("zero=0000000000000000000000000000000000000000\n");
    }

    static void AppendHookRangeLoop(
        StringBuilder builder,
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options,
        string readVariables,
        string oldShaVariable,
        string newShaVariable)
    {
        builder.Append("status=0\n");
        builder.Append("while read ");
        builder.Append(readVariables);
        builder.Append('\n');
        builder.Append("do\n");
        builder.Append("  [ \"$");
        builder.Append(newShaVariable);
        builder.Append("\" = \"$zero\" ] && continue\n");
        builder.Append("  if [ \"$");
        builder.Append(oldShaVariable);
        builder.Append("\" = \"$zero\" ]; then\n");
        builder.Append("    range=\"$");
        builder.Append(newShaVariable);
        builder.Append("\"\n");
        builder.Append("  else\n");
        builder.Append("    range=\"$");
        builder.Append(oldShaVariable);
        builder.Append("..$");
        builder.Append(newShaVariable);
        builder.Append("\"\n");
        builder.Append("  fi\n");
        builder.Append("  ");
        builder.Append(QuoteShell(options.CommandPath));
        builder.Append(" git \"$repo_root\" --log-opts \"$range\"");
        AppendHookScanOptions(builder, options);
        builder.Append(" || status=$?\n");
        builder.Append("done\n");
        builder.Append("exit \"$status\"\n");
    }

    static void AppendHookScanOptions(
        StringBuilder builder,
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        AppendHookOption(builder, "--config", options.ConfigPath);
        AppendHookOption(builder, "--baseline-path", options.BaselinePath);
        AppendHookOption(builder, "--max-target-megabytes", options.MaxTargetMegabytes);
        builder.Append(' ');
        builder.Append(QuoteShell($"--redact={options.RedactionPercent.ToString(CultureInfo.InvariantCulture)}"));
    }

    static void AppendHookOption(StringBuilder builder, string name, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }

        builder.Append(' ');
        builder.Append(name);
        builder.Append(' ');
        builder.Append(QuoteShell(value));
    }

    static string QuoteShell(string value)
    {
        return string.Concat('\'', value.Replace("'", "'\"'\"'", StringComparison.Ordinal), '\'');
    }
}
