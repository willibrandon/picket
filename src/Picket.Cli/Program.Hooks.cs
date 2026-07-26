using System.ComponentModel;
using System.Diagnostics;
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
        if (!Directory.Exists(repositoryPath))
        {
            throw new DirectoryNotFoundException($"repository path does not exist: {repositoryPath}");
        }

        var startInfo = new ProcessStartInfo("git")
        {
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        startInfo.ArgumentList.Add("-C");
        startInfo.ArgumentList.Add(repositoryPath);
        startInfo.ArgumentList.Add("rev-parse");
        startInfo.ArgumentList.Add("--path-format=absolute");
        startInfo.ArgumentList.Add("--git-path");
        startInfo.ArgumentList.Add("hooks");

        Process process;
        try
        {
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("git did not start");
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException("git is required to install repository hooks but could not be started", ex);
        }

        using (process)
        {
            Task<string> outputTask = process.StandardOutput.ReadToEndAsync();
            Task<string> errorTask = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            string output = outputTask.GetAwaiter().GetResult();
            string error = errorTask.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
            {
                string reason = SanitizeHookText(error.Trim(), MaxHookPathLength);
                throw new InvalidOperationException(reason.Length == 0
                    ? $"{repositoryPath} is not a git repository or bare repository"
                    : reason);
            }

            string hooksPath = output.ReplaceLineEndings("\n");
            if (hooksPath.EndsWith('\n'))
            {
                hooksPath = hooksPath[..^1];
            }

            if (hooksPath.Length == 0 || hooksPath.Contains('\n'))
            {
                throw new InvalidOperationException("git returned an invalid hooks path");
            }

            return Path.GetFullPath(hooksPath);
        }
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
        builder.Append("status=0\n");
        builder.Append(QuoteShell(options.CommandPath));
        builder.Append(" git \"$repo_root\" --pre-commit --staged");
        AppendHookScanOptions(builder, options, PreCommitHookContext);
        builder.Append(" || status=$?\n");
        AppendHookOperationalFailure(builder, "status", PreCommitHookContext, indent: "");
        builder.Append("exit \"$status\"\n");
        return builder.ToString();
    }

    static string CreatePrePushHookScript(
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options)
    {
        var builder = new StringBuilder();
        AppendHookHeader(builder);
        builder.Append("repo_root=$(git rev-parse --show-toplevel)\n");
        AppendHookRangeLoop(
            builder,
            options,
            "local_ref local_sha remote_ref remote_sha",
            "remote_sha",
            "local_sha",
            PrePushHookContext);
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
        AppendHookRangeLoop(
            builder,
            options,
            "old_sha new_sha ref_name",
            "old_sha",
            "new_sha",
            PreReceiveHookContext);
        return builder.ToString();
    }

    static void AppendHookHeader(StringBuilder builder)
    {
        builder.Append("#!/bin/sh\n");
        builder.Append(ManagedHookMarker);
        builder.Append('\n');
        builder.Append("set -eu\n");
        builder.Append("finding_status=");
        builder.Append(HookFindingExitCode.ToString(CultureInfo.InvariantCulture));
        builder.Append('\n');
        builder.Append("zero=0000000000000000000000000000000000000000\n");
    }

    static void AppendHookRangeLoop(
        StringBuilder builder,
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options,
        string readVariables,
        string oldShaVariable,
        string newShaVariable,
        string hookContext)
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
        builder.Append("  result=0\n");
        builder.Append("  ");
        builder.Append(QuoteShell(options.CommandPath));
        builder.Append(" git \"$repo_root\" --log-opts \"$range\"");
        AppendHookScanOptions(builder, options, hookContext);
        builder.Append(" || result=$?\n");
        builder.Append("  if [ \"$result\" -ne 0 ]; then\n");
        AppendHookOperationalFailure(builder, "result", hookContext, indent: "    ");
        builder.Append("    if [ \"$result\" -ne \"$finding_status\" ] || [ \"$status\" -eq 0 ]; then\n");
        builder.Append("      status=$result\n");
        builder.Append("    fi\n");
        builder.Append("  fi\n");
        builder.Append("done\n");
        builder.Append("exit \"$status\"\n");
    }

    static void AppendHookScanOptions(
        StringBuilder builder,
        (string CommandPath, string? ConfigPath, string? BaselinePath, string? MaxTargetMegabytes, int RedactionPercent) options,
        string hookContext)
    {
        AppendHookOption(builder, "--config", options.ConfigPath);
        AppendHookOption(builder, "--baseline-path", options.BaselinePath);
        AppendHookOption(builder, "--max-target-megabytes", options.MaxTargetMegabytes);
        builder.Append(' ');
        builder.Append(QuoteShell($"--hook-context={hookContext}"));
        builder.Append(' ');
        builder.Append(QuoteShell($"--exit-code={HookFindingExitCode.ToString(CultureInfo.InvariantCulture)}"));
        builder.Append(" --no-banner --no-color ");
        builder.Append(QuoteShell($"--redact={options.RedactionPercent.ToString(CultureInfo.InvariantCulture)}"));
    }

    static void AppendHookOperationalFailure(StringBuilder builder, string statusVariable, string hookContext, string indent)
    {
        string message = hookContext switch
        {
            PreCommitHookContext => "Picket could not scan staged changes; commit blocked.",
            PrePushHookContext => "Picket could not scan outgoing commits; push blocked.",
            PreReceiveHookContext => "Picket could not scan received commits; push rejected.",
            _ => throw new InvalidOperationException($"unsupported hook context: {hookContext}"),
        };
        builder.Append(indent);
        builder.Append("if [ \"$");
        builder.Append(statusVariable);
        builder.Append("\" -ne 0 ] && [ \"$");
        builder.Append(statusVariable);
        builder.Append("\" -ne \"$finding_status\" ]; then\n");
        builder.Append(indent);
        builder.Append("  printf '%s\\n' ");
        builder.Append(QuoteShell(message));
        builder.Append(" >&2\n");
        builder.Append(indent);
        builder.Append("fi\n");
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
