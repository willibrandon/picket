namespace Picket;

internal static partial class Program
{
    static async Task<int> RunDetectAsync(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteDetectHelp();
            return 0;
        }

        var forwardedArgs = new List<string>();
        string? logOptions = null;
        string? platform = null;
        string source = ".";
        bool followSymlinks = false;
        bool noGit = false;
        bool pipe = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return 1;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsNoGitFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--no-git", out noGit))
                {
                    return 1;
                }

                continue;
            }

            if (IsPipeFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--pipe", out pipe))
                {
                    return 1;
                }

                continue;
            }

            if (IsFollowSymlinksFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--follow-symlinks", out followSymlinks))
                {
                    return 1;
                }

                continue;
            }

            if (IsLogOptionsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
                {
                    return 1;
                }

                continue;
            }

            if (IsPlatformFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--platform", out platform))
                {
                    return 1;
                }

                continue;
            }

            if (TryForwardCompatibilityRootFlag(args, ref i, forwardedArgs, out bool handledRootFlag))
            {
                if (handledRootFlag)
                {
                    continue;
                }
            }
            else
            {
                return 1;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }
        }

        if (noGit)
        {
            if (followSymlinks)
            {
                forwardedArgs.Add("--follow-symlinks");
            }

            forwardedArgs.Add(source);
            return RunDirectory([.. forwardedArgs]);
        }

        if (pipe)
        {
            return await RunStdinAsync([.. forwardedArgs], source).ConfigureAwait(false);
        }

        if (!string.IsNullOrEmpty(logOptions))
        {
            forwardedArgs.Add("--log-opts");
            forwardedArgs.Add(logOptions);
        }

        if (!string.IsNullOrEmpty(platform))
        {
            forwardedArgs.Add("--platform");
            forwardedArgs.Add(platform);
        }

        forwardedArgs.Add(source);
        return RunGit([.. forwardedArgs]);
    }

    static int RunProtect(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteProtectHelp();
            return 0;
        }

        var forwardedArgs = new List<string>();
        string? logOptions = null;
        string source = ".";
        bool staged = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return 1;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsStagedFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--staged", out staged))
                {
                    return 1;
                }

                continue;
            }

            if (IsLogOptionsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
                {
                    return 1;
                }

                continue;
            }

            if (TryForwardCompatibilityRootFlag(args, ref i, forwardedArgs, out bool handledRootFlag))
            {
                if (handledRootFlag)
                {
                    continue;
                }
            }
            else
            {
                return 1;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return UnknownFlagExitCode;
            }
        }

        forwardedArgs.Add("--pre-commit");
        if (staged)
        {
            forwardedArgs.Add("--staged");
        }

        if (!string.IsNullOrEmpty(logOptions))
        {
            forwardedArgs.Add("--log-opts");
            forwardedArgs.Add(logOptions);
        }

        forwardedArgs.Add(source);
        return RunGit([.. forwardedArgs]);
    }

    private static bool TryForwardCompatibilityRootFlag(
        string[] args,
        ref int index,
        List<string> forwardedArgs,
        out bool handled)
    {
        string arg = args[index];
        bool hasValue = IsBaselinePathFlag(arg)
            || IsConfigFlag(arg)
            || IsEnableRuleFlag(arg)
            || IsGitleaksIgnorePathFlag(arg)
            || IsLogLevelFlag(arg)
            || IsMaxArchiveDepthFlag(arg)
            || IsMaxDecodeDepthFlag(arg)
            || IsMaxTargetMegabytesFlag(arg)
            || IsReportFormatFlag(arg)
            || IsReportTemplateFlag(arg)
            || IsTimeoutFlag(arg)
            || IsDiagnosticsFlag(arg)
            || IsDiagnosticsDirFlag(arg)
            || arg is "-r" or "--report-path"
            || arg.StartsWith("--report-path=", StringComparison.Ordinal)
            || arg.Equals("--exit-code", StringComparison.Ordinal)
            || arg.StartsWith("--exit-code=", StringComparison.Ordinal);
        bool isFlag = IsIgnoreGitleaksAllowFlag(arg)
            || IsNoBannerFlag(arg)
            || IsNoColorFlag(arg)
            || IsRedactFlag(arg)
            || IsVerboseFlag(arg);
        handled = hasValue || isFlag;
        if (!handled)
        {
            return true;
        }

        forwardedArgs.Add(arg);
        if (!hasValue || arg.Contains('='))
        {
            return true;
        }

        if (index + 1 >= args.Length)
        {
            Console.Error.WriteLine($"{arg} requires a value");
            return false;
        }

        forwardedArgs.Add(args[++index]);
        return true;
    }
}
