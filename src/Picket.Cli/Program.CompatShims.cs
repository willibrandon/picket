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
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsNoGitFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--no-git", out noGit))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsPipeFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--pipe", out pipe))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsFollowSymlinksFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--follow-symlinks", out followSymlinks))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsLogOptionsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--log-opts", out logOptions))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsPlatformFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--platform", out platform))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            forwardedArgs.Add(arg);
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
        string source = ".";
        bool staged = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsStagedFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--staged", out staged))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsLogOptionsFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--log-opts", out _))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            forwardedArgs.Add(arg);
        }

        forwardedArgs.Add("--pre-commit");
        if (staged)
        {
            forwardedArgs.Add("--staged");
        }

        forwardedArgs.Add(source);
        return RunGit([.. forwardedArgs]);
    }
}
