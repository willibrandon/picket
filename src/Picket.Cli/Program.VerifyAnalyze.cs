namespace Picket;

internal static partial class Program
{
    static int RunVerify(string[] args)
    {
        var forwardedArgs = new List<string>();
        bool allowNonPublicProviderEndpoints = false;
        Uri? githubApiEndpoint = null;
        bool liveVerification = false;
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteVerifyHelp();
                return 0;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsOfflineVerificationFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--offline", out bool offline) || !offline)
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsLiveVerificationFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--live", out bool live))
                {
                    return UnknownFlagExitCode;
                }

                if (live)
                {
                    liveVerification = true;
                }

                continue;
            }

            if (IsGitHubApiEndpointFlag(arg))
            {
                if (!TryReadUriFlag(args, ref i, "--github-api-endpoint", out githubApiEndpoint))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            forwardedArgs.Add(arg);
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        return RunDirectory(
            [.. forwardedArgs],
            nativeReportFormats: true,
            diagnosticsCommand: "verify",
            defaultRoot: ".",
            allowValidationResultFilters: true,
            liveVerification: liveVerification
                ? new LiveVerificationConfiguration(githubApiEndpoint, allowNonPublicProviderEndpoints)
                : null);
    }

    static int RunAnalyze(string[] args)
    {
        var forwardedArgs = new List<string>();
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteAnalyzeHelp();
                return 0;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return UnknownFlagExitCode;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                continue;
            }

            if (IsOfflineVerificationFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--offline", out bool offline) || !offline)
                {
                    return UnknownFlagExitCode;
                }

                continue;
            }

            if (IsLiveVerificationFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--live", out bool live))
                {
                    return UnknownFlagExitCode;
                }

                if (live)
                {
                    Console.Error.WriteLine("live access analysis is not implemented yet; use --offline");
                    return 1;
                }

                continue;
            }

            forwardedArgs.Add(arg);
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        return RunDirectory(
            [.. forwardedArgs],
            nativeReportFormats: true,
            diagnosticsCommand: "analyze",
            defaultRoot: ".",
            allowValidationResultFilters: true,
            nativeResultWriter: TryWriteAnalysisReports);
    }
}
