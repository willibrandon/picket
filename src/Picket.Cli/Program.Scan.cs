namespace Picket;

internal static partial class Program
{
    static int RunScan(string[] args)
    {
        var forwardedArgs = new List<string>();
        bool allowNonPublicProviderEndpoints = false;
        bool liveVerification = false;
        bool providerOptionSpecified = false;
        Uri? githubApiEndpoint = null;
        string? source = null;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsHelp(arg))
            {
                WriteScanHelp();
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

            if (IsVerifyFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--verify", out bool verify))
                {
                    return UnknownFlagExitCode;
                }

                if (verify)
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

                providerOptionSpecified = true;
                continue;
            }

            if (IsAllowNonPublicProviderEndpointsFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--allow-non-public-endpoints", out allowNonPublicProviderEndpoints))
                {
                    return UnknownFlagExitCode;
                }

                providerOptionSpecified = true;
                continue;
            }

            forwardedArgs.Add(arg);
        }

        if (providerOptionSpecified && !liveVerification)
        {
            Console.Error.WriteLine("--github-api-endpoint and --allow-non-public-endpoints require --verify");
            return UnknownFlagExitCode;
        }

        if (source is not null)
        {
            forwardedArgs.Add(source);
        }

        return RunDirectory(
            [.. forwardedArgs],
            nativeReportFormats: true,
            diagnosticsCommand: "scan",
            defaultRoot: ".",
            liveVerification: liveVerification
                ? new LiveVerificationConfiguration(githubApiEndpoint, allowNonPublicProviderEndpoints)
                : null);
    }
}
