using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using Picket.Store;
using Picket.Verify;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Picket;

internal static partial class Program
{
    private static bool s_rawScanCacheWarningWritten;

    static bool IsHelp(string arg)
    {
        return arg is "-h" or "--help" or "help";
    }

    static bool ContainsHelp(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (IsHelp(args[i]))
            {
                return true;
            }
        }

        return false;
    }

    static long CreateTimeoutTimestamp(int timeoutSeconds)
    {
        return timeoutSeconds == 0 ? 0 : Stopwatch.GetTimestamp() + timeoutSeconds * Stopwatch.Frequency;
    }

    static bool IsTimedOut(long timeoutTimestamp)
    {
        return timeoutTimestamp != 0 && Stopwatch.GetTimestamp() >= timeoutTimestamp;
    }

    static int CompleteRun(int exitCode, CompatibilityDiagnosticsSession? diagnosticsSession)
    {
        if (diagnosticsSession is null)
        {
            return exitCode;
        }

        return diagnosticsSession.TryComplete(exitCode, Console.Error) ? exitCode : 1;
    }

    static bool LooksBinary(ReadOnlySpan<byte> input)
    {
        int length = Math.Min(input.Length, BinaryProbeLength);
        for (int i = 0; i < length; i++)
        {
            if (input[i] == 0)
            {
                return true;
            }
        }

        return false;
    }

    static bool TryParseMegabytes(string value, out long? bytes)
    {
        if (!long.TryParse(value, out long megabytes) || megabytes < 0)
        {
            bytes = null;
            return false;
        }

        bytes = megabytes == 0 ? null : megabytes * 1_000_000;
        return true;
    }

    static bool TryReadMegabytesFlag(string[] args, ref int index, out long? maxTargetBytes)
    {
        return TryReadMegabytesFlag(args, ref index, "--max-target-megabytes", out maxTargetBytes);
    }

    static bool TryReadMegabytesFlag(string[] args, ref int index, string longName, out long? bytes)
    {
        if (TryReadStringFlag(args, ref index, longName, out string? value)
            && TryParseMegabytes(value, out bytes))
        {
            return true;
        }

        Console.Error.WriteLine($"{longName} requires a non-negative integer value");
        bytes = null;
        return false;
    }

    static bool TryResolveNativeProfile(string[] args, bool defaultNativeProfile, out bool nativeProfile)
    {
        nativeProfile = defaultNativeProfile;
        for (int i = 0; i < args.Length; i++)
        {
            if (!IsProfileFlag(args[i]))
            {
                continue;
            }

            if (!TryReadProfileFlag(args, ref i, out bool parsedNativeProfile))
            {
                return false;
            }

            nativeProfile = parsedNativeProfile;
        }

        return true;
    }

    static bool TryReadProfileFlag(string[] args, ref int index, out bool nativeProfile)
    {
        nativeProfile = false;
        if (!TryReadStringFlag(args, ref index, "--profile", out string? value))
        {
            return false;
        }

        if (value.Equals("picket", StringComparison.OrdinalIgnoreCase))
        {
            nativeProfile = true;
            return true;
        }

        Console.Error.WriteLine($"unsupported profile: {value}");
        return false;
    }

    static bool TryReadStringFlag(string[] args, ref int index, string longName, [NotNullWhen(true)] out string? value)
    {
        string arg = args[index];
        string longNameWithEquals = string.Concat(longName, "=");
        if (arg.StartsWith(longNameWithEquals, StringComparison.Ordinal))
        {
            value = arg[longNameWithEquals.Length..];
            return true;
        }

        if (index + 1 >= args.Length)
        {
            Console.Error.WriteLine($"{arg} requires a value");
            value = null;
            return false;
        }

        value = args[++index];
        return true;
    }

    static bool TryReadUriFlag(string[] args, ref int index, string longName, [NotNullWhen(true)] out Uri? value)
    {
        value = null;
        if (!TryReadStringFlag(args, ref index, longName, out string? text))
        {
            return false;
        }

        if (Uri.TryCreate(text, UriKind.Absolute, out value))
        {
            return true;
        }

        Console.Error.WriteLine($"{longName} requires an absolute URI value");
        return false;
    }

    static bool TryReadLiveTlsModeFlag(string[] args, ref int index, out GitHubSecretLiveValidatorTlsMode value)
    {
        if (!TryReadStringFlag(args, ref index, "--live-tls-mode", out string? text))
        {
            value = GitHubSecretLiveValidatorTlsMode.System;
            return false;
        }

        string normalized = text.Trim().ToLowerInvariant();
        if (normalized is "system" or "default")
        {
            value = GitHubSecretLiveValidatorTlsMode.System;
            return true;
        }

        if (normalized is "tls12-plus" or "tls12-or-later")
        {
            value = GitHubSecretLiveValidatorTlsMode.Tls12OrLater;
            return true;
        }

        Console.Error.WriteLine($"unsupported live TLS mode: {text}");
        value = GitHubSecretLiveValidatorTlsMode.System;
        return false;
    }

    static bool TryReadIntFlag(string[] args, ref int index, string longName, out int value)
    {
        if (TryReadStringFlag(args, ref index, longName, out string? text) && int.TryParse(text, out value))
        {
            return true;
        }

        Console.Error.WriteLine($"{longName} requires an integer value");
        value = 0;
        return false;
    }

    static bool TryReadNonNegativeIntFlag(string[] args, ref int index, string longName, out int value)
    {
        if (!TryReadIntFlag(args, ref index, longName, out value))
        {
            return false;
        }

        if (value >= 0)
        {
            return true;
        }

        Console.Error.WriteLine($"{longName} requires a non-negative integer value");
        value = 0;
        return false;
    }

    static bool TryReadNonNegativeMillisecondsFlag(string[] args, ref int index, string longName, out TimeSpan value)
    {
        if (TryReadNonNegativeIntFlag(args, ref index, longName, out int milliseconds))
        {
            value = TimeSpan.FromMilliseconds(milliseconds);
            return true;
        }

        value = TimeSpan.Zero;
        return false;
    }

    static bool TryReadRuleIdFlag(string[] args, ref int index, List<string> enabledRuleIds)
    {
        if (!TryReadStringFlag(args, ref index, "--enable-rule", out string? value))
        {
            return false;
        }

        foreach (string ruleId in value.Split(','))
        {
            string trimmedRuleId = ruleId.Trim();
            if (trimmedRuleId.Length != 0)
            {
                enabledRuleIds.Add(trimmedRuleId);
            }
        }

        return true;
    }

    static bool TryReadValidationResultsFlag(string[] args, ref int index, HashSet<string> validationResults)
    {
        if (!TryReadStringFlag(args, ref index, "--results", out string? value))
        {
            return false;
        }

        foreach (string result in value.Split(','))
        {
            string normalizedResult = result.Trim();
            if (normalizedResult.Length == 0)
            {
                continue;
            }

            if (!IsSupportedValidationResult(normalizedResult))
            {
                Console.Error.WriteLine($"unsupported verification result: {normalizedResult}");
                return false;
            }

            validationResults.Add(normalizedResult);
        }

        if (validationResults.Count != 0)
        {
            return true;
        }

        Console.Error.WriteLine("--results requires at least one verification result");
        return false;
    }

    static bool TryReadCacheOptions(
        string[] args,
        bool allowPruneOptions,
        out string? cacheDir,
        out string? configPath,
        out string source,
        out int maxDecodeDepth,
        out long? maxTargetBytes,
        out bool ignoreGitleaksAllow,
        out ScanCacheStorageMode cacheStorageMode,
        out bool pruneOtherKeys,
        out int? olderThanDays)
    {
        cacheDir = null;
        configPath = null;
        source = ".";
        maxDecodeDepth = 5;
        maxTargetBytes = null;
        ignoreGitleaksAllow = false;
        cacheStorageMode = ScanCacheStorageMode.SecretHashOnly;
        pruneOtherKeys = false;
        olderThanDays = null;
        bool sourceRead = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsCacheDirFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--cache-dir", out cacheDir))
                {
                    return false;
                }

                continue;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return false;
                }

                continue;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return false;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                sourceRead = true;
                continue;
            }

            if (IsMaxDecodeDepthFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
                {
                    return false;
                }

                continue;
            }

            if (IsMaxTargetMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, out maxTargetBytes))
                {
                    return false;
                }

                continue;
            }

            if (IsIgnoreGitleaksAllowFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--ignore-gitleaks-allow", out ignoreGitleaksAllow))
                {
                    return false;
                }

                continue;
            }

            if (IsCacheModeFlag(arg))
            {
                if (!TryReadScanCacheStorageMode(args, ref i, out cacheStorageMode))
                {
                    return false;
                }

                continue;
            }

            if (allowPruneOptions && IsOtherKeysFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--other-keys", out pruneOtherKeys))
                {
                    return false;
                }

                continue;
            }

            if (allowPruneOptions && IsOlderThanDaysFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--older-than-days", out int value))
                {
                    return false;
                }

                olderThanDays = value;
                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return false;
            }

            if (sourceRead)
            {
                Console.Error.WriteLine($"unexpected argument: {arg}");
                return false;
            }

            source = arg.Length == 0 ? "." : arg;
            sourceRead = true;
        }

        return true;
    }

    static bool TryReadCacheTransferOptions(
        string[] args,
        string archiveFlag,
        out string? cacheDir,
        out string? configPath,
        out string source,
        out int maxDecodeDepth,
        out long? maxTargetBytes,
        out bool ignoreGitleaksAllow,
        out ScanCacheStorageMode cacheStorageMode,
        out string? archivePath)
    {
        cacheDir = null;
        configPath = null;
        source = ".";
        maxDecodeDepth = 5;
        maxTargetBytes = null;
        ignoreGitleaksAllow = false;
        cacheStorageMode = ScanCacheStorageMode.SecretHashOnly;
        archivePath = null;
        bool sourceRead = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsCacheDirFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--cache-dir", out cacheDir))
                {
                    return false;
                }

                continue;
            }

            if (IsConfigFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--config", out configPath))
                {
                    return false;
                }

                continue;
            }

            if (IsSourceFlag(arg))
            {
                if (!TryReadStringFlag(args, ref i, "--source", out string? sourceValue))
                {
                    return false;
                }

                source = sourceValue.Length == 0 ? "." : sourceValue;
                sourceRead = true;
                continue;
            }

            if (IsMaxDecodeDepthFlag(arg))
            {
                if (!TryReadNonNegativeIntFlag(args, ref i, "--max-decode-depth", out maxDecodeDepth))
                {
                    return false;
                }

                continue;
            }

            if (IsMaxTargetMegabytesFlag(arg))
            {
                if (!TryReadMegabytesFlag(args, ref i, out maxTargetBytes))
                {
                    return false;
                }

                continue;
            }

            if (IsIgnoreGitleaksAllowFlag(arg))
            {
                if (!TryReadBooleanFlag(arg, "--ignore-gitleaks-allow", out ignoreGitleaksAllow))
                {
                    return false;
                }

                continue;
            }

            if (IsCacheModeFlag(arg))
            {
                if (!TryReadScanCacheStorageMode(args, ref i, out cacheStorageMode))
                {
                    return false;
                }

                continue;
            }

            if (IsCacheArchiveFlag(arg, archiveFlag))
            {
                if (!TryReadStringFlag(args, ref i, archiveFlag, out archivePath))
                {
                    return false;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.Error.WriteLine($"unknown flag: {arg}");
                return false;
            }

            if (sourceRead)
            {
                Console.Error.WriteLine($"unexpected argument: {arg}");
                return false;
            }

            source = arg.Length == 0 ? "." : arg;
            sourceRead = true;
        }

        return true;
    }

    static bool IsSupportedValidationResult(string value)
    {
        return value is "unknown"
            or "structurally-valid"
            or "test-credential"
            or "invalid"
            or "active"
            or "inactive"
            or "skipped"
            or "error";
    }

    static List<Finding> FilterValidationResults(IReadOnlyList<Finding> findings, HashSet<string> validationResults)
    {
        var filtered = new List<Finding>(findings.Count);
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            string validationState = finding.ValidationState.Length == 0 ? "unknown" : finding.ValidationState;
            if (validationResults.Contains(validationState))
            {
                filtered.Add(finding);
            }
        }

        return filtered;
    }

    static bool IsBaselinePathFlag(string arg)
    {
        return arg is "-b" or "--baseline-path"
            || arg.StartsWith("--baseline-path=", StringComparison.Ordinal);
    }

    static bool IsConfigFlag(string arg)
    {
        return arg is "-c" or "--config"
            || arg.StartsWith("--config=", StringComparison.Ordinal);
    }

    static bool IsCacheDirFlag(string arg)
    {
        return arg.Equals("--cache-dir", StringComparison.Ordinal)
            || arg.StartsWith("--cache-dir=", StringComparison.Ordinal);
    }

    static bool IsCacheModeFlag(string arg)
    {
        return arg.Equals("--cache-mode", StringComparison.Ordinal)
            || arg.StartsWith("--cache-mode=", StringComparison.Ordinal);
    }

    static bool IsOtherKeysFlag(string arg)
    {
        return arg.Equals("--other-keys", StringComparison.Ordinal)
            || arg.StartsWith("--other-keys=", StringComparison.Ordinal);
    }

    static bool IsOlderThanDaysFlag(string arg)
    {
        return arg.Equals("--older-than-days", StringComparison.Ordinal)
            || arg.StartsWith("--older-than-days=", StringComparison.Ordinal);
    }

    static bool IsCacheArchiveFlag(string arg, string longName)
    {
        return arg.Equals(longName, StringComparison.Ordinal)
            || arg.StartsWith(string.Concat(longName, "="), StringComparison.Ordinal);
    }

    static bool IsRulesTestPathFlag(string arg)
    {
        return arg.Equals("--path", StringComparison.Ordinal)
            || arg.StartsWith("--path=", StringComparison.Ordinal);
    }

    static bool IsGitleaksIgnorePathFlag(string arg)
    {
        return arg is "-i" or "--gitleaks-ignore-path"
            || arg.StartsWith("--gitleaks-ignore-path=", StringComparison.Ordinal);
    }

    static bool IsIgnoreGitleaksAllowFlag(string arg)
    {
        return arg.Equals("--ignore-gitleaks-allow", StringComparison.Ordinal)
            || arg.StartsWith("--ignore-gitleaks-allow=", StringComparison.Ordinal);
    }

    static bool IsMaxTargetMegabytesFlag(string arg)
    {
        return arg.Equals("--max-target-megabytes", StringComparison.Ordinal)
            || arg.StartsWith("--max-target-megabytes=", StringComparison.Ordinal);
    }

    static bool IsReportFormatFlag(string arg)
    {
        return arg is "-f" or "--report-format"
            || arg.StartsWith("--report-format=", StringComparison.Ordinal);
    }

    static bool IsReportTemplateFlag(string arg)
    {
        return arg.Equals("--report-template", StringComparison.Ordinal)
            || arg.StartsWith("--report-template=", StringComparison.Ordinal);
    }

    static bool IsEnableRuleFlag(string arg)
    {
        return arg.Equals("--enable-rule", StringComparison.Ordinal)
            || arg.StartsWith("--enable-rule=", StringComparison.Ordinal);
    }

    static bool IsLogLevelFlag(string arg)
    {
        return arg is "-l" or "--log-level"
            || arg.StartsWith("--log-level=", StringComparison.Ordinal);
    }

    static bool IsVerboseFlag(string arg)
    {
        return arg is "-v" or "--verbose"
            || arg.StartsWith("--verbose=", StringComparison.Ordinal);
    }

    static bool IsNoColorFlag(string arg)
    {
        return arg.Equals("--no-color", StringComparison.Ordinal)
            || arg.StartsWith("--no-color=", StringComparison.Ordinal);
    }

    static bool IsNoBannerFlag(string arg)
    {
        return arg.Equals("--no-banner", StringComparison.Ordinal)
            || arg.StartsWith("--no-banner=", StringComparison.Ordinal);
    }

    static bool IsMaxDecodeDepthFlag(string arg)
    {
        return arg.Equals("--max-decode-depth", StringComparison.Ordinal)
            || arg.StartsWith("--max-decode-depth=", StringComparison.Ordinal);
    }

    static bool IsMaxArchiveDepthFlag(string arg)
    {
        return arg.Equals("--max-archive-depth", StringComparison.Ordinal)
            || arg.StartsWith("--max-archive-depth=", StringComparison.Ordinal);
    }

    static bool IsMaxArchiveEntriesFlag(string arg)
    {
        return arg.Equals("--max-archive-entries", StringComparison.Ordinal)
            || arg.StartsWith("--max-archive-entries=", StringComparison.Ordinal);
    }

    static bool IsMaxArchiveMegabytesFlag(string arg)
    {
        return arg.Equals("--max-archive-megabytes", StringComparison.Ordinal)
            || arg.StartsWith("--max-archive-megabytes=", StringComparison.Ordinal);
    }

    static bool IsMaxArchiveRatioFlag(string arg)
    {
        return arg.Equals("--max-archive-ratio", StringComparison.Ordinal)
            || arg.StartsWith("--max-archive-ratio=", StringComparison.Ordinal);
    }

    static bool IsTimeoutFlag(string arg)
    {
        return arg.Equals("--timeout", StringComparison.Ordinal)
            || arg.StartsWith("--timeout=", StringComparison.Ordinal);
    }

    static bool IsDiagnosticsFlag(string arg)
    {
        return arg.Equals("--diagnostics", StringComparison.Ordinal)
            || arg.StartsWith("--diagnostics=", StringComparison.Ordinal);
    }

    static bool IsDiagnosticsDirFlag(string arg)
    {
        return arg.Equals("--diagnostics-dir", StringComparison.Ordinal)
            || arg.StartsWith("--diagnostics-dir=", StringComparison.Ordinal);
    }

    static bool IsOfflineVerificationFlag(string arg)
    {
        return arg.Equals("--offline", StringComparison.Ordinal)
            || arg.StartsWith("--offline=", StringComparison.Ordinal);
    }

    static bool IsLiveVerificationFlag(string arg)
    {
        return arg.Equals("--live", StringComparison.Ordinal)
            || arg.StartsWith("--live=", StringComparison.Ordinal);
    }

    static bool IsVerifyFlag(string arg)
    {
        return arg.Equals("--verify", StringComparison.Ordinal)
            || arg.StartsWith("--verify=", StringComparison.Ordinal);
    }

    static bool IsGitHubApiEndpointFlag(string arg)
    {
        return arg.Equals("--github-api-endpoint", StringComparison.Ordinal)
            || arg.StartsWith("--github-api-endpoint=", StringComparison.Ordinal);
    }

    static bool IsGitHubApiProxyFlag(string arg)
    {
        return arg.Equals("--github-api-proxy", StringComparison.Ordinal)
            || arg.StartsWith("--github-api-proxy=", StringComparison.Ordinal);
    }

    static bool IsLiveTlsModeFlag(string arg)
    {
        return arg.Equals("--live-tls-mode", StringComparison.Ordinal)
            || arg.StartsWith("--live-tls-mode=", StringComparison.Ordinal);
    }

    static bool IsLiveRateLimitMillisecondsFlag(string arg)
    {
        return arg.Equals("--live-rate-limit-ms", StringComparison.Ordinal)
            || arg.StartsWith("--live-rate-limit-ms=", StringComparison.Ordinal);
    }

    static bool IsLiveProviderRateLimitMillisecondsFlag(string arg)
    {
        return arg.Equals("--live-provider-rate-limit-ms", StringComparison.Ordinal)
            || arg.StartsWith("--live-provider-rate-limit-ms=", StringComparison.Ordinal);
    }

    static bool IsAllowNonPublicProviderEndpointsFlag(string arg)
    {
        return arg.Equals("--allow-non-public-endpoints", StringComparison.Ordinal)
            || arg.StartsWith("--allow-non-public-endpoints=", StringComparison.Ordinal);
    }

    static bool IsValidationResultsFlag(string arg)
    {
        return arg.Equals("--results", StringComparison.Ordinal)
            || arg.StartsWith("--results=", StringComparison.Ordinal);
    }

    static bool IsOnlyVerifiedFlag(string arg)
    {
        return arg.Equals("--only-verified", StringComparison.Ordinal)
            || arg.StartsWith("--only-verified=", StringComparison.Ordinal);
    }

    static bool IsPrintConfigFlag(string arg)
    {
        return arg.Equals("--print-config", StringComparison.Ordinal)
            || arg.StartsWith("--print-config=", StringComparison.Ordinal);
    }

    static bool IsSourceFlag(string arg)
    {
        return arg is "-s" or "--source"
            || arg.StartsWith("--source=", StringComparison.Ordinal);
    }

    static bool IsProfileFlag(string arg)
    {
        return arg.Equals("--profile", StringComparison.Ordinal)
            || arg.StartsWith("--profile=", StringComparison.Ordinal);
    }

    static bool IsHooksRepoFlag(string arg)
    {
        return arg.Equals("--repo", StringComparison.Ordinal)
            || arg.StartsWith("--repo=", StringComparison.Ordinal);
    }

    static bool IsHookCommandFlag(string arg)
    {
        return arg.Equals("--command", StringComparison.Ordinal)
            || arg.StartsWith("--command=", StringComparison.Ordinal);
    }

    static bool IsForceFlag(string arg)
    {
        return arg.Equals("--force", StringComparison.Ordinal)
            || arg.StartsWith("--force=", StringComparison.Ordinal);
    }

    static bool IsNativeIgnorePathFlag(string arg)
    {
        return arg.Equals("--ignore-path", StringComparison.Ordinal)
            || arg.StartsWith("--ignore-path=", StringComparison.Ordinal);
    }

    static bool IsNoIgnoreFlag(string arg)
    {
        return arg.Equals("--no-ignore", StringComparison.Ordinal)
            || arg.StartsWith("--no-ignore=", StringComparison.Ordinal);
    }

    static bool IsOpenFlag(string arg)
    {
        return arg.Equals("--open", StringComparison.Ordinal)
            || arg.StartsWith("--open=", StringComparison.Ordinal);
    }

    static bool IsNoGitFlag(string arg)
    {
        return arg.Equals("--no-git", StringComparison.Ordinal)
            || arg.StartsWith("--no-git=", StringComparison.Ordinal);
    }

    static bool IsPipeFlag(string arg)
    {
        return arg.Equals("--pipe", StringComparison.Ordinal)
            || arg.StartsWith("--pipe=", StringComparison.Ordinal);
    }

    static bool IsFollowSymlinksFlag(string arg)
    {
        return arg.Equals("--follow-symlinks", StringComparison.Ordinal)
            || arg.StartsWith("--follow-symlinks=", StringComparison.Ordinal);
    }

    static bool IsLogOptionsFlag(string arg)
    {
        return arg.Equals("--log-opts", StringComparison.Ordinal)
            || arg.StartsWith("--log-opts=", StringComparison.Ordinal);
    }

    static bool IsPlatformFlag(string arg)
    {
        return arg.Equals("--platform", StringComparison.Ordinal)
            || arg.StartsWith("--platform=", StringComparison.Ordinal);
    }

    static bool IsPreCommitFlag(string arg)
    {
        return arg.Equals("--pre-commit", StringComparison.Ordinal)
            || arg.StartsWith("--pre-commit=", StringComparison.Ordinal);
    }

    static bool IsStagedFlag(string arg)
    {
        return arg.Equals("--staged", StringComparison.Ordinal)
            || arg.StartsWith("--staged=", StringComparison.Ordinal);
    }

    static bool TryReadBooleanFlag(string arg, string longName, out bool value)
    {
        if (arg.Equals(longName, StringComparison.Ordinal))
        {
            value = true;
            return true;
        }

        string longNameWithEquals = string.Concat(longName, "=");
        string text = arg[longNameWithEquals.Length..];
        if (bool.TryParse(text, out value))
        {
            return true;
        }

        Console.Error.WriteLine($"{longName} requires a boolean value");
        return false;
    }

    static bool TryReadBooleanFlagWithShort(string arg, string shortName, string longName, out bool value)
    {
        if (arg.Equals(shortName, StringComparison.Ordinal))
        {
            value = true;
            return true;
        }

        return TryReadBooleanFlag(arg, longName, out value);
    }

    static bool TryHandleCommonCompatibilityFlag(string[] args, ref int index, out bool handled)
    {
        string arg = args[index];
        handled = true;
        if (IsLogLevelFlag(arg))
        {
            return TryReadStringFlag(args, ref index, "--log-level", out _);
        }

        if (IsVerboseFlag(arg))
        {
            return TryReadBooleanFlagWithShort(arg, "-v", "--verbose", out _);
        }

        if (IsNoColorFlag(arg))
        {
            return TryReadBooleanFlag(arg, "--no-color", out _);
        }

        if (IsNoBannerFlag(arg))
        {
            return TryReadBooleanFlag(arg, "--no-banner", out _);
        }

        handled = false;
        return true;
    }

    static bool IsRedactFlag(string arg)
    {
        return arg.Equals("--redact", StringComparison.Ordinal)
            || arg.StartsWith("--redact=", StringComparison.Ordinal);
    }

    static bool TryReadRedactionPercent(string[] args, ref int index, out int redactionPercent)
    {
        string arg = args[index];
        if (arg.Equals("--redact", StringComparison.Ordinal))
        {
            if (index + 1 < args.Length && int.TryParse(args[index + 1], out int parsedRedactionPercent))
            {
                if (!IsValidRedactionPercent(parsedRedactionPercent))
                {
                    Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
                    redactionPercent = 0;
                    return false;
                }

                redactionPercent = parsedRedactionPercent;
                index++;
                return true;
            }

            redactionPercent = 100;
            return true;
        }

        string value = arg["--redact=".Length..];
        if (TryParseRedactionPercent(value, out redactionPercent))
        {
            return true;
        }

        Console.Error.WriteLine("--redact requires an integer value from 0 through 100");
        return false;
    }

    static bool TryParseRedactionPercent(string value, out int redactionPercent)
    {
        if (!int.TryParse(value, out redactionPercent) || !IsValidRedactionPercent(redactionPercent))
        {
            redactionPercent = 0;
            return false;
        }

        return true;
    }

    static bool IsValidRedactionPercent(int redactionPercent)
    {
        return redactionPercent is >= 0 and <= 100;
    }

    static bool TryReadScanCacheStorageMode(string[] args, ref int index, out ScanCacheStorageMode mode)
    {
        if (!TryReadStringFlag(args, ref index, "--cache-mode", out string? value))
        {
            mode = ScanCacheStorageMode.SecretHashOnly;
            return false;
        }

        if (TryParseScanCacheStorageMode(value, out mode))
        {
            return true;
        }

        Console.Error.WriteLine("unsupported cache mode: {0}", value);
        return false;
    }

    static bool TryParseScanCacheStorageMode(string value, out ScanCacheStorageMode mode)
    {
        string normalized = value.Trim().ToLowerInvariant();
        if (normalized.Equals("raw", StringComparison.Ordinal))
        {
            mode = ScanCacheStorageMode.Raw;
            return true;
        }

        if (normalized.Equals("default", StringComparison.Ordinal))
        {
            mode = ScanCacheStorageMode.SecretHashOnly;
            return true;
        }

        if (normalized is "secret-hash-only" or "hash-only")
        {
            mode = ScanCacheStorageMode.SecretHashOnly;
            return true;
        }

        mode = ScanCacheStorageMode.SecretHashOnly;
        return false;
    }

    static void WarnIfRawScanCacheMode(ScanCacheStorageMode mode)
    {
        if (mode != ScanCacheStorageMode.Raw || s_rawScanCacheWarningWritten)
        {
            return;
        }

        s_rawScanCacheWarningWritten = true;
        Console.Error.WriteLine("warning: raw scan-cache mode stores finding match, secret, and line text; use secret-hash-only for shared or public caches");
    }

    static bool TryValidatePlatform(string? platform)
    {
        if (TryNormalizeScmPlatform(platform, out _))
        {
            return true;
        }

        Console.Error.WriteLine($"invalid scm platform value: {platform}");
        return false;
    }

    static string NormalizeScmPlatform(string? platform)
    {
        return TryNormalizeScmPlatform(platform, out string? normalizedPlatform) ? normalizedPlatform : "unknown";
    }

    static bool TryNormalizeScmPlatform(string? platform, [NotNullWhen(true)] out string? normalizedPlatform)
    {
        if (string.IsNullOrWhiteSpace(platform))
        {
            normalizedPlatform = "unknown";
            return true;
        }

        normalizedPlatform = platform.Trim().ToLowerInvariant();
        if (normalizedPlatform is "unknown" or "none" or "github" or "gitlab" or "azuredevops" or "gitea" or "bitbucket")
        {
            return true;
        }

        normalizedPlatform = null;
        return false;
    }

    static string GetScmPlatformFromRemoteUrl(string remoteUrl)
    {
        if (!Uri.TryCreate(remoteUrl, UriKind.Absolute, out Uri? uri))
        {
            return "unknown";
        }

        return uri.Host.ToLowerInvariant() switch
        {
            "github.com" => "github",
            "gitlab.com" => "gitlab",
            "dev.azure.com" => "azuredevops",
            "visualstudio.com" => "azuredevops",
            "gitea.com" => "gitea",
            "code.forgejo.org" => "gitea",
            "codeberg.org" => "gitea",
            "bitbucket.org" => "bitbucket",
            _ => "unknown",
        };
    }

    static bool TryLoadRules(
        string? configPath,
        string source,
        IReadOnlyList<string> enabledRuleIds,
        bool nativeConfig,
        [NotNullWhen(true)] out CompiledRuleSet? rules)
    {
        try
        {
            RuleSet ruleSet = nativeConfig
                ? PicketConfigLoader.LoadRuleSet(configPath, source)
                : GitleaksConfigLoader.LoadRuleSet(configPath, source);
            ruleSet = FilterEnabledRules(ruleSet, enabledRuleIds);
            rules = CompiledRuleSet.Compile(ruleSet);
            return true;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or NotSupportedException or ArgumentException)
        {
            Console.Error.WriteLine(ex.Message);
            rules = null;
            return false;
        }
    }

    static bool TryOpenNativeScanCache(
        string cacheDir,
        string? configPath,
        string source,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool ignoreGitleaksAllow,
        ScanCacheStorageMode cacheStorageMode,
        [NotNullWhen(true)] out PicketScanCache? scanCache)
    {
        scanCache = null;
        if (!TryLoadRules(configPath, source, [], nativeConfig: true, out CompiledRuleSet? rules))
        {
            return false;
        }

        try
        {
            WarnIfRawScanCacheMode(cacheStorageMode);
            scanCache = PicketScanCache.Open(cacheDir, CreateNativeScanCacheKey(rules, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode));
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"failed to open cache: {ex.Message}");
            return false;
        }
    }

    static ScanCacheKey CreateNativeScanCacheKey(
        CompiledRuleSet rules,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool ignoreGitleaksAllow,
        ScanCacheStorageMode cacheStorageMode)
    {
        return ScanCacheKey.Create(
            rules.Fingerprint,
            maxDecodeDepth,
            maxTargetBytes,
            ignoreGitleaksAllow,
            CreateNativeScanCacheAddressMode(rules, maxDecodeDepth),
            cacheStorageMode);
    }

    static ScanCacheAddressMode CreateNativeScanCacheAddressMode(CompiledRuleSet rules, int maxDecodeDepth)
    {
        ArgumentNullException.ThrowIfNull(rules);
        if (rules.UsesPathSensitiveMatching)
        {
            return ScanCacheAddressMode.Path;
        }

        return maxDecodeDepth > 0 ? ScanCacheAddressMode.FileExtension : ScanCacheAddressMode.Content;
    }
}
