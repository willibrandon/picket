using Picket.Compat;
using Picket.Engine;
using Picket.Rules;
using Picket.Verify;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Picket;

internal static partial class Program
{
    private const int AgentGuardBlockExitCode = 2;
    private const int AgentGuardDefaultMaxInputMegabytes = 1;
    private const int AgentGuardMaxInputMegabytes = 64;
    private const int AgentGuardMaxJsonDepth = 64;
    private const int AgentGuardMaxRuleIds = 10;
    private const int AgentGuardMaxTextValues = 4_096;
    private const int AgentGuardMaxRuleIdLength = 120;
    private const int AgentGuardMaxDecodeDepth = 5;
    private const string AgentGuardPreToolUseEvent = "PreToolUse";
    private const string AgentGuardPromptEvent = "UserPromptSubmit";
    private const string AgentGuardInputError = "Picket blocked the coding-agent request because the hook input could not be safely inspected.";
    private const string AgentGuardLimitError = "Picket blocked the coding-agent request because the hook input exceeded the configured limit.";
    private const string AgentGuardRulesError = "Picket blocked the coding-agent request because scanner rules could not be loaded.";
    private const string AgentGuardSource = "coding-agent-input";

    static async Task<int> RunAgentGuardAsync(string[] args, CancellationToken cancellationToken)
    {
        if (!TryParseAgentGuardOptions(
            args,
            out string? configPath,
            out List<string> additionalRulePacks,
            out int maxInputMegabytes))
        {
            Console.Error.WriteLine(AgentGuardInputError);
            return AgentGuardBlockExitCode;
        }

        if (!TryLoadAgentGuardRules(configPath, additionalRulePacks, out CompiledRuleSet? rules))
        {
            Console.Error.WriteLine(AgentGuardRulesError);
            return AgentGuardBlockExitCode;
        }

        int maxInputBytes = checked(maxInputMegabytes * 1_000_000);
        byte[] inputBuffer = ArrayPool<byte>.Shared.Rent(maxInputBytes + 1);
        try
        {
            using Stream standardInput = Console.OpenStandardInput();
            int inputLength = await ReadAgentGuardInputAsync(
                standardInput,
                inputBuffer.AsMemory(0, maxInputBytes + 1),
                cancellationToken).ConfigureAwait(false);
            if (inputLength > maxInputBytes)
            {
                Console.Error.WriteLine(AgentGuardLimitError);
                return AgentGuardBlockExitCode;
            }

            var ruleIds = new SortedSet<string>(StringComparer.Ordinal);
            int findingCount = 0;
            int textValueCount = 0;
            if (!TryScanAgentGuardEnvelope(
                inputBuffer.AsMemory(0, inputLength),
                rules,
                ruleIds,
                ref findingCount,
                ref textValueCount,
                cancellationToken))
            {
                Console.Error.WriteLine(AgentGuardInputError);
                return AgentGuardBlockExitCode;
            }

            if (findingCount == 0)
            {
                return 0;
            }

            WriteAgentGuardFindingBlock(findingCount, ruleIds);
            return AgentGuardBlockExitCode;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine(AgentGuardInputError);
            return AgentGuardBlockExitCode;
        }
        catch (Exception ex) when (ex is IOException
            or InvalidDataException
            or InvalidOperationException
            or ArgumentException
            or OverflowException
            or JsonException)
        {
            Console.Error.WriteLine(AgentGuardInputError);
            return AgentGuardBlockExitCode;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(inputBuffer, clearArray: true);
        }
    }

    private static bool TryParseAgentGuardOptions(
        string[] args,
        out string? configPath,
        out List<string> additionalRulePacks,
        out int maxInputMegabytes)
    {
        configPath = null;
        additionalRulePacks = [];
        maxInputMegabytes = AgentGuardDefaultMaxInputMegabytes;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (IsConfigFlag(arg))
            {
                if (!TryReadAgentGuardValue(args, ref i, "-c", "--config", out configPath)
                    || string.IsNullOrWhiteSpace(configPath))
                {
                    return false;
                }

                continue;
            }

            if (IsRulePackFlag(arg))
            {
                if (!TryReadAgentGuardValue(args, ref i, null, "--rule-pack", out string? rulePacks)
                    || !TryAddAgentGuardRulePacks(rulePacks, additionalRulePacks))
                {
                    return false;
                }

                continue;
            }

            if (arg.Equals("--max-input-megabytes", StringComparison.Ordinal)
                || arg.StartsWith("--max-input-megabytes=", StringComparison.Ordinal))
            {
                if (!TryReadAgentGuardValue(args, ref i, null, "--max-input-megabytes", out string? value)
                    || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out maxInputMegabytes)
                    || maxInputMegabytes is < 1 or > AgentGuardMaxInputMegabytes)
                {
                    return false;
                }

                continue;
            }

            if (TrySkipAgentGuardCompatibilityOption(args, ref i))
            {
                continue;
            }

            return false;
        }

        return true;
    }

    private static bool TryReadAgentGuardValue(
        string[] args,
        ref int index,
        string? shortName,
        string longName,
        [NotNullWhen(true)] out string? value)
    {
        string arg = args[index];
        string longNameWithEquals = string.Concat(longName, "=");
        if (arg.StartsWith(longNameWithEquals, StringComparison.Ordinal))
        {
            value = arg[longNameWithEquals.Length..];
            return value.Length != 0;
        }

        if (shortName is not null)
        {
            string shortNameWithEquals = string.Concat(shortName, "=");
            if (arg.StartsWith(shortNameWithEquals, StringComparison.Ordinal))
            {
                value = arg[shortNameWithEquals.Length..];
                return value.Length != 0;
            }
        }

        if (index + 1 >= args.Length)
        {
            value = null;
            return false;
        }

        value = args[++index];
        return value.Length != 0;
    }

    private static bool TryAddAgentGuardRulePacks(string value, List<string> additionalRulePacks)
    {
        bool found = false;
        foreach (string rulePack in value.Split(','))
        {
            string normalizedRulePack = rulePack.Trim().ToLowerInvariant();
            if (normalizedRulePack.Length == 0)
            {
                continue;
            }

            if (normalizedRulePack is not PicketRulePackNames.Strict and not PicketRulePackNames.Experimental)
            {
                return false;
            }

            found = true;
            if (!additionalRulePacks.Contains(normalizedRulePack, StringComparer.Ordinal))
            {
                additionalRulePacks.Add(normalizedRulePack);
            }
        }

        return found;
    }

    private static bool TrySkipAgentGuardCompatibilityOption(string[] args, ref int index)
    {
        string arg = args[index];
        if (IsLogLevelFlag(arg))
        {
            if (arg.Contains('='))
            {
                return arg[(arg.IndexOf('=') + 1)..].Length != 0;
            }

            if (index + 1 >= args.Length)
            {
                return false;
            }

            index++;
            return true;
        }

        if (IsVerboseFlag(arg))
        {
            return TryValidateAgentGuardBooleanOption(arg, "-v", "--verbose");
        }

        if (IsNoColorFlag(arg))
        {
            return TryValidateAgentGuardBooleanOption(arg, null, "--no-color");
        }

        if (IsNoBannerFlag(arg))
        {
            return TryValidateAgentGuardBooleanOption(arg, null, "--no-banner");
        }

        return false;
    }

    private static bool TryValidateAgentGuardBooleanOption(string arg, string? shortName, string longName)
    {
        if (arg.Equals(longName, StringComparison.Ordinal)
            || shortName is not null && arg.Equals(shortName, StringComparison.Ordinal))
        {
            return true;
        }

        int separator = arg.IndexOf('=');
        return separator > 0 && bool.TryParse(arg[(separator + 1)..], out _);
    }

    private static bool TryLoadAgentGuardRules(
        string? configPath,
        List<string> additionalRulePacks,
        [NotNullWhen(true)] out CompiledRuleSet? rules)
    {
        try
        {
            RuleSet ruleSet = PicketConfigLoader.LoadRuleSet(configPath, ".", [.. additionalRulePacks]);
            rules = CompiledRuleSet.Compile(ruleSet);
            rules.ValidateNativePredicates();
            return true;
        }
        catch (Exception ex) when (ex is IOException
            or InvalidDataException
            or InvalidOperationException
            or NotSupportedException
            or ArgumentException)
        {
            rules = null;
            return false;
        }
    }

    private static async Task<int> ReadAgentGuardInputAsync(
        Stream input,
        Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < destination.Length)
        {
            int read = await input.ReadAsync(destination[totalRead..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
        }

        return totalRead;
    }

    private static bool TryScanAgentGuardEnvelope(
        ReadOnlyMemory<byte> input,
        CompiledRuleSet rules,
        SortedSet<string> ruleIds,
        ref int findingCount,
        ref int textValueCount,
        CancellationToken cancellationToken)
    {
        if (input.IsEmpty)
        {
            return false;
        }

        using JsonDocument document = JsonDocument.Parse(input, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = AgentGuardMaxJsonDepth,
        });
        JsonElement root = document.RootElement;
        if (root.ValueKind is not JsonValueKind.Object
            || !TryGetUniqueAgentGuardProperty(root, "hook_event_name", out JsonElement eventNameElement)
            || eventNameElement.ValueKind is not JsonValueKind.String)
        {
            return false;
        }

        string? eventName = eventNameElement.GetString();
        if (eventName is AgentGuardPromptEvent)
        {
            return TryGetUniqueAgentGuardProperty(root, "prompt", out JsonElement prompt)
                && prompt.ValueKind is JsonValueKind.String
                && TryScanAgentGuardElement(
                    prompt,
                    rules,
                    ruleIds,
                    ref findingCount,
                    ref textValueCount,
                    cancellationToken);
        }

        if (eventName is AgentGuardPreToolUseEvent)
        {
            return TryGetUniqueAgentGuardProperty(root, "tool_input", out JsonElement toolInput)
                && TryScanAgentGuardElement(
                    toolInput,
                    rules,
                    ruleIds,
                    ref findingCount,
                    ref textValueCount,
                    cancellationToken);
        }

        return false;
    }

    private static bool TryGetUniqueAgentGuardProperty(
        JsonElement root,
        string propertyName,
        out JsonElement value)
    {
        bool found = false;
        value = default;
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!property.NameEquals(propertyName))
            {
                continue;
            }

            if (found)
            {
                value = default;
                return false;
            }

            found = true;
            value = property.Value;
        }

        return found;
    }

    private static bool TryScanAgentGuardElement(
        JsonElement element,
        CompiledRuleSet rules,
        SortedSet<string> ruleIds,
        ref int findingCount,
        ref int textValueCount,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (!TryScanAgentGuardElement(
                        property.Value,
                        rules,
                        ruleIds,
                        ref findingCount,
                        ref textValueCount,
                        cancellationToken))
                    {
                        return false;
                    }
                }

                return true;

            case JsonValueKind.Array:
                foreach (JsonElement item in element.EnumerateArray())
                {
                    if (!TryScanAgentGuardElement(
                        item,
                        rules,
                        ruleIds,
                        ref findingCount,
                        ref textValueCount,
                        cancellationToken))
                    {
                        return false;
                    }
                }

                return true;

            case JsonValueKind.String:
                textValueCount++;
                return textValueCount <= AgentGuardMaxTextValues
                    && ScanAgentGuardText(
                        element.GetString(),
                        rules,
                        ruleIds,
                        ref findingCount,
                        cancellationToken);

            default:
                return true;
        }
    }

    private static bool ScanAgentGuardText(
        string? text,
        CompiledRuleSet rules,
        SortedSet<string> ruleIds,
        ref int findingCount,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(text))
        {
            return true;
        }

        int byteCount = Encoding.UTF8.GetByteCount(text);
        byte[] bytes = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int bytesWritten = Encoding.UTF8.GetBytes(text, bytes);
            IReadOnlyList<Finding> findings = SecretScanner.Scan(new ScanRequest(
                bytes.AsMemory(0, bytesWritten),
                AgentGuardSource,
                rules,
                ignoreGitleaksAllow: false,
                maxDecodeDepth: AgentGuardMaxDecodeDepth,
                enableCSharpStringConcatenation: true,
                useGitleaksMaxTargetSemantics: false,
                isCancellationRequested: () => cancellationToken.IsCancellationRequested,
                cancellationToken: cancellationToken)
            {
                EnableNativeDetectors = true,
                EnableNativePredicates = true,
                EnableRandomnessScoring = true,
                PositionKind = FindingPositionKind.UnicodeCodePointsExclusive,
            });
            findings = OfflineSecretValidator.AnnotateAll(findings);
            findings = SecretRandomnessFindingProcessor.Apply(findings, rules);
            findingCount = checked(findingCount + findings.Count);
            foreach (Finding finding in findings)
            {
                ruleIds.Add(SanitizeHookFindingText(finding.RuleID, finding, AgentGuardMaxRuleIdLength));
            }

            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
        }
    }

    private static void WriteAgentGuardFindingBlock(int findingCount, SortedSet<string> ruleIds)
    {
        string findingLabel = findingCount == 1 ? "finding" : "findings";
        Console.Error.Write(
            $"Picket blocked the coding-agent request: {findingCount.ToString(CultureInfo.InvariantCulture)} secret {findingLabel}.");
        if (ruleIds.Count != 0)
        {
            Console.Error.Write(" Rule IDs: ");
            int displayed = 0;
            foreach (string ruleId in ruleIds)
            {
                if (displayed == AgentGuardMaxRuleIds)
                {
                    Console.Error.Write(", ...");
                    break;
                }

                if (displayed != 0)
                {
                    Console.Error.Write(", ");
                }

                Console.Error.Write(ruleId);
                displayed++;
            }

            Console.Error.Write('.');
        }

        Console.Error.WriteLine(" Secret values are not printed.");
    }
}
