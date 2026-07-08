using Picket.Rules;

namespace Picket.Engine;

internal static class GcpServiceAccountKeyMatcher
{
    private const int CancellationPollInterval = 4096;
    private const int MaxObjectLength = 16 * 1024;
    private const int MaxPrefixSearchLength = 4 * 1024;
    private const string Pattern = """"type"\s*:\s*"service_account"""";
    private const string RuleId = "picket-gcp-service-account-key";

    internal static bool CanHandle(SecretRule rule)
    {
        return rule.Id.Equals(RuleId, StringComparison.Ordinal)
            && rule.Pattern.Equals(Pattern, StringComparison.Ordinal)
            && rule.SecretGroup == 0;
    }

    internal static bool TryFind(
        ReadOnlySpan<byte> input,
        int startAt,
        Func<bool>? isCancellationRequested,
        out int matchStart,
        out int matchEnd)
    {
        int searchStart = startAt;
        while (searchStart < input.Length)
        {
            if (ShouldPoll(searchStart, startAt) && IsCancellationRequested(isCancellationRequested))
            {
                break;
            }

            int markerOffset = input[searchStart..].IndexOf("\"service_account\""u8);
            if (markerOffset < 0)
            {
                break;
            }

            int markerStart = searchStart + markerOffset;
            if (TryFindObjectStart(input, markerStart, out int objectStart)
                && TryFindObjectEnd(input, objectStart, out int objectEnd)
                && HasRequiredMarkers(input[objectStart..objectEnd]))
            {
                matchStart = objectStart;
                matchEnd = objectEnd;
                return true;
            }

            searchStart = markerStart + 1;
        }

        matchStart = 0;
        matchEnd = 0;
        return false;
    }

    private static bool IsCancellationRequested(Func<bool>? isCancellationRequested)
    {
        return isCancellationRequested is not null && isCancellationRequested();
    }

    private static bool ShouldPoll(int position, int start)
    {
        return position == start || (position - start) % CancellationPollInterval == 0;
    }

    private static bool TryFindObjectStart(ReadOnlySpan<byte> input, int before, out int objectStart)
    {
        int lowerBound = Math.Max(0, before - MaxPrefixSearchLength);
        for (int i = before; i >= lowerBound; i--)
        {
            if (input[i] == (byte)'{')
            {
                objectStart = i;
                return true;
            }
        }

        objectStart = 0;
        return false;
    }

    private static bool TryFindObjectEnd(ReadOnlySpan<byte> input, int objectStart, out int objectEnd)
    {
        int limit = Math.Min(input.Length, objectStart + MaxObjectLength);
        int depth = 0;
        bool escaped = false;
        bool inString = false;
        for (int i = objectStart; i < limit; i++)
        {
            byte value = input[i];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (value == (byte)'\\')
                {
                    escaped = true;
                }
                else if (value == (byte)'"')
                {
                    inString = false;
                }

                continue;
            }

            if (value == (byte)'"')
            {
                inString = true;
                continue;
            }

            if (value == (byte)'{')
            {
                depth++;
                continue;
            }

            if (value == (byte)'}')
            {
                depth--;
                if (depth == 0)
                {
                    objectEnd = i + 1;
                    return true;
                }
            }
        }

        objectEnd = 0;
        return false;
    }

    private static bool HasRequiredMarkers(ReadOnlySpan<byte> candidate)
    {
        return candidate.IndexOf("\"type\""u8) >= 0
            && candidate.IndexOf("\"service_account\""u8) >= 0
            && candidate.IndexOf("\"project_id\""u8) >= 0
            && candidate.IndexOf("\"private_key_id\""u8) >= 0
            && candidate.IndexOf("\"private_key\""u8) >= 0
            && candidate.IndexOf("-----BEGIN PRIVATE KEY-----"u8) >= 0
            && candidate.IndexOf("\"client_email\""u8) >= 0
            && candidate.IndexOf(".iam.gserviceaccount.com"u8) >= 0
            && candidate.IndexOf("\"token_uri\""u8) >= 0
            && candidate.IndexOf("https://oauth2.googleapis.com/token"u8) >= 0;
    }
}
