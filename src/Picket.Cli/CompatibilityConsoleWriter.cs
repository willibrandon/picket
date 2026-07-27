using Picket.Engine;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Picket;

internal static class CompatibilityConsoleWriter
{
    private const string AnsiBold = "\u001b[1m";
    private const string AnsiGray = "\u001b[90m";
    private const string AnsiGreen = "\u001b[32m";
    private const string AnsiMatch = "\u001b[38;2;245;212;69m";
    private const string AnsiReset = "\u001b[0m";
    private const string AnsiSecret = "\u001b[1;3;38;2;240;92;7m";
    private const string AnsiSecretRedirected = "\u001b[1;3;m";
    private const string AnsiWarn = "\u001b[33m";
    private const string Banner = """

            ○
            │╲
            │ ○
            ○ ░
            ░    picket


        """;

    internal static void WriteBanner(CompatibilityConsoleOptions options)
    {
        if (!options.NoBanner)
        {
            Console.Error.Write(Banner);
        }
    }

    internal static void WriteGitCommitCount(CompatibilityConsoleOptions options, int commitCount)
    {
        WriteLog(
            options,
            CompatibilityLogLevel.Info,
            $"{commitCount.ToString(CultureInfo.InvariantCulture)} commits scanned.");
    }

    internal static void WriteSummary(
        CompatibilityConsoleOptions options,
        IReadOnlyList<Finding> findings,
        bool partialScan)
    {
        long totalBytes = options.Metrics.TotalBytes;
        string bytesMessage = $"scanned ~{totalBytes.ToString(CultureInfo.InvariantCulture)} bytes ({FormatBytes(totalBytes)})";
        if (!partialScan)
        {
            WriteLog(
                options,
                CompatibilityLogLevel.Info,
                $"{bytesMessage} in {FormatDuration(Stopwatch.GetElapsedTime(options.StartTimestamp))}");
            WriteLog(
                options,
                findings.Count == 0 ? CompatibilityLogLevel.Info : CompatibilityLogLevel.Warn,
                findings.Count == 0
                    ? "no leaks found"
                    : $"leaks found: {findings.Count.ToString(CultureInfo.InvariantCulture)}");
            return;
        }

        WriteLog(options, CompatibilityLogLevel.Warn, bytesMessage);
        WriteLog(
            options,
            CompatibilityLogLevel.Warn,
            $"partial scan completed in {FormatDuration(Stopwatch.GetElapsedTime(options.StartTimestamp))}");
        WriteLog(
            options,
            CompatibilityLogLevel.Warn,
            findings.Count == 0
                ? "no leaks found in partial scan"
                : $"{findings.Count.ToString(CultureInfo.InvariantCulture)} leaks found in partial scan");
    }

    internal static void WriteUnknownLogLevel(string value)
    {
        WriteColoredLog(CompatibilityLogLevel.Warn, $"unknown log level: {value}");
    }

    internal static void WriteVerboseFindings(
        CompatibilityConsoleOptions options,
        IReadOnlyList<Finding> findings)
    {
        if (!options.Verbose)
        {
            return;
        }

        for (int i = 0; i < findings.Count; i++)
        {
            WriteVerboseFinding(options, findings[i]);
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes == 0)
        {
            return "0";
        }

        const long Kilobyte = 1_000;
        const long Megabyte = Kilobyte * 1_000;
        const long Gigabyte = Megabyte * 1_000;
        float value = bytes;
        string unit = "bytes";
        if (bytes >= Gigabyte)
        {
            value /= Gigabyte;
            unit = "GB";
        }
        else if (bytes >= Megabyte)
        {
            value /= Megabyte;
            unit = "MB";
        }
        else if (bytes >= Kilobyte)
        {
            value /= Kilobyte;
            unit = "KB";
        }

        string formatted = value.ToString("0.00", CultureInfo.InvariantCulture);
        if (formatted.EndsWith(".00", StringComparison.Ordinal))
        {
            formatted = formatted[..^3];
        }

        return $"{formatted} {unit}";
    }

    private static string FormatDuration(TimeSpan duration)
    {
        double totalNanoseconds = duration.TotalNanoseconds;
        if (totalNanoseconds < 1_000)
        {
            return $"{Math.Round(totalNanoseconds, MidpointRounding.AwayFromZero).ToString(CultureInfo.InvariantCulture)}ns";
        }

        if (totalNanoseconds < 1_000_000)
        {
            return FormatDurationValue(totalNanoseconds / 1_000, "µs");
        }

        if (totalNanoseconds < 1_000_000_000)
        {
            return FormatDurationValue(totalNanoseconds / 1_000_000, "ms");
        }

        if (duration.TotalSeconds < 60)
        {
            return FormatDurationValue(duration.TotalSeconds, "s");
        }

        return duration.ToString("g", CultureInfo.InvariantCulture);
    }

    private static string FormatDurationValue(double value, string suffix)
    {
        double scale = value switch
        {
            >= 100 => 1,
            >= 10 => 0.1,
            _ => 0.01,
        };
        double rounded = Math.Round(value / scale, MidpointRounding.AwayFromZero) * scale;
        return string.Concat(rounded.ToString("0.##", CultureInfo.InvariantCulture), suffix);
    }

    private static bool IsEnabled(
        CompatibilityConsoleOptions options,
        CompatibilityLogLevel messageLevel)
    {
        return messageLevel >= options.LogLevel;
    }

    private static void WriteField(TextWriter writer, string label, object value)
    {
        writer.Write(label.PadRight(12));
        writer.Write(' ');
        writer.Write(value);
        writer.Write('\n');
    }

    private static void WriteLog(
        CompatibilityConsoleOptions options,
        CompatibilityLogLevel level,
        string message)
    {
        if (!IsEnabled(options, level))
        {
            return;
        }

        if (options.NoColor)
        {
            string levelName = level == CompatibilityLogLevel.Warn ? "WRN" : "INF";
            Console.Error.Write(
                $"{DateTime.Now.ToString("h:mmtt", CultureInfo.InvariantCulture)} {levelName} {message}\n");
            return;
        }

        WriteColoredLog(level, message);
    }

    private static void WriteColoredLog(CompatibilityLogLevel level, string message)
    {
        string levelName = level == CompatibilityLogLevel.Warn ? "WRN" : "INF";
        string levelColor = level == CompatibilityLogLevel.Warn ? AnsiWarn : AnsiGreen;
        Console.Error.Write(AnsiGray);
        Console.Error.Write(DateTime.Now.ToString("h:mmtt", CultureInfo.InvariantCulture));
        Console.Error.Write(AnsiReset);
        Console.Error.Write(' ');
        Console.Error.Write(levelColor);
        Console.Error.Write(levelName);
        Console.Error.Write(AnsiReset);
        Console.Error.Write(' ');
        Console.Error.Write(AnsiBold);
        Console.Error.Write(message);
        Console.Error.Write(AnsiReset);
        Console.Error.Write('\n');
    }

    private static void WriteVerboseFinding(
        CompatibilityConsoleOptions options,
        Finding finding)
    {
        TextWriter writer = Console.Out;
        string match = finding.Match.Trim();
        string secret = finding.Secret.Trim();
        string displayMatch = options.NoColor
            ? match
            : ColorizeMatch(match, secret);
        string displaySecret = options.NoColor
            ? secret
            : ColorizeSecret(secret);
        WriteField(writer, "Finding:", displayMatch);
        WriteField(writer, "Secret:", displaySecret);
        WriteField(writer, "RuleID:", finding.RuleID);
        WriteField(writer, "Entropy:", finding.Entropy.ToString("F6", CultureInfo.InvariantCulture));
        if (finding.File.Length == 0)
        {
            WriteRequiredFindings(options, writer, finding.RequiredFindings);
            writer.Write('\n');
            return;
        }

        if (finding.Tags.Count != 0)
        {
            WriteField(writer, "Tags:", $"[{string.Join(' ', finding.Tags)}]");
        }

        WriteField(writer, "File:", finding.File);
        WriteField(writer, "Line:", finding.StartLine.ToString(CultureInfo.InvariantCulture));
        if (finding.Commit.Length == 0)
        {
            WriteField(writer, "Fingerprint:", finding.Fingerprint);
            WriteRequiredFindings(options, writer, finding.RequiredFindings);
            writer.Write('\n');
            return;
        }

        WriteField(writer, "Commit:", finding.Commit);
        WriteField(writer, "Author:", finding.Author);
        WriteField(writer, "Email:", finding.Email);
        WriteField(writer, "Date:", finding.Date);
        WriteField(writer, "Fingerprint:", finding.Fingerprint);
        if (finding.Link.Length != 0)
        {
            WriteField(writer, "Link:", finding.Link);
        }

        WriteRequiredFindings(options, writer, finding.RequiredFindings);
        writer.Write('\n');
    }

    private static void WriteRequiredFindings(
        CompatibilityConsoleOptions options,
        TextWriter writer,
        IReadOnlyList<RequiredFinding> requiredFindings)
    {
        for (int i = 0; i < requiredFindings.Count; i++)
        {
            RequiredFinding requiredFinding = requiredFindings[i];
            string secret = requiredFinding.Secret.Trim();
            if (secret.Length > 40)
            {
                secret = string.Concat(secret.AsSpan(0, 37), "...");
            }

            writer.Write(i == 0 ? "Required:".PadRight(12) : new string(' ', 12));
            writer.Write(' ');
            writer.Write(requiredFinding.RuleID);
            writer.Write(':');
            writer.Write(requiredFinding.StartLine.ToString(CultureInfo.InvariantCulture));
            writer.Write(':');
            if (!options.NoColor)
            {
                writer.Write("\u001b[38;2;191;148;120m");
            }

            writer.Write(secret);
            if (!options.NoColor)
            {
                writer.Write(AnsiReset);
            }

            writer.Write('\n');
        }
    }

    private static string ColorizeMatch(string match, string secret)
    {
        int secretIndex = match.IndexOf(secret, StringComparison.Ordinal);
        if (secretIndex < 0)
        {
            return match;
        }

        var builder = new StringBuilder(match.Length + 32);
        if (!Console.IsOutputRedirected)
        {
            builder.Append(AnsiMatch);
        }

        builder.Append(match.AsSpan(0, secretIndex));
        builder.Append(Console.IsOutputRedirected ? AnsiSecretRedirected : AnsiSecret);
        builder.Append(TruncateSecret(secret));
        builder.Append(AnsiReset);
        if (!Console.IsOutputRedirected)
        {
            builder.Append(AnsiMatch);
        }

        builder.Append(match.AsSpan(secretIndex + secret.Length));
        if (!Console.IsOutputRedirected)
        {
            builder.Append(AnsiReset);
        }

        return builder.ToString();
    }

    private static string ColorizeSecret(string secret)
    {
        string style = Console.IsOutputRedirected ? AnsiSecretRedirected : AnsiSecret;
        return string.Concat(style, TruncateSecret(secret), AnsiReset);
    }

    private static string TruncateSecret(string secret)
    {
        return secret.Length > 100
            ? string.Concat(secret.AsSpan(0, 100), "...")
            : secret;
    }
}
