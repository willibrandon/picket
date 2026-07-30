using Picket.Compat;
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
                $"{bytesMessage} in {GitleaksDurationFormatter.Format(Stopwatch.GetElapsedTime(options.StartTimestamp))}");
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
            $"partial scan completed in {GitleaksDurationFormatter.Format(Stopwatch.GetElapsedTime(options.StartTimestamp))}");
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

    internal static void WriteWarning(CompatibilityConsoleOptions options, string message)
    {
        WriteLog(options, CompatibilityLogLevel.Warn, message);
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
        string line = finding.Line.Trim();
        string match = finding.Match.Trim();
        string secret = finding.Secret.Trim();
        CreateFindingDisplay(
            options,
            line,
            match,
            secret,
            out string displayMatch,
            out string displaySecret);
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

    private static void CreateFindingDisplay(
        CompatibilityConsoleOptions options,
        string line,
        string match,
        string secret,
        out string displayMatch,
        out string displaySecret)
    {
        bool isFileMatch = match.StartsWith("file detected:", StringComparison.Ordinal);
        int matchIndex = line.IndexOf(match, StringComparison.Ordinal);
        int secretIndex = match.IndexOf(secret, StringComparison.Ordinal);
        if (options.NoColor || isFileMatch || matchIndex < 0 || secretIndex < 0)
        {
            displayMatch = match;
            displaySecret = secret;
            return;
        }

        string prefix = line[..matchIndex];
        if (matchIndex > 20)
        {
            prefix = string.Concat("...", line.AsSpan(matchIndex - 20, 20));
        }

        prefix = prefix.TrimStart(' ');
        if (prefix.StartsWith('\n'))
        {
            prefix = prefix[1..];
        }

        int suffixIndex = matchIndex + match.Length;
        if (line.Length - 1 <= suffixIndex)
        {
            suffixIndex = line.Length;
        }

        ReadOnlySpan<char> suffix = line.AsSpan(suffixIndex);
        string suffixText = suffix.Length > 20
            ? string.Concat(suffix[..20], "...")
            : suffix.ToString();
        displayMatch = string.Concat(prefix, ColorizeMatch(match, secret), suffixText);
        displaySecret = ColorizeSecret(secret);
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
