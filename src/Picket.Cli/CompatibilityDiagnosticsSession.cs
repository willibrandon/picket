using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Picket;

internal sealed class CompatibilityDiagnosticsSession
{
    private readonly string _command;
    private readonly bool _writeCpu;
    private readonly bool _writeMemory;
    private readonly bool _writeTrace;
    private readonly string _outputDirectory;
    private readonly long _startTimestamp;
    private readonly DateTimeOffset _startedAt;
    private readonly TimeSpan _startProcessorTime;
    private readonly TimeSpan _startPrivilegedProcessorTime;
    private readonly TimeSpan _startUserProcessorTime;
    private readonly long _startAllocatedBytes;
    private readonly long _startManagedMemoryBytes;
    private readonly long _startWorkingSetBytes;
    private readonly long _startPrivateMemoryBytes;
    private readonly int _startGen0Collections;
    private readonly int _startGen1Collections;
    private readonly int _startGen2Collections;
    private bool _completed;

    private CompatibilityDiagnosticsSession(string command, string outputDirectory, bool writeCpu, bool writeMemory, bool writeTrace)
    {
        using Process process = Process.GetCurrentProcess();
        _command = command;
        _outputDirectory = outputDirectory;
        _writeCpu = writeCpu;
        _writeMemory = writeMemory;
        _writeTrace = writeTrace;
        _startTimestamp = Stopwatch.GetTimestamp();
        _startedAt = DateTimeOffset.UtcNow;
        _startProcessorTime = process.TotalProcessorTime;
        _startPrivilegedProcessorTime = process.PrivilegedProcessorTime;
        _startUserProcessorTime = process.UserProcessorTime;
        _startAllocatedBytes = GC.GetTotalAllocatedBytes(precise: false);
        _startManagedMemoryBytes = GC.GetTotalMemory(forceFullCollection: false);
        _startWorkingSetBytes = process.WorkingSet64;
        _startPrivateMemoryBytes = process.PrivateMemorySize64;
        _startGen0Collections = GC.CollectionCount(0);
        _startGen1Collections = GC.CollectionCount(1);
        _startGen2Collections = GC.CollectionCount(2);
    }

    internal static bool TryStart(
        string? diagnostics,
        string? diagnosticsDirectory,
        string command,
        TextWriter error,
        out CompatibilityDiagnosticsSession? session)
    {
        session = null;
        if (string.IsNullOrEmpty(diagnostics))
        {
            return true;
        }

        bool writeCpu = false;
        bool writeMemory = false;
        bool writeTrace = false;
        bool sawSupportedMode = false;
        string[] modes = diagnostics.Split(',', StringSplitOptions.TrimEntries);
        foreach (string mode in modes)
        {
            if (mode.Length == 0)
            {
                continue;
            }

            switch (mode)
            {
                case "cpu":
                    writeCpu = true;
                    sawSupportedMode = true;
                    break;
                case "mem":
                    writeMemory = true;
                    sawSupportedMode = true;
                    break;
                case "trace":
                    writeTrace = true;
                    sawSupportedMode = true;
                    break;
                case "http":
                    error.WriteLine("--diagnostics=http is not supported yet");
                    return false;
                default:
                    error.WriteLine($"Unknown diagnostics type: {mode}");
                    break;
            }
        }

        if (!sawSupportedMode)
        {
            return true;
        }

        string outputDirectory = string.IsNullOrEmpty(diagnosticsDirectory)
            ? Environment.CurrentDirectory
            : diagnosticsDirectory;

        try
        {
            Directory.CreateDirectory(outputDirectory);
            outputDirectory = Path.GetFullPath(outputDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error.WriteLine($"failed to create diagnostics directory: {ex.Message}");
            return false;
        }

        session = new CompatibilityDiagnosticsSession(command, outputDirectory, writeCpu, writeMemory, writeTrace);
        return true;
    }

    internal bool TryComplete(int exitCode, TextWriter error)
    {
        if (_completed)
        {
            return true;
        }

        _completed = true;
        using Process process = Process.GetCurrentProcess();
        DateTimeOffset endedAt = DateTimeOffset.UtcNow;
        TimeSpan elapsed = Stopwatch.GetElapsedTime(_startTimestamp);
        TimeSpan processorTime = process.TotalProcessorTime - _startProcessorTime;
        TimeSpan privilegedProcessorTime = process.PrivilegedProcessorTime - _startPrivilegedProcessorTime;
        TimeSpan userProcessorTime = process.UserProcessorTime - _startUserProcessorTime;
        long allocatedBytes = GC.GetTotalAllocatedBytes(precise: false) - _startAllocatedBytes;
        long managedMemoryBytes = GC.GetTotalMemory(forceFullCollection: false);

        try
        {
            if (_writeCpu)
            {
                WriteCpuDiagnostics(exitCode, endedAt, elapsed, processorTime, privilegedProcessorTime, userProcessorTime);
            }

            if (_writeMemory)
            {
                WriteMemoryDiagnostics(exitCode, endedAt, elapsed, allocatedBytes, managedMemoryBytes, process);
            }

            if (_writeTrace)
            {
                WriteTraceDiagnostics(exitCode, endedAt, elapsed);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error.WriteLine($"failed to write diagnostics: {ex.Message}");
            return false;
        }

        return true;
    }

    private void WriteCpuDiagnostics(
        int exitCode,
        DateTimeOffset endedAt,
        TimeSpan elapsed,
        TimeSpan processorTime,
        TimeSpan privilegedProcessorTime,
        TimeSpan userProcessorTime)
    {
        var builder = new StringBuilder(384);
        AppendObjectStart(builder, "cpu", exitCode, endedAt, elapsed);
        AppendNumber(builder, "processorTimeMilliseconds", processorTime.TotalMilliseconds);
        AppendNumber(builder, "userProcessorTimeMilliseconds", userProcessorTime.TotalMilliseconds);
        AppendNumber(builder, "privilegedProcessorTimeMilliseconds", privilegedProcessorTime.TotalMilliseconds);
        AppendObjectEnd(builder);
        File.WriteAllText(Path.Combine(_outputDirectory, "cpu.json"), builder.ToString());
    }

    private void WriteMemoryDiagnostics(
        int exitCode,
        DateTimeOffset endedAt,
        TimeSpan elapsed,
        long allocatedBytes,
        long managedMemoryBytes,
        Process process)
    {
        var builder = new StringBuilder(512);
        AppendObjectStart(builder, "mem", exitCode, endedAt, elapsed);
        AppendNumber(builder, "allocatedBytes", allocatedBytes);
        AppendNumber(builder, "startManagedMemoryBytes", _startManagedMemoryBytes);
        AppendNumber(builder, "managedMemoryBytes", managedMemoryBytes);
        AppendNumber(builder, "startWorkingSetBytes", _startWorkingSetBytes);
        AppendNumber(builder, "workingSetBytes", process.WorkingSet64);
        AppendNumber(builder, "startPrivateMemoryBytes", _startPrivateMemoryBytes);
        AppendNumber(builder, "privateMemoryBytes", process.PrivateMemorySize64);
        AppendNumber(builder, "gen0Collections", GC.CollectionCount(0) - _startGen0Collections);
        AppendNumber(builder, "gen1Collections", GC.CollectionCount(1) - _startGen1Collections);
        AppendNumber(builder, "gen2Collections", GC.CollectionCount(2) - _startGen2Collections);
        AppendObjectEnd(builder);
        File.WriteAllText(Path.Combine(_outputDirectory, "mem.json"), builder.ToString());
    }

    private void WriteTraceDiagnostics(int exitCode, DateTimeOffset endedAt, TimeSpan elapsed)
    {
        var builder = new StringBuilder(384);
        AppendTraceEvent(builder, "scan.start", _startedAt, 0, exitCode);
        AppendTraceEvent(builder, "scan.stop", endedAt, elapsed.TotalMilliseconds, exitCode);
        File.WriteAllText(Path.Combine(_outputDirectory, "trace.jsonl"), builder.ToString());
    }

    private void AppendObjectStart(StringBuilder builder, string diagnostic, int exitCode, DateTimeOffset endedAt, TimeSpan elapsed)
    {
        builder.Append("{\n");
        AppendString(builder, "tool", "picket");
        AppendString(builder, "profile", "gitleaks-compat");
        AppendString(builder, "diagnostic", diagnostic);
        AppendString(builder, "command", _command);
        AppendString(builder, "startedAtUtc", FormatTimestamp(_startedAt));
        AppendString(builder, "endedAtUtc", FormatTimestamp(endedAt));
        AppendNumber(builder, "elapsedMilliseconds", elapsed.TotalMilliseconds);
        AppendNumber(builder, "exitCode", exitCode);
    }

    private static void AppendObjectEnd(StringBuilder builder)
    {
        if (builder[^2] == ',')
        {
            builder.Length -= 2;
            builder.Append('\n');
        }

        builder.Append("}\n");
    }

    private void AppendTraceEvent(StringBuilder builder, string name, DateTimeOffset timestamp, double elapsedMilliseconds, int exitCode)
    {
        builder.Append('{');
        AppendInlineString(builder, "tool", "picket");
        AppendInlineString(builder, "profile", "gitleaks-compat");
        AppendInlineString(builder, "event", name);
        AppendInlineString(builder, "command", _command);
        AppendInlineString(builder, "timestampUtc", FormatTimestamp(timestamp));
        AppendInlineNumber(builder, "elapsedMilliseconds", elapsedMilliseconds);
        AppendInlineNumber(builder, "exitCode", exitCode);
        builder.Length--;
        builder.Append("}\n");
    }

    private static void AppendString(StringBuilder builder, string name, string value)
    {
        builder.Append("  \"");
        AppendEscaped(builder, name);
        builder.Append("\": \"");
        AppendEscaped(builder, value);
        builder.Append("\",\n");
    }

    private static void AppendNumber(StringBuilder builder, string name, double value)
    {
        builder.Append("  \"");
        AppendEscaped(builder, name);
        builder.Append("\": ");
        builder.Append(value.ToString("0.###", CultureInfo.InvariantCulture));
        builder.Append(",\n");
    }

    private static void AppendNumber(StringBuilder builder, string name, long value)
    {
        builder.Append("  \"");
        AppendEscaped(builder, name);
        builder.Append("\": ");
        builder.Append(value.ToString(CultureInfo.InvariantCulture));
        builder.Append(",\n");
    }

    private static void AppendInlineString(StringBuilder builder, string name, string value)
    {
        builder.Append('"');
        AppendEscaped(builder, name);
        builder.Append("\":\"");
        AppendEscaped(builder, value);
        builder.Append("\",");
    }

    private static void AppendInlineNumber(StringBuilder builder, string name, double value)
    {
        builder.Append('"');
        AppendEscaped(builder, name);
        builder.Append("\":");
        builder.Append(value.ToString("0.###", CultureInfo.InvariantCulture));
        builder.Append(',');
    }

    private static void AppendEscaped(StringBuilder builder, string value)
    {
        foreach (char c in value)
        {
            switch (c)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (c < ' ')
                    {
                        builder.Append("\\u");
                        builder.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        builder.Append(c);
                    }

                    break;
            }
        }
    }

    private static string FormatTimestamp(DateTimeOffset timestamp)
    {
        return timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture);
    }
}
