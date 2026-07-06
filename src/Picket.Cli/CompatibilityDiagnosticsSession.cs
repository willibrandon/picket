using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace Picket;

internal sealed class CompatibilityDiagnosticsSession
{
    private readonly string _command;
    private readonly bool _writeHttp;
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
    private CompatibilityDiagnosticsHttpServer? _httpServer;
    private bool _completed;

    private CompatibilityDiagnosticsSession(string command, string outputDirectory, bool writeHttp, bool writeCpu, bool writeMemory, bool writeTrace)
    {
        using Process process = Process.GetCurrentProcess();
        _command = command;
        _outputDirectory = outputDirectory;
        _writeHttp = writeHttp;
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
        bool writeHttp = false;
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
                    writeHttp = true;
                    sawSupportedMode = true;
                    break;
                default:
                    error.WriteLine($"Unknown diagnostics type: {mode}");
                    break;
            }
        }

        if (!sawSupportedMode)
        {
            return true;
        }

        if (writeHttp)
        {
            if (writeCpu || writeMemory || writeTrace)
            {
                error.WriteLine("other diagnostics modes should not be enabled when http mode is enabled");
                return false;
            }

            if (!string.IsNullOrEmpty(diagnosticsDirectory))
            {
                error.WriteLine("the diagnostics directory should not be set in http mode");
                return false;
            }

            session = new CompatibilityDiagnosticsSession(command, string.Empty, writeHttp, writeCpu, writeMemory, writeTrace);
            return session.TryStartHttp(error);
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

        session = new CompatibilityDiagnosticsSession(command, outputDirectory, writeHttp, writeCpu, writeMemory, writeTrace);
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
            if (!_writeHttp && _writeCpu)
            {
                WriteCpuDiagnostics(exitCode, endedAt, elapsed, processorTime, privilegedProcessorTime, userProcessorTime);
            }

            if (!_writeHttp && _writeMemory)
            {
                WriteMemoryDiagnostics(exitCode, endedAt, elapsed, allocatedBytes, managedMemoryBytes, process);
            }

            if (!_writeHttp && _writeTrace)
            {
                WriteTraceDiagnostics(exitCode, endedAt, elapsed);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            error.WriteLine($"failed to write diagnostics: {ex.Message}");
            return false;
        }
        finally
        {
            _httpServer?.Dispose();
        }

        return true;
    }

    private bool TryStartHttp(TextWriter error)
    {
        try
        {
            _httpServer = CompatibilityDiagnosticsHttpServer.Start(CreateHttpDiagnosticsResponse);
            error.WriteLine("diagnostics server started at http://localhost:6060/debug/pprof/");
            return true;
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            error.WriteLine($"failed to start diagnostics http server: {ex.Message}");
            return false;
        }
    }

    private CompatibilityDiagnosticsHttpResponse CreateHttpDiagnosticsResponse(string path)
    {
        if (path.Equals("/", StringComparison.Ordinal)
            || path.Equals("/debug/pprof", StringComparison.Ordinal)
            || path.Equals("/debug/pprof/", StringComparison.Ordinal))
        {
            return new CompatibilityDiagnosticsHttpResponse("application/json; charset=utf-8", CreateHttpIndex(), 200);
        }

        if (path.Equals("/debug/pprof/profile", StringComparison.Ordinal)
            || path.Equals("/debug/pprof/profile/", StringComparison.Ordinal))
        {
            return new CompatibilityDiagnosticsHttpResponse("application/json; charset=utf-8", CreateCpuSnapshot());
        }

        if (path.Equals("/debug/pprof/heap", StringComparison.Ordinal)
            || path.Equals("/debug/pprof/heap/", StringComparison.Ordinal))
        {
            return new CompatibilityDiagnosticsHttpResponse("application/json; charset=utf-8", CreateMemorySnapshot());
        }

        if (path.Equals("/debug/pprof/trace", StringComparison.Ordinal)
            || path.Equals("/debug/pprof/trace/", StringComparison.Ordinal))
        {
            return new CompatibilityDiagnosticsHttpResponse("application/x-ndjson; charset=utf-8", CreateTraceSnapshot());
        }

        return new CompatibilityDiagnosticsHttpResponse("text/plain; charset=utf-8", "not found\n", 404);
    }

    private string CreateHttpIndex()
    {
        var builder = new StringBuilder(512);
        builder.Append("{\n");
        AppendString(builder, "tool", "picket");
        AppendString(builder, "profile", "gitleaks-compat");
        AppendString(builder, "diagnostic", "http");
        AppendString(builder, "command", _command);
        AppendString(builder, "startedAtUtc", FormatTimestamp(_startedAt));
        AppendString(builder, "note", "Picket serves AOT-safe JSON diagnostics here instead of Go pprof profiles.");
        builder.Append("  \"endpoints\": [\"/debug/pprof/profile\", \"/debug/pprof/heap\", \"/debug/pprof/trace\"]\n");
        builder.Append("}\n");
        return builder.ToString();
    }

    private string CreateCpuSnapshot()
    {
        using Process process = Process.GetCurrentProcess();
        DateTimeOffset current = DateTimeOffset.UtcNow;
        TimeSpan elapsed = Stopwatch.GetElapsedTime(_startTimestamp);
        TimeSpan processorTime = process.TotalProcessorTime - _startProcessorTime;
        TimeSpan privilegedProcessorTime = process.PrivilegedProcessorTime - _startPrivilegedProcessorTime;
        TimeSpan userProcessorTime = process.UserProcessorTime - _startUserProcessorTime;
        var builder = new StringBuilder(384);
        AppendObjectStart(builder, "cpu", exitCode: -1, current, elapsed);
        AppendNumber(builder, "processorTimeMilliseconds", processorTime.TotalMilliseconds);
        AppendNumber(builder, "userProcessorTimeMilliseconds", userProcessorTime.TotalMilliseconds);
        AppendNumber(builder, "privilegedProcessorTimeMilliseconds", privilegedProcessorTime.TotalMilliseconds);
        AppendObjectEnd(builder);
        return builder.ToString();
    }

    private string CreateMemorySnapshot()
    {
        using Process process = Process.GetCurrentProcess();
        DateTimeOffset current = DateTimeOffset.UtcNow;
        TimeSpan elapsed = Stopwatch.GetElapsedTime(_startTimestamp);
        long allocatedBytes = GC.GetTotalAllocatedBytes(precise: false) - _startAllocatedBytes;
        long managedMemoryBytes = GC.GetTotalMemory(forceFullCollection: false);
        var builder = new StringBuilder(512);
        AppendObjectStart(builder, "mem", exitCode: -1, current, elapsed);
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
        return builder.ToString();
    }

    private string CreateTraceSnapshot()
    {
        var builder = new StringBuilder(384);
        AppendTraceEvent(builder, "scan.start", _startedAt, 0, exitCode: -1);
        AppendTraceEvent(builder, "scan.snapshot", DateTimeOffset.UtcNow, Stopwatch.GetElapsedTime(_startTimestamp).TotalMilliseconds, exitCode: -1);
        return builder.ToString();
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
