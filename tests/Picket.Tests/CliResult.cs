namespace Picket.Tests;

internal sealed class CliResult(int exitCode, string stdout, string stderr)
{
    internal int ExitCode { get; } = exitCode;

    internal string Stdout { get; } = stdout;

    internal string Stderr { get; } = stderr;
}
