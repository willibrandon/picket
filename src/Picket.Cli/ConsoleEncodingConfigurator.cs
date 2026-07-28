using System.Text;

namespace Picket;

internal static class ConsoleEncodingConfigurator
{
    private static readonly UTF8Encoding s_utf8 = new(encoderShouldEmitUTF8Identifier: false);

    internal static void Configure()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        bool outputRedirected = Console.IsOutputRedirected;
        bool errorRedirected = Console.IsErrorRedirected;

        // Encoding.Unicode makes attached streams use WriteConsoleW. Keep redirected
        // streams byte-compatible with other platforms and Gitleaks.
        Console.OutputEncoding = Encoding.Unicode;

        if (outputRedirected)
        {
            Console.SetOut(CreateUtf8Writer(Console.OpenStandardOutput()));
        }

        if (errorRedirected)
        {
            Console.SetError(CreateUtf8Writer(Console.OpenStandardError()));
        }
    }

    private static StreamWriter CreateUtf8Writer(Stream stream)
    {
        return new StreamWriter(stream, s_utf8, leaveOpen: true)
        {
            AutoFlush = true,
        };
    }
}
