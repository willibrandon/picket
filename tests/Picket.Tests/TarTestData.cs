using System.IO.Compression;
using System.Text;

namespace Picket.Tests;

internal static class TarTestData
{
    internal static byte[] CreateGzipBytes(byte[] content)
    {
        using var stream = new MemoryStream();
        using (var gzipStream = new GZipStream(stream, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            gzipStream.Write(content);
        }

        return stream.ToArray();
    }

    internal static byte[] CreateTarBytes(params (string Name, byte[] Content)[] entries)
    {
        using var stream = new MemoryStream();
        foreach ((string name, byte[] content) in entries)
        {
            byte[] header = CreateTarHeader(name, content.Length);
            stream.Write(header);
            stream.Write(content);
            int padding = 512 - (content.Length % 512);
            if (padding != 512)
            {
                stream.Write(new byte[padding]);
            }
        }

        stream.Write(new byte[1024]);
        return stream.ToArray();
    }

    private static byte[] CreateTarHeader(string name, int size)
    {
        byte[] header = new byte[512];
        WriteAscii(header, 0, 100, name);
        WriteAscii(header, 100, 8, "0000644\0");
        WriteAscii(header, 108, 8, "0000000\0");
        WriteAscii(header, 116, 8, "0000000\0");
        WriteOctal(header, 124, 12, size);
        WriteAscii(header, 136, 12, "00000000000\0");
        for (int i = 148; i < 156; i++)
        {
            header[i] = (byte)' ';
        }

        header[156] = (byte)'0';
        WriteAscii(header, 257, 6, "ustar\0");
        WriteAscii(header, 263, 2, "00");

        int checksum = 0;
        for (int i = 0; i < header.Length; i++)
        {
            checksum += header[i];
        }

        string checksumText = Convert.ToString(checksum, 8).PadLeft(6, '0');
        WriteAscii(header, 148, 8, $"{checksumText}\0 ");
        return header;
    }

    private static void WriteOctal(byte[] destination, int offset, int length, int value)
    {
        string text = Convert.ToString(value, 8).PadLeft(length - 1, '0');
        WriteAscii(destination, offset, length, $"{text}\0");
    }

    private static void WriteAscii(byte[] destination, int offset, int length, string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);
        int count = Math.Min(bytes.Length, length);
        bytes.AsSpan(0, count).CopyTo(destination.AsSpan(offset, count));
    }
}
