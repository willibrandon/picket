using System.Buffers.Binary;

namespace Picket.Compat;

/// <summary>
/// Classifies file prefixes using the application MIME boundary from the
/// <c>h2non/filetype</c> version pinned by Gitleaks.
/// </summary>
internal static class GitleaksFileTypeClassifier
{
    /// <summary>
    /// Determines whether the input matches a file type whose top-level MIME
    /// type is <c>application</c>.
    /// </summary>
    /// <param name="input">The initial file bytes to classify.</param>
    /// <returns><see langword="true"/> when Gitleaks skips the file as binary.</returns>
    internal static bool IsApplication(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
        {
            return false;
        }

        if (IsApplicationSpecific(input))
        {
            return true;
        }

        // h2non/filetype checks these non-application groups before the
        // application-valued font, document, and archive groups.
        if (IsImage(input) || IsVideo(input) || IsAudio(input))
        {
            return false;
        }

        return IsFont(input) || IsDocument(input) || IsArchiveOrExecutable(input);
    }

    private static bool IsApplicationSpecific(ReadOnlySpan<byte> input)
    {
        return HasPrefix(input, [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00])
            || IsDex(input)
            || IsDey(input);
    }

    private static bool IsDex(ReadOnlySpan<byte> input)
    {
        return input.Length > 36
            && HasPrefix(input, [0x64, 0x65, 0x78, 0x0A])
            && input[36] == 0x70;
    }

    private static bool IsDey(ReadOnlySpan<byte> input)
    {
        return input.Length > 100
            && HasPrefix(input, [0x64, 0x65, 0x79, 0x0A])
            && IsDex(input[40..100]);
    }

    private static bool IsImage(ReadOnlySpan<byte> input)
    {
        return HasPrefix(input, [0xFF, 0xD8, 0xFF])
            || HasPrefix(input, [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 0x00])
            || HasPrefix(input, [0x89, 0x50, 0x4E, 0x47])
            || HasPrefix(input, "GIF"u8)
            || MatchesAt(input, 8, "WEBP"u8)
            || IsTiff(input)
            || HasPrefix(input, [0x42, 0x4D])
            || HasPrefix(input, [0x49, 0x49, 0xBC])
            || HasPrefix(input, "8BPS"u8)
            || HasPrefix(input, [0x00, 0x00, 0x01, 0x00])
            || IsHeif(input)
            || HasPrefix(input, "AC10"u8);
    }

    private static bool IsTiff(ReadOnlySpan<byte> input)
    {
        return input.Length > 10
            && (HasPrefix(input, [0x49, 0x49, 0x2A, 0x00])
                || HasPrefix(input, [0x4D, 0x4D, 0x00, 0x2A]));
    }

    private static bool IsHeif(ReadOnlySpan<byte> input)
    {
        if (input.Length < 17
            || !MatchesAt(input, 4, "ftyp"u8))
        {
            return false;
        }

        uint boxLength = BinaryPrimitives.ReadUInt32BigEndian(input);
        if (boxLength > input.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> majorBrand = input.Slice(8, 4);
        if (majorBrand.SequenceEqual("heic"u8))
        {
            return true;
        }

        if (!majorBrand.SequenceEqual("mif1"u8)
            && !majorBrand.SequenceEqual("msf1"u8))
        {
            return false;
        }

        for (int offset = 16; offset + 4 <= boxLength; offset += 4)
        {
            if (input.Slice(offset, 4).SequenceEqual("heic"u8))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsVideo(ReadOnlySpan<byte> input)
    {
        return IsMp4(input)
            || MatchesAt(input, 4, "ftypM4V"u8)
            || IsMatroska(input, "matroska"u8)
            || IsMatroska(input, "webm"u8)
            || IsQuickTime(input)
            || (HasPrefix(input, "RIFF"u8) && MatchesAt(input, 8, "AVI"u8))
            || HasPrefix(input, [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9])
            || (input.Length > 3
                && input[0] == 0x00
                && input[1] == 0x00
                && input[2] == 0x01
                && input[3] is >= 0xB0 and <= 0xBF)
            || HasPrefix(input, [0x46, 0x4C, 0x56, 0x01])
            || MatchesAt(input, 4, "ftyp3gp"u8);
    }

    private static bool IsMp4(ReadOnlySpan<byte> input)
    {
        if (input.Length <= 11 || !MatchesAt(input, 4, "ftyp"u8))
        {
            return false;
        }

        ReadOnlySpan<byte> brand = input.Slice(8, 4);
        return brand.SequenceEqual("avc1"u8)
            || brand.SequenceEqual("dash"u8)
            || brand.SequenceEqual("iso2"u8)
            || brand.SequenceEqual("iso3"u8)
            || brand.SequenceEqual("iso4"u8)
            || brand.SequenceEqual("iso5"u8)
            || brand.SequenceEqual("iso6"u8)
            || brand.SequenceEqual("isom"u8)
            || brand.SequenceEqual("mmp4"u8)
            || brand.SequenceEqual("mp41"u8)
            || brand.SequenceEqual("mp42"u8)
            || brand.SequenceEqual("mp4v"u8)
            || brand.SequenceEqual("mp71"u8)
            || brand.SequenceEqual("MSNV"u8)
            || brand.SequenceEqual("NDAS"u8)
            || brand.SequenceEqual("NDSC"u8)
            || brand.SequenceEqual("NSDC"u8)
            || brand.SequenceEqual("NDSH"u8)
            || brand.SequenceEqual("NDSM"u8)
            || brand.SequenceEqual("NDSP"u8)
            || brand.SequenceEqual("NDSS"u8)
            || brand.SequenceEqual("NDXC"u8)
            || brand.SequenceEqual("NDXH"u8)
            || brand.SequenceEqual("NDXM"u8)
            || brand.SequenceEqual("NDXP"u8)
            || brand.SequenceEqual("NDXS"u8)
            || brand.SequenceEqual("F4V "u8)
            || brand.SequenceEqual("F4P "u8);
    }

    private static bool IsMatroska(ReadOnlySpan<byte> input, ReadOnlySpan<byte> documentType)
    {
        if (!HasPrefix(input, [0x1A, 0x45, 0xDF, 0xA3]))
        {
            return false;
        }

        ReadOnlySpan<byte> probe = input[..Math.Min(input.Length, 4096)];
        int index = probe.IndexOf(documentType);
        return index >= 3
            && probe[index - 3] == 0x42
            && probe[index - 2] == 0x82;
    }

    private static bool IsQuickTime(ReadOnlySpan<byte> input)
    {
        return input.Length > 15
            && (HasPrefix(input, [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70])
                || MatchesAt(input, 4, "moov"u8)
                || MatchesAt(input, 4, "mdat"u8)
                || MatchesAt(input, 12, "mdat"u8));
    }

    private static bool IsAudio(ReadOnlySpan<byte> input)
    {
        return HasPrefix(input, "MThd"u8)
            || HasPrefix(input, "ID3"u8)
            || HasPrefix(input, [0xFF, 0xFB])
            || MatchesAt(input, 4, "ftypM4A"u8)
            || HasPrefix(input, "M4A "u8)
            || HasPrefix(input, "OggS"u8)
            || HasPrefix(input, "fLaC"u8)
            || (HasPrefix(input, "RIFF"u8) && MatchesAt(input, 8, "WAVE"u8))
            || HasPrefix(input, [0x23, 0x21, 0x41, 0x4D, 0x52, 0x0A])
            || HasPrefix(input, [0xFF, 0xF1])
            || HasPrefix(input, [0xFF, 0xF9])
            || (HasPrefix(input, "FORM"u8) && MatchesAt(input, 8, "AIFF"u8));
    }

    private static bool IsFont(ReadOnlySpan<byte> input)
    {
        return HasPrefix(input, [0x77, 0x4F, 0x46, 0x46, 0x00, 0x01, 0x00, 0x00])
            || HasPrefix(input, [0x77, 0x4F, 0x46, 0x32, 0x00, 0x01, 0x00, 0x00])
            || HasPrefix(input, [0x00, 0x01, 0x00, 0x00, 0x00])
            || HasPrefix(input, [0x4F, 0x54, 0x54, 0x4F, 0x00]);
    }

    private static bool IsDocument(ReadOnlySpan<byte> input)
    {
        if (!HasPrefix(input, [0xD0, 0xCF, 0x11, 0xE0]))
        {
            return false;
        }

        return input.Length <= 513
            || (input[512] == 0xEC && input[513] == 0xA5)
            || (input[512] == 0x09 && input[513] == 0x08)
            || (input[512] == 0xA0 && input[513] == 0x46);
    }

    private static bool IsArchiveOrExecutable(ReadOnlySpan<byte> input)
    {
        return IsZip(input)
            || (input.Length > 261 && MatchesAt(input, 257, "ustar"u8))
            || (input.Length > 6
                && HasPrefix(input, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])
                && input[6] is 0x00 or 0x01)
            || HasPrefix(input, [0x1F, 0x8B, 0x08])
            || HasPrefix(input, "BZh"u8)
            || HasPrefix(input, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
            || HasPrefix(input, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00])
            || IsZstandard(input)
            || HasPrefix(input, "%PDF"u8)
            || HasPrefix(input, "MZ"u8)
            || (input.Length > 2
                && input[0] is 0x43 or 0x46
                && input[1] == 0x57
                && input[2] == 0x53)
            || HasPrefix(input, "{\\rtf"u8)
            || IsEmbeddedOpenType(input)
            || HasPrefix(input, "%!"u8)
            || HasPrefix(input, "SQLi"u8)
            || HasPrefix(input, [0x4E, 0x45, 0x53, 0x1A])
            || HasPrefix(input, "Cr24"u8)
            || HasPrefix(input, "MSCF"u8)
            || HasPrefix(input, "ISc("u8)
            || HasPrefix(input, "!<arch>"u8)
            || (input.Length > 1
                && input[0] == 0x1F
                && input[1] is 0xA0 or 0x9D)
            || HasPrefix(input, "LZIP"u8)
            || (input.Length > 96 && HasPrefix(input, [0xED, 0xAB, 0xEE, 0xDB]))
            || (input.Length > 52 && HasPrefix(input, [0x7F, 0x45, 0x4C, 0x46]))
            || (input.Length > 131 && MatchesAt(input, 128, "DICM"u8))
            || (input.Length > 32773 && MatchesAt(input, 32769, "CD001"u8))
            || IsMachO(input);
    }

    private static bool IsZip(ReadOnlySpan<byte> input)
    {
        return input.Length > 3
            && input[0] == 0x50
            && input[1] == 0x4B
            && input[2] is 0x03 or 0x05 or 0x07
            && input[3] is 0x04 or 0x06 or 0x08;
    }

    private static bool IsZstandard(ReadOnlySpan<byte> input)
    {
        while (true)
        {
            if (HasPrefix(input, [0x28, 0xB5, 0x2F, 0xFD]))
            {
                return true;
            }

            if (input.Length < 8)
            {
                return false;
            }

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(input);
            if ((magic & 0xFFFFFFF0) != 0x184D2A50)
            {
                return false;
            }

            uint userDataLength = BinaryPrimitives.ReadUInt32LittleEndian(input[4..]);
            if (userDataLength > input.Length - 8)
            {
                return false;
            }

            input = input[(8 + (int)userDataLength)..];
        }
    }

    private static bool IsEmbeddedOpenType(ReadOnlySpan<byte> input)
    {
        return input.Length > 35
            && input[34] == 0x4C
            && input[35] == 0x50
            && ((input[8] == 0x02 && input[9] == 0x00 && input[10] == 0x01)
                || (input[8] == 0x01 && input[9] == 0x00 && input[10] == 0x00)
                || (input[8] == 0x02 && input[9] == 0x00 && input[10] == 0x02));
    }

    private static bool IsMachO(ReadOnlySpan<byte> input)
    {
        return HasPrefix(input, [0xFE, 0xED, 0xFA, 0xCF])
            || HasPrefix(input, [0xFE, 0xED, 0xFA, 0xCE])
            || HasPrefix(input, [0xBE, 0xBA, 0xFE, 0xCA])
            || HasPrefix(input, [0xCF, 0xFA, 0xED, 0xFE])
            || HasPrefix(input, [0xCE, 0xFA, 0xED, 0xFE])
            || HasPrefix(input, [0xCA, 0xFE, 0xBA, 0xBE]);
    }

    private static bool HasPrefix(
        ReadOnlySpan<byte> input,
        ReadOnlySpan<byte> value)
    {
        return input.StartsWith(value);
    }

    private static bool MatchesAt(
        ReadOnlySpan<byte> input,
        int offset,
        ReadOnlySpan<byte> value)
    {
        return offset >= 0
            && offset <= input.Length - value.Length
            && input.Slice(offset, value.Length).SequenceEqual(value);
    }
}
