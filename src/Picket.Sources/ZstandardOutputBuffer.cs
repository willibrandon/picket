using System.Runtime.InteropServices;

namespace Picket.Sources;

/// <summary>
/// Describes an output buffer passed to libzstd.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ZstandardOutputBuffer(byte* destination, nuint size)
{
    internal byte* _destination = destination;
    internal nuint _size = size;
    internal nuint _position;
}
