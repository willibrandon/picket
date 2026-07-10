using System.Runtime.InteropServices;

namespace Picket.Sources;

/// <summary>
/// Describes an input buffer passed to libzstd.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct ZstandardInputBuffer(byte* source, nuint size)
{
    internal byte* _source = source;
    internal nuint _size = size;
    internal nuint _position;
}
