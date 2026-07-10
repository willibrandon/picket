using Microsoft.Win32.SafeHandles;

namespace Picket.Sources;

/// <summary>
/// Owns a libzstd decompression context.
/// </summary>
internal sealed class ZstandardDecompressionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private ZstandardDecompressionHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    internal static ZstandardDecompressionHandle Create()
    {
        IntPtr handle = ZstandardNativeMethods.CreateDecompressionContext();
        if (handle == IntPtr.Zero)
        {
            throw new IOException("could not create the zstandard decompression context");
        }

        return new ZstandardDecompressionHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        return ZstandardNativeMethods.FreeDecompressionContext(handle) == 0;
    }
}
