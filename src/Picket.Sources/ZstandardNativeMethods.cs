using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Picket.Sources;

/// <summary>
/// Provides the libzstd entry points required for bounded streaming decompression.
/// </summary>
internal static partial class ZstandardNativeMethods
{
    private const string LibraryName = "libzstd";

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_createDCtx")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr CreateDecompressionContext();

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_DCtx_setParameter")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint SetDecompressionParameter(IntPtr context, int parameter, int value);

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_decompressStream")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static unsafe partial nuint DecompressStream(
        IntPtr context,
        ref ZstandardOutputBuffer output,
        ref ZstandardInputBuffer input);

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_freeDCtx")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial nuint FreeDecompressionContext(IntPtr context);

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_isError")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint IsError(nuint result);

    [LibraryImport(LibraryName, EntryPoint = "ZSTD_getErrorName")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr GetErrorName(nuint result);
}
