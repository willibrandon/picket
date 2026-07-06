using System.Globalization;
using Picket.Store;

namespace Picket;

internal static partial class Program
{
    static int RunCache(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteCacheHelp();
            return 0;
        }

        string subcommand = args[0];
        if (subcommand.Equals("stats", StringComparison.OrdinalIgnoreCase))
        {
            return RunCacheStats(args[1..]);
        }

        if (subcommand.Equals("prune", StringComparison.OrdinalIgnoreCase))
        {
            return RunCachePrune(args[1..]);
        }

        if (subcommand.Equals("export", StringComparison.OrdinalIgnoreCase))
        {
            return RunCacheExport(args[1..]);
        }

        if (subcommand.Equals("import", StringComparison.OrdinalIgnoreCase))
        {
            return RunCacheImport(args[1..]);
        }

        Console.Error.WriteLine($"unknown cache command: {subcommand}");
        return UnknownFlagExitCode;
    }

    static int RunCacheStats(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteCacheStatsHelp();
            return 0;
        }

        if (!TryReadCacheOptions(
            args,
            allowPruneOptions: false,
            out string? cacheDir,
            out string? configPath,
            out string source,
            out int maxDecodeDepth,
            out long? maxTargetBytes,
            out bool ignoreGitleaksAllow,
            out ScanCacheStorageMode cacheStorageMode,
            out _,
            out _))
        {
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(cacheDir))
        {
            Console.Error.WriteLine("cache stats requires --cache-dir");
            return UnknownFlagExitCode;
        }

        if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode, out PicketScanCache? scanCache))
        {
            return 1;
        }

        PicketScanCacheStats stats = scanCache.GetStats();
        Console.Out.WriteLine($"cache: {stats.RootPath}");
        Console.Out.WriteLine($"entries: {stats.EntryCount.ToString(CultureInfo.InvariantCulture)}");
        Console.Out.WriteLine($"current-key entries: {stats.CurrentKeyEntryCount.ToString(CultureInfo.InvariantCulture)}");
        Console.Out.WriteLine($"bytes: {stats.TotalBytes.ToString(CultureInfo.InvariantCulture)}");
        return 0;
    }

    static int RunCachePrune(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteCachePruneHelp();
            return 0;
        }

        if (!TryReadCacheOptions(
            args,
            allowPruneOptions: true,
            out string? cacheDir,
            out string? configPath,
            out string source,
            out int maxDecodeDepth,
            out long? maxTargetBytes,
            out bool ignoreGitleaksAllow,
            out ScanCacheStorageMode cacheStorageMode,
            out bool pruneOtherKeys,
            out int? olderThanDays))
        {
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(cacheDir))
        {
            Console.Error.WriteLine("cache prune requires --cache-dir");
            return UnknownFlagExitCode;
        }

        if (!pruneOtherKeys && !olderThanDays.HasValue)
        {
            Console.Error.WriteLine("cache prune requires --other-keys or --older-than-days");
            return UnknownFlagExitCode;
        }

        if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode, out PicketScanCache? scanCache))
        {
            return 1;
        }

        int deleted = 0;
        if (pruneOtherKeys)
        {
            deleted += scanCache.PruneOtherKeys();
        }

        if (olderThanDays.HasValue)
        {
            deleted += scanCache.PruneOlderThan(TimeSpan.FromDays(olderThanDays.Value));
        }

        Console.Out.WriteLine($"deleted: {deleted.ToString(CultureInfo.InvariantCulture)}");
        return 0;
    }

    static int RunCacheExport(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteCacheExportHelp();
            return 0;
        }

        if (!TryReadCacheTransferOptions(
            args,
            "--output",
            out string? cacheDir,
            out string? configPath,
            out string source,
            out int maxDecodeDepth,
            out long? maxTargetBytes,
            out bool ignoreGitleaksAllow,
            out ScanCacheStorageMode cacheStorageMode,
            out string? outputPath))
        {
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(cacheDir))
        {
            Console.Error.WriteLine("cache export requires --cache-dir");
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            Console.Error.WriteLine("cache export requires --output");
            return UnknownFlagExitCode;
        }

        if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode, out PicketScanCache? scanCache))
        {
            return 1;
        }

        try
        {
            int exported = scanCache.Export(outputPath);
            Console.Out.WriteLine($"exported: {exported.ToString(CultureInfo.InvariantCulture)}");
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
        {
            Console.Error.WriteLine($"failed to export cache: {exception.Message}");
            return 1;
        }
    }

    static int RunCacheImport(string[] args)
    {
        if (ContainsHelp(args))
        {
            WriteCacheImportHelp();
            return 0;
        }

        if (!TryReadCacheTransferOptions(
            args,
            "--input",
            out string? cacheDir,
            out string? configPath,
            out string source,
            out int maxDecodeDepth,
            out long? maxTargetBytes,
            out bool ignoreGitleaksAllow,
            out ScanCacheStorageMode cacheStorageMode,
            out string? inputPath))
        {
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(cacheDir))
        {
            Console.Error.WriteLine("cache import requires --cache-dir");
            return UnknownFlagExitCode;
        }

        if (string.IsNullOrWhiteSpace(inputPath))
        {
            Console.Error.WriteLine("cache import requires --input");
            return UnknownFlagExitCode;
        }

        if (!TryOpenNativeScanCache(cacheDir, configPath, source, maxDecodeDepth, maxTargetBytes, ignoreGitleaksAllow, cacheStorageMode, out PicketScanCache? scanCache))
        {
            return 1;
        }

        try
        {
            int imported = scanCache.Import(inputPath);
            Console.Out.WriteLine($"imported: {imported.ToString(CultureInfo.InvariantCulture)}");
            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or ArgumentException or FormatException)
        {
            Console.Error.WriteLine($"failed to import cache: {exception.Message}");
            return 1;
        }
    }
}
