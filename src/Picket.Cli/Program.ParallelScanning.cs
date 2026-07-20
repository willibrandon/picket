using Picket.Engine;
using Picket.Sources;
using Picket.Store;

namespace Picket;

internal static partial class Program
{
    // Match the GC pressure bands used by ArrayPool in dotnet/runtime.
    private const double HighMemoryPressureThreshold = 0.90;
    private const double MediumMemoryPressureThreshold = 0.70;
    private const int MinimumParallelScanFileCount = 8;

    static int GetSourceFileScanDegree(int fileCount)
    {
        int processorDegree = Math.Min(fileCount, Environment.ProcessorCount);
        if (fileCount < MinimumParallelScanFileCount || processorDegree <= 1)
        {
            return 1;
        }

        GCMemoryInfo memoryInfo = GC.GetGCMemoryInfo();
        long highMemoryLoadThreshold = memoryInfo.HighMemoryLoadThresholdBytes;
        if (highMemoryLoadThreshold <= 0)
        {
            return processorDegree;
        }

        double memoryPressure = (double)memoryInfo.MemoryLoadBytes / highMemoryLoadThreshold;
        if (memoryPressure >= HighMemoryPressureThreshold)
        {
            return 1;
        }

        return memoryPressure >= MediumMemoryPressureThreshold
            ? Math.Max(1, (processorDegree + 1) / 2)
            : processorDegree;
    }

    static bool ScanSourceFiles(
        IReadOnlyList<SourceFile> files,
        int startFileIndex,
        Func<SourceFile, bool> shouldSkip,
        CompiledRuleSet rules,
        PicketIgnore picketIgnore,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool nativeMode,
        long timeoutTimestamp,
        int maxDegreeOfParallelism,
        PicketScanCache? scanCache,
        CompatibilityDiagnosticsSession? diagnosticsSession,
        List<Finding> findings,
        out bool stopped,
        out Exception? error,
        CancellationToken cancellationToken)
    {
        int fileCount = files.Count - startFileIndex;
        var fileFindings = new IReadOnlyList<Finding>?[fileCount];
        var fileErrors = new Exception?[fileCount];
        var stoppedFiles = new bool[fileCount];

        void ScanFile(int resultIndex)
        {
            if (IsScanStopped(timeoutTimestamp, cancellationToken))
            {
                stoppedFiles[resultIndex] = true;
                return;
            }

            SourceFile file = files[startFileIndex + resultIndex];
            if (shouldSkip(file))
            {
                fileFindings[resultIndex] = [];
                return;
            }

            try
            {
                fileFindings[resultIndex] = ScanSourceFileForParallelBatch(
                    file,
                    rules,
                    picketIgnore,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    maxTargetBytes,
                    nativeMode,
                    timeoutTimestamp,
                    scanCache,
                    diagnosticsSession,
                    out stoppedFiles[resultIndex],
                    cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                fileErrors[resultIndex] = exception;
            }
        }

        if (maxDegreeOfParallelism == 1)
        {
            for (int resultIndex = 0; resultIndex < fileCount; resultIndex++)
            {
                ScanFile(resultIndex);
            }
        }
        else
        {
            var options = new ParallelOptions
            {
                MaxDegreeOfParallelism = maxDegreeOfParallelism,
            };
            Parallel.For(0, fileCount, options, ScanFile);
        }

        stopped = false;
        error = null;
        for (int resultIndex = 0; resultIndex < fileCount; resultIndex++)
        {
            if (fileErrors[resultIndex] is not null)
            {
                error = fileErrors[resultIndex];
                return false;
            }

            if (stoppedFiles[resultIndex])
            {
                stopped = true;
                return false;
            }

            findings.AddRange(fileFindings[resultIndex] ?? []);
        }

        return true;
    }

    private static IReadOnlyList<Finding> ScanSourceFileForParallelBatch(
        SourceFile file,
        CompiledRuleSet rules,
        PicketIgnore picketIgnore,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        long? maxTargetBytes,
        bool nativeMode,
        long timeoutTimestamp,
        PicketScanCache? scanCache,
        CompatibilityDiagnosticsSession? diagnosticsSession,
        out bool stopped,
        CancellationToken cancellationToken)
    {
        if (file.Length > SourceFragmentReader.DefaultBufferSize)
        {
            return ScanSourceFileFragments(
                file,
                rules,
                picketIgnore,
                ignoreGitleaksAllow,
                maxDecodeDepth,
                maxTargetBytes,
                nativeMode,
                timeoutTimestamp,
                scanCache,
                diagnosticsSession,
                out stopped,
                cancellationToken);
        }

        stopped = false;
        byte[] input = file.ReadAllBytes();
        if (picketIgnore.TryIgnoreContentHash(input) || LooksBinary(input))
        {
            return [];
        }

        diagnosticsSession?.RecordScanInput();
        if (scanCache is not null
            && scanCache.TryRead(input, file.DisplayPath, file.SymlinkDisplayPath, out List<Finding>? cachedFindings))
        {
            diagnosticsSession?.RecordCacheHit();
            return cachedFindings;
        }

        if (scanCache is not null)
        {
            diagnosticsSession?.RecordCacheMiss();
        }

        IReadOnlyList<Finding> scannedFindings = SecretScanner.Scan(new ScanRequest(
            input,
            file.DisplayPath,
            rules,
            ignoreGitleaksAllow,
            maxDecodeDepth: maxDecodeDepth,
            maxTargetBytes: maxTargetBytes,
            symlinkFile: file.SymlinkDisplayPath,
            enableCSharpStringConcatenation: nativeMode,
            isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
            cancellationToken: cancellationToken)
        {
            EnableNativeDetectors = nativeMode,
            EnableRandomnessScoring = nativeMode,
            PositionKind = nativeMode
                ? FindingPositionKind.UnicodeCodePointsExclusive
                : FindingPositionKind.GitleaksUtf8BytesInclusive,
        });
        if (IsScanStopped(timeoutTimestamp, cancellationToken))
        {
            stopped = true;
            return [];
        }

        if (scanCache is not null && nativeMode)
        {
            scannedFindings = AnnotateFindingsForNativeCache(scannedFindings);
        }

        if (scanCache is not null)
        {
            scanCache.Write(input, file.DisplayPath, scannedFindings);
            diagnosticsSession?.RecordCacheWrite();
        }

        return scannedFindings;
    }
}
