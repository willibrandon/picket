using Picket.Engine;
using Picket.Sources;
using Picket.Store;
using System.Buffers;
using System.Security.Cryptography;

namespace Picket;

internal static partial class Program
{
    private const int NativeFragmentOverlapBytes = 64 * 1024;
    private const int SourceFragmentForceCutBytes = SourceFragmentReader.DefaultBufferSize + SourceFragmentReader.DefaultMaxPeekBytes;
    private const int SourceHashBufferSize = 128 * 1024;

    static List<Finding> ScanSourceFileFragments(
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
        stopped = false;
        if (maxTargetBytes.HasValue && file.Length > maxTargetBytes.Value)
        {
            return [];
        }

        using Stream stream = file.OpenRead();
        using var reader = new SourceFragmentReader(stream);
        SourceFragment? firstFragment = reader.ReadNext(cancellationToken);
        try
        {
            if (firstFragment is not null
                && LooksBinary(firstFragment.Content.Span[..Math.Min(
                    firstFragment.Content.Length,
                    SourceFragmentReader.DefaultBufferSize)]))
            {
                return [];
            }

            string blobSha256 = string.Empty;
            if (picketIgnore.ContentHashCount != 0 || scanCache is not null)
            {
                long resumeOffset = firstFragment?.Content.Length ?? 0;
                stream.Position = 0;
                blobSha256 = ComputeSourceStreamSha256(stream, timeoutTimestamp, out stopped, cancellationToken);
                if (stopped || picketIgnore.TryIgnoreContentHash(blobSha256))
                {
                    return [];
                }

                stream.Position = resumeOffset;
            }

            diagnosticsSession?.RecordScanInput();
            if (scanCache is not null
                && scanCache.TryRead(blobSha256, file.DisplayPath, file.SymlinkDisplayPath, out List<Finding>? cachedFindings))
            {
                diagnosticsSession?.RecordCacheHit();
                return cachedFindings;
            }

            if (scanCache is not null)
            {
                diagnosticsSession?.RecordCacheMiss();
            }

            using IncrementalHash scannedHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            List<Finding> findings;
            HashSet<int>? forceCutLines = null;
            if (firstFragment is null)
            {
                findings = [.. ScanSourceFragment(
                    ReadOnlyMemory<byte>.Empty,
                    file,
                    rules,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    nativeMode,
                    sourceStartLine: 1,
                    sourceStartColumn: 1,
                    blobSha256,
                    timeoutTimestamp,
                    cancellationToken)];
            }
            else if (nativeMode)
            {
                forceCutLines = [];
                SourceFragment ownedFirstFragment = firstFragment;
                firstFragment = null;
                findings = ScanNativeSourceFragments(
                    reader,
                    ownedFirstFragment,
                    file,
                    rules,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    blobSha256,
                    scannedHash,
                    forceCutLines,
                    timeoutTimestamp,
                    out stopped,
                    cancellationToken);
            }
            else
            {
                SourceFragment ownedFirstFragment = firstFragment;
                firstFragment = null;
                findings = ScanCompatibleSourceFragments(
                    reader,
                    ownedFirstFragment,
                    file,
                    rules,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    blobSha256,
                    scannedHash,
                    timeoutTimestamp,
                    out stopped,
                    cancellationToken);
            }

            if (stopped || IsScanStopped(timeoutTimestamp, cancellationToken))
            {
                stopped = true;
                return [];
            }

            string scannedBlobSha256 = Convert.ToHexStringLower(scannedHash.GetHashAndReset());
            if (blobSha256.Length != 0 && !blobSha256.Equals(scannedBlobSha256, StringComparison.Ordinal))
            {
                throw new IOException($"source changed while scanning: {file.DisplayPath}");
            }

            if (!ignoreGitleaksAllow
                && findings.Count != 0
                && forceCutLines is { Count: > 0 })
            {
                stream.Position = 0;
                RemoveFindingsAllowedOnForceCutLines(
                    stream,
                    findings,
                    forceCutLines,
                    scannedBlobSha256,
                    file.DisplayPath,
                    timeoutTimestamp,
                    out stopped,
                    cancellationToken);
                if (stopped)
                {
                    return [];
                }
            }

            blobSha256 = scannedBlobSha256;
            if (findings.Count != 0)
            {
                for (int i = 0; i < findings.Count; i++)
                {
                    findings[i] = findings[i].WithBlobSha256(blobSha256);
                }
            }

            if (scanCache is not null && nativeMode)
            {
                findings = AnnotateFindingsForNativeCache(findings);
            }

            if (scanCache is not null)
            {
                scanCache.Write(blobSha256, file.DisplayPath, findings);
                diagnosticsSession?.RecordCacheWrite();
            }

            return findings;
        }
        finally
        {
            firstFragment?.Dispose();
        }
    }

    private static List<Finding> ScanCompatibleSourceFragments(
        SourceFragmentReader reader,
        SourceFragment firstFragment,
        SourceFile file,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        string blobSha256,
        IncrementalHash scannedHash,
        long timeoutTimestamp,
        out bool stopped,
        CancellationToken cancellationToken)
    {
        stopped = false;
        var findings = new List<Finding>();
        SourceFragment? fragment = firstFragment;
        while (fragment is not null)
        {
            using (fragment)
            {
                scannedHash.AppendData(fragment.Content.Span);
                findings.AddRange(ScanSourceFragment(
                    fragment.Content,
                    file,
                    rules,
                    ignoreGitleaksAllow,
                    maxDecodeDepth,
                    nativeMode: false,
                    fragment.StartLine,
                    sourceStartColumn: 1,
                    blobSha256,
                    timeoutTimestamp,
                    cancellationToken));
            }

            if (IsScanStopped(timeoutTimestamp, cancellationToken))
            {
                stopped = true;
                return [];
            }

            fragment = reader.ReadNext(cancellationToken);
        }

        return findings;
    }

    private static List<Finding> ScanNativeSourceFragments(
        SourceFragmentReader reader,
        SourceFragment firstFragment,
        SourceFile file,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        string blobSha256,
        IncrementalHash scannedHash,
        HashSet<int> forceCutLines,
        long timeoutTimestamp,
        out bool stopped,
        CancellationToken cancellationToken)
    {
        stopped = false;
        var findings = new List<Finding>();
        var seen = new HashSet<(string RuleId, int StartLine, int EndLine, int StartColumn, int EndColumn, string Match, string Secret, string DecodePath)>();
        byte[]? overlap = null;
        int overlapLength = 0;
        int overlapStartColumn = 1;
        int overlapStartLine = 1;
        List<Finding> deferredFindings = [];
        SourceFragment? fragment = firstFragment;
        try
        {
            while (fragment is not null)
            {
                using (fragment)
                {
                    scannedHash.AppendData(fragment.Content.Span);
                    RecordForceCutLine(fragment, forceCutLines);
                    IReadOnlyList<Finding> fragmentFindings;
                    if (overlap is not null)
                    {
                        fragmentFindings = ScanCombinedSourceFragment(
                            overlap,
                            overlapLength,
                            fragment,
                            file,
                            rules,
                            ignoreGitleaksAllow,
                            maxDecodeDepth,
                            overlapStartLine,
                            overlapStartColumn,
                            blobSha256,
                            timeoutTimestamp,
                            cancellationToken);
                        ArrayPool<byte>.Shared.Return(overlap, clearArray: true);
                        overlap = null;
                    }
                    else
                    {
                        fragmentFindings = ScanSourceFragment(
                            fragment.Content,
                            file,
                            rules,
                            ignoreGitleaksAllow,
                            maxDecodeDepth,
                            nativeMode: true,
                            fragment.StartLine,
                            fragment.StartColumn,
                            blobSha256,
                            timeoutTimestamp,
                            cancellationToken);
                    }

                    overlap = CreateOverlap(fragment, out overlapLength, out overlapStartLine, out overlapStartColumn);
                    deferredFindings = AddFinalizedFindings(
                        findings,
                        seen,
                        fragmentFindings,
                        overlapStartLine,
                        overlapStartColumn);
                }

                if (IsScanStopped(timeoutTimestamp, cancellationToken))
                {
                    stopped = true;
                    return [];
                }

                fragment = reader.ReadNext(cancellationToken);
            }

            AddUniqueFindings(findings, seen, deferredFindings);
            return SecretScanner.ApplyGitleaksGenericRulePrecedence(findings);
        }
        finally
        {
            fragment?.Dispose();
            if (overlap is not null)
            {
                ArrayPool<byte>.Shared.Return(overlap, clearArray: true);
            }
        }
    }

    private static IReadOnlyList<Finding> ScanCombinedSourceFragment(
        byte[] overlap,
        int overlapLength,
        SourceFragment fragment,
        SourceFile file,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        int sourceStartLine,
        int sourceStartColumn,
        string blobSha256,
        long timeoutTimestamp,
        CancellationToken cancellationToken)
    {
        int combinedLength = checked(overlapLength + fragment.Content.Length);
        byte[] combined = ArrayPool<byte>.Shared.Rent(combinedLength);
        try
        {
            overlap.AsSpan(0, overlapLength).CopyTo(combined);
            fragment.Content.Span.CopyTo(combined.AsSpan(overlapLength));
            return SecretScanner.Scan(new ScanRequest(
                combined.AsMemory(0, combinedLength),
                file.DisplayPath,
                rules,
                ignoreGitleaksAllow,
                maxDecodeDepth: maxDecodeDepth,
                symlinkFile: file.SymlinkDisplayPath,
                enableCSharpStringConcatenation: true,
                isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
                cancellationToken: cancellationToken)
            {
                BlobSha256 = blobSha256,
                EnableRandomnessScoring = true,
                SourceStartColumn = sourceStartColumn,
                SourceStartLine = sourceStartLine,
            });
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(combined, clearArray: true);
        }
    }

    private static IReadOnlyList<Finding> ScanSourceFragment(
        ReadOnlyMemory<byte> content,
        SourceFile file,
        CompiledRuleSet rules,
        bool ignoreGitleaksAllow,
        int maxDecodeDepth,
        bool nativeMode,
        int sourceStartLine,
        int sourceStartColumn,
        string blobSha256,
        long timeoutTimestamp,
        CancellationToken cancellationToken)
    {
        return SecretScanner.Scan(new ScanRequest(
            content,
            file.DisplayPath,
            rules,
            ignoreGitleaksAllow,
            maxDecodeDepth: maxDecodeDepth,
            symlinkFile: file.SymlinkDisplayPath,
            enableCSharpStringConcatenation: nativeMode,
            isCancellationRequested: () => IsScanStopped(timeoutTimestamp, cancellationToken),
            cancellationToken: cancellationToken)
        {
            BlobSha256 = blobSha256,
            EnableRandomnessScoring = nativeMode,
            SourceStartColumn = sourceStartColumn,
            SourceStartLine = sourceStartLine,
        });
    }

    private static byte[] CreateOverlap(
        SourceFragment fragment,
        out int overlapLength,
        out int overlapStartLine,
        out int overlapStartColumn)
    {
        ReadOnlySpan<byte> content = fragment.Content.Span;
        int overlapStart = Math.Max(0, content.Length - NativeFragmentOverlapBytes);
        int lineBoundary = content[..overlapStart].LastIndexOf((byte)'\n');
        if (lineBoundary >= 0)
        {
            overlapStart = lineBoundary + 1;
        }
        else
        {
            overlapStart = 0;
        }

        CalculatePosition(
            content[..overlapStart],
            fragment.StartLine,
            fragment.StartColumn,
            out overlapStartLine,
            out overlapStartColumn);
        overlapLength = content.Length - overlapStart;
        byte[] overlap = ArrayPool<byte>.Shared.Rent(overlapLength);
        content[overlapStart..].CopyTo(overlap);
        return overlap;
    }

    private static string ComputeSourceStreamSha256(
        Stream stream,
        long timeoutTimestamp,
        out bool stopped,
        CancellationToken cancellationToken)
    {
        stopped = false;
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(SourceHashBufferSize);
        try
        {
            while (true)
            {
                if (IsScanStopped(timeoutTimestamp, cancellationToken))
                {
                    stopped = true;
                    return string.Empty;
                }

                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    return Convert.ToHexStringLower(hash.GetHashAndReset());
                }

                hash.AppendData(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static void AddUniqueFindings(
        List<Finding> destination,
        HashSet<(string RuleId, int StartLine, int EndLine, int StartColumn, int EndColumn, string Match, string Secret, string DecodePath)> seen,
        List<Finding> findings)
    {
        for (int i = 0; i < findings.Count; i++)
        {
            AddUniqueFinding(destination, seen, findings[i]);
        }
    }

    private static List<Finding> AddFinalizedFindings(
        List<Finding> destination,
        HashSet<(string RuleId, int StartLine, int EndLine, int StartColumn, int EndColumn, string Match, string Secret, string DecodePath)> seen,
        IReadOnlyList<Finding> findings,
        int overlapStartLine,
        int overlapStartColumn)
    {
        var deferred = new List<Finding>();
        for (int i = 0; i < findings.Count; i++)
        {
            Finding finding = findings[i];
            if (finding.EndLine < overlapStartLine
                || (finding.EndLine == overlapStartLine && finding.EndColumn <= overlapStartColumn))
            {
                AddUniqueFinding(destination, seen, finding);
            }
            else
            {
                deferred.Add(finding);
            }
        }

        return deferred;
    }

    private static void AddUniqueFinding(
        List<Finding> destination,
        HashSet<(string RuleId, int StartLine, int EndLine, int StartColumn, int EndColumn, string Match, string Secret, string DecodePath)> seen,
        Finding finding)
    {
        var key = (
            finding.RuleID,
            finding.StartLine,
            finding.EndLine,
            finding.StartColumn,
            finding.EndColumn,
            finding.Match,
            finding.Secret,
            string.Join('\u001f', finding.DecodePath));
        if (seen.Add(key))
        {
            destination.Add(finding);
        }
    }

    private static void RecordForceCutLine(SourceFragment fragment, HashSet<int> forceCutLines)
    {
        ReadOnlySpan<byte> content = fragment.Content.Span;
        if (content.Length != SourceFragmentForceCutBytes || content[^1] == (byte)'\n')
        {
            return;
        }

        CalculatePosition(
            content,
            fragment.StartLine,
            fragment.StartColumn,
            out int line,
            out _);
        forceCutLines.Add(line);
    }

    private static void RemoveFindingsAllowedOnForceCutLines(
        Stream stream,
        List<Finding> findings,
        HashSet<int> forceCutLines,
        string expectedBlobSha256,
        string displayPath,
        long timeoutTimestamp,
        out bool stopped,
        CancellationToken cancellationToken)
    {
        stopped = false;
        int[] candidateLines = [.. findings
            .Select(static finding => finding.StartLine)
            .Where(forceCutLines.Contains)
            .Distinct()
            .Order()];
        if (candidateLines.Length == 0)
        {
            return;
        }

        ReadOnlySpan<byte> marker = "gitleaks:allow"u8;
        var allowedLines = new HashSet<int>();
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(SourceHashBufferSize);
        int candidateIndex = 0;
        int currentLine = 1;
        int markerOffset = 0;
        try
        {
            while (true)
            {
                if (IsScanStopped(timeoutTimestamp, cancellationToken))
                {
                    stopped = true;
                    return;
                }

                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
                for (int i = 0; i < read; i++)
                {
                    byte value = buffer[i];
                    if (candidateIndex < candidateLines.Length && currentLine == candidateLines[candidateIndex])
                    {
                        if (value == marker[markerOffset])
                        {
                            markerOffset++;
                            if (markerOffset == marker.Length)
                            {
                                allowedLines.Add(currentLine);
                                markerOffset = 0;
                            }
                        }
                        else
                        {
                            markerOffset = value == marker[0] ? 1 : 0;
                        }
                    }

                    if (value != (byte)'\n')
                    {
                        continue;
                    }

                    currentLine++;
                    markerOffset = 0;
                    while (candidateIndex < candidateLines.Length && candidateLines[candidateIndex] < currentLine)
                    {
                        candidateIndex++;
                    }
                }
            }

            string actualBlobSha256 = Convert.ToHexStringLower(hash.GetHashAndReset());
            if (!actualBlobSha256.Equals(expectedBlobSha256, StringComparison.Ordinal))
            {
                throw new IOException($"source changed while scanning: {displayPath}");
            }

            if (allowedLines.Count != 0)
            {
                findings.RemoveAll(finding => allowedLines.Contains(finding.StartLine));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static void CalculatePosition(
        ReadOnlySpan<byte> content,
        int startLine,
        int startColumn,
        out int line,
        out int column)
    {
        line = startLine;
        column = startColumn;
        for (int i = 0; i < content.Length; i++)
        {
            if (content[i] == (byte)'\n')
            {
                line++;
                column = 1;
            }
            else
            {
                column++;
            }
        }
    }
}
