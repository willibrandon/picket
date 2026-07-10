using Picket.Engine;
using Picket.Security;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;

namespace Picket.Store;

/// <summary>
/// Persists an authenticated, encrypted low-water mark for an interrupted native source scan.
/// </summary>
public sealed class RemoteScanCheckpoint : IDisposable
{
    private const string HeaderPrefix = "header\t";
    private const string KeyFileName = "remote-scan-checkpoint.key";
    private const string LockSuffix = ".lock";
    private const string RecordPrefix = "record\t";
    private const string SchemaLine = "picket.remote-scan-checkpoint.v1";
    private readonly List<RemoteScanCheckpointEntry> _entries = [];
    private readonly long _maxBytes;
    private readonly string _lockPath;
    private readonly byte[] _protectionKey = [];
    private FileStream? _lockStream;
    private FileStream? _stateStream;
    private bool _completed;
    private bool _disposed;
    private static readonly byte[] s_keyDerivationPurpose = Encoding.UTF8.GetBytes("picket.remote-scan-checkpoint.payload.v1");
    private static readonly UTF8Encoding s_utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private RemoteScanCheckpoint(string path, RemoteScanCheckpointKey key, bool reset, long maxBytes)
    {
        Path = System.IO.Path.GetFullPath(path);
        Key = key;
        _maxBytes = maxBytes;
        _lockPath = string.Concat(Path, LockSuffix);

        string? directory = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        try
        {
            RejectSymbolicLink(_lockPath);
            RejectSymbolicLink(Path);
            _lockStream = OwnerOnlyFileSystem.OpenFile(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            OwnerOnlyFileSystem.ProtectFile(_lockPath);

            byte[] authenticationKey = PicketStateProtectionKey.LoadOrCreate(KeyFileName);
            try
            {
                _protectionKey = ProtectedStatePayload.DeriveKey(authenticationKey, s_keyDerivationPurpose);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authenticationKey);
            }

            if (reset)
            {
                TryDelete(Path);
            }

            if (File.Exists(Path))
            {
                RejectSymbolicLink(Path);
                _stateStream = OwnerOnlyFileSystem.OpenFile(Path, FileMode.Open, FileAccess.ReadWrite);
                Load();
            }
            else
            {
                Create();
                RejectSymbolicLink(Path);
                _stateStream = OwnerOnlyFileSystem.OpenFile(Path, FileMode.Open, FileAccess.ReadWrite);
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets the checkpoint file path.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Gets the default maximum checkpoint size in bytes.
    /// </summary>
    public const long DefaultMaxCheckpointBytes = 100_000_000;

    /// <summary>
    /// Gets the scanner and source-manifest identity bound to this checkpoint.
    /// </summary>
    public RemoteScanCheckpointKey Key { get; }

    /// <summary>
    /// Gets the number of consecutively completed source files.
    /// </summary>
    public int CompletedFileCount => _entries.Count;

    /// <summary>
    /// Opens or creates a remote scan checkpoint.
    /// </summary>
    /// <param name="path">The checkpoint file path.</param>
    /// <param name="key">The current scanner and source-manifest identity.</param>
    /// <param name="reset">A value indicating whether existing state is discarded before the scan starts.</param>
    /// <param name="maxBytes">The maximum checkpoint file size.</param>
    /// <returns>The opened checkpoint.</returns>
    public static RemoteScanCheckpoint Open(
        string path,
        RemoteScanCheckpointKey key,
        bool reset = false,
        long maxBytes = DefaultMaxCheckpointBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(key);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxBytes, 0);
        return new RemoteScanCheckpoint(path, key, reset, maxBytes);
    }

    /// <summary>
    /// Restores findings for a previously completed file at the supplied ordinal.
    /// </summary>
    /// <param name="ordinal">The zero-based position in the ordered source manifest.</param>
    /// <param name="displayPath">The normalized report path.</param>
    /// <param name="symlinkDisplayPath">The normalized symlink report path, or an empty string.</param>
    /// <param name="content">The current source bytes.</param>
    /// <param name="findings">The restored findings when the method returns <see langword="true" />.</param>
    /// <returns><see langword="true" /> when the file was completed before interruption; otherwise <see langword="false" />.</returns>
    public bool TryRestoreFile(
        int ordinal,
        string displayPath,
        string symlinkDisplayPath,
        ReadOnlySpan<byte> content,
        [NotNullWhen(true)] out List<Finding>? findings)
    {
        ThrowIfDisposed();
        ArgumentOutOfRangeException.ThrowIfNegative(ordinal);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayPath);
        symlinkDisplayPath ??= string.Empty;

        if (ordinal >= _entries.Count)
        {
            findings = null;
            return false;
        }

        RemoteScanCheckpointEntry entry = _entries[ordinal];
        string blobSha256 = BlobHasher.ComputeSha256Hex(content);
        if (entry.Ordinal != ordinal
            || !entry.DisplayPath.Equals(displayPath, StringComparison.Ordinal)
            || !entry.SymlinkDisplayPath.Equals(symlinkDisplayPath, StringComparison.Ordinal)
            || !entry.BlobSha256.Equals(blobSha256, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Checkpoint file sequence does not match the current source manifest.");
        }

        findings = [.. entry.Findings];
        return true;
    }

    /// <summary>
    /// Appends one successfully processed source file to the checkpoint low-water mark.
    /// </summary>
    /// <param name="displayPath">The normalized report path.</param>
    /// <param name="symlinkDisplayPath">The normalized symlink report path, or an empty string.</param>
    /// <param name="content">The source bytes that produced the findings.</param>
    /// <param name="findings">The unredacted findings produced for the file.</param>
    public void AppendCompletedFile(
        string displayPath,
        string symlinkDisplayPath,
        ReadOnlySpan<byte> content,
        IReadOnlyList<Finding> findings)
    {
        ThrowIfDisposed();
        ArgumentException.ThrowIfNullOrWhiteSpace(displayPath);
        ArgumentNullException.ThrowIfNull(findings);
        symlinkDisplayPath ??= string.Empty;

        int ordinal = _entries.Count;
        string blobSha256 = BlobHasher.ComputeSha256Hex(content);
        string previousRecordSha256 = ordinal == 0 ? string.Empty : _entries[^1].RecordSha256;
        string record = RemoteScanCheckpointCodec.WriteRecord(
            ordinal,
            displayPath,
            symlinkDisplayPath,
            blobSha256,
            previousRecordSha256,
            findings);
        string protectedRecord = ProtectedStatePayload.Protect(_protectionKey, record);
        string line = string.Concat(RecordPrefix, protectedRecord, "\n");
        byte[] bytes = s_utf8NoBom.GetBytes(line);
        FileStream stream = _stateStream ?? throw new InvalidOperationException("Checkpoint state file is not open.");
        long currentLength = stream.Length;
        if (bytes.LongLength > _maxBytes || currentLength > _maxBytes - bytes.LongLength)
        {
            throw new IOException($"Checkpoint exceeds maximum size: {_maxBytes} bytes.");
        }

        stream.Position = currentLength;
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);

        OwnerOnlyFileSystem.ProtectFile(Path);
        string recordSha256 = BlobHasher.ComputeSha256Hex(protectedRecord);
        _entries.Add(new RemoteScanCheckpointEntry(
            ordinal,
            displayPath,
            symlinkDisplayPath,
            blobSha256,
            recordSha256,
            [.. findings]));
    }

    /// <summary>
    /// Removes checkpoint state after reports have been written successfully.
    /// </summary>
    /// <returns><see langword="true" /> when checkpoint state was removed; otherwise <see langword="false" />.</returns>
    public bool Complete()
    {
        ThrowIfDisposed();
        ReleaseStateFile();
        bool deleted = TryDelete(Path);
        if (deleted)
        {
            _completed = true;
        }

        return deleted;
    }

    /// <summary>
    /// Releases the checkpoint lock while retaining incomplete state.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ReleaseStateFile();
        ReleaseLock();
        CryptographicOperations.ZeroMemory(_protectionKey);
    }

    private void Create()
    {
        string protectedHeader = ProtectedStatePayload.Protect(_protectionKey, RemoteScanCheckpointCodec.WriteHeader(Key));
        string contents = string.Concat(SchemaLine, "\n", HeaderPrefix, protectedHeader, "\n");
        byte[] bytes = s_utf8NoBom.GetBytes(contents);
        if (bytes.LongLength > _maxBytes)
        {
            throw new IOException($"Checkpoint exceeds maximum size: {_maxBytes} bytes.");
        }

        string tempPath = string.Concat(Path, ".", Environment.ProcessId, ".", Guid.NewGuid().ToString("N"), ".tmp");
        try
        {
            using (FileStream stream = OwnerOnlyFileSystem.OpenNewFile(tempPath))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, Path, overwrite: false);
            OwnerOnlyFileSystem.ProtectFile(Path);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private void Load()
    {
        FileStream stream = _stateStream ?? throw new InvalidOperationException("Checkpoint state file is not open.");
        if (stream.Length > _maxBytes)
        {
            throw new InvalidDataException($"Checkpoint exceeds maximum size: {_maxBytes} bytes.");
        }

        bool hasTerminatingNewline = HasTerminatingNewline(stream);
        stream.Position = 0;
        var lines = new List<string>();
        using (var reader = new StreamReader(stream, s_utf8NoBom, detectEncodingFromByteOrderMarks: false, leaveOpen: true))
        {
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                lines.Add(line);
            }
        }

        if (lines.Count < 2
            || !lines[0].Equals(SchemaLine, StringComparison.Ordinal)
            || !TryReadEnvelope(lines[1], HeaderPrefix, out string? protectedHeader)
            || !ProtectedStatePayload.TryUnprotect(_protectionKey, protectedHeader, out string header)
            || !RemoteScanCheckpointCodec.TryReadHeader(header, out string storedFingerprint))
        {
            throw new InvalidDataException("Checkpoint header is invalid or has been tampered with.");
        }

        if (!storedFingerprint.Equals(Key.Fingerprint, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Checkpoint does not match the current scan or source snapshot; use --checkpoint-reset to replace it.");
        }

        string previousRecordSha256 = string.Empty;
        for (int i = 2; i < lines.Count; i++)
        {
            bool isRecoverableCrashTail = i == lines.Count - 1 && !hasTerminatingNewline;
            if (!TryReadEnvelope(lines[i], RecordPrefix, out string? protectedRecord)
                || !ProtectedStatePayload.TryUnprotect(_protectionKey, protectedRecord, out string record)
                || !RemoteScanCheckpointCodec.TryReadRecord(record, previousRecordSha256, out RemoteScanCheckpointEntry? parsedEntry)
                || parsedEntry.Ordinal != _entries.Count)
            {
                if (isRecoverableCrashTail)
                {
                    break;
                }

                throw new InvalidDataException("Checkpoint record is invalid or has been tampered with.");
            }

            string recordSha256 = BlobHasher.ComputeSha256Hex(protectedRecord);
            _entries.Add(new RemoteScanCheckpointEntry(
                parsedEntry.Ordinal,
                parsedEntry.DisplayPath,
                parsedEntry.SymlinkDisplayPath,
                parsedEntry.BlobSha256,
                recordSha256,
                parsedEntry.Findings));
            previousRecordSha256 = recordSha256;
        }
    }

    private static bool HasTerminatingNewline(FileStream stream)
    {
        if (stream.Length == 0)
        {
            return false;
        }

        stream.Seek(-1, SeekOrigin.End);
        return stream.ReadByte() == '\n';
    }

    private static bool TryReadEnvelope(string line, string prefix, [NotNullWhen(true)] out string? value)
    {
        if (!line.StartsWith(prefix, StringComparison.Ordinal) || line.Length == prefix.Length)
        {
            value = null;
            return false;
        }

        value = line[prefix.Length..];
        return true;
    }

    private static void RejectSymbolicLink(string path)
    {
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException($"Checkpoint path must not be a symbolic link: {path}");
        }
    }

    private void ReleaseLock()
    {
        _lockStream?.Dispose();
        _lockStream = null;
    }

    private void ReleaseStateFile()
    {
        _stateStream?.Dispose();
        _stateStream = null;
    }

    private static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return !File.Exists(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed)
        {
            throw new InvalidOperationException("Checkpoint is already complete.");
        }
    }
}
