# Native Scan Cache

Picket's native `--cache-dir` stores scan results for unchanged filesystem blobs. The cache is native-only; strict Gitleaks-compatible commands reject `--cache-dir`.

## Identity

Each entry is addressed by:

- SHA-256 of the source content,
- SHA-256 of the logical report path,
- scanner configuration fingerprint.

The scanner configuration fingerprint includes the compiled rule-set fingerprint, maximum decode depth, and maximum target size. Changing rules or these scan options invalidates old entries without deleting them.

## Entry Format

Cache entries are UTF-8 line-oriented files under `entries/<blob-shard>/`.

Current entries include:

- schema line,
- scanner key fingerprint,
- blob hash,
- creation time as Unix seconds,
- finding count,
- cached finding rows.

Older entries without creation and finding-count metadata remain readable. Corrupt entries are treated as misses and are not allowed to fail a scan.

## Privacy

The cache may contain finding match and secret fields because cached findings must preserve native report behavior. Use a workspace-local or protected cache directory. Public CI should rely on normal Picket redaction for logs and annotations and should avoid uploading raw cache contents as generic artifacts.

## Maintenance

`PicketScanCache.GetStats()` reports entry count, active-key entry count, and total entry bytes.

`PicketScanCache.PruneOtherKeys()` removes entries for inactive scanner configuration keys.

`PicketScanCache.PruneOlderThan(...)` removes entries older than the supplied retention age.

These APIs are the current building blocks for the design's cache garbage-collection and retention policy. Future CLI maintenance commands can wrap the same APIs.
