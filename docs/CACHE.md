# Native Scan Cache

Picket's native `--cache-dir` stores scan results for unchanged filesystem blobs. The cache is native-only; strict Gitleaks-compatible commands reject `--cache-dir`.

## Identity

Each entry is addressed by:

- SHA-256 of the source content,
- SHA-256 of the logical report path,
- scanner configuration fingerprint.

The scanner configuration fingerprint includes the compiled rule-set fingerprint, maximum decode depth, maximum target size, and whether `--ignore-gitleaks-allow` was enabled. Changing rules or these scan options invalidates old entries without deleting them.

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

`PicketScanCache.Export(...)` writes entries for the active scanner configuration key to a portable zip archive.

`PicketScanCache.Import(...)` restores entries for the active scanner configuration key from a portable zip archive. Import validates archive paths and cache entry contents before writing files under the cache root.

The native CLI wraps the same APIs:

```text
picket cache stats --cache-dir .picket/cache --source .
picket cache stats --cache-dir .picket/cache --source . --ignore-gitleaks-allow
picket cache prune --cache-dir .picket/cache --source . --other-keys
picket cache prune --cache-dir .picket/cache --source . --older-than-days 14
picket cache export --cache-dir .picket/cache --source . --output .picket/cache.zip
picket cache import --cache-dir .picket/cache --source . --input .picket/cache.zip
```

`picket cache stats` reports total entries, entries for the active scanner configuration key, and total entry bytes. Pass the same rule/config and scan-behavior options that created the cache, including `--ignore-gitleaks-allow` when used, so the active-key count matches the scan behavior being inspected. `picket cache prune` requires an explicit selector: `--other-keys` deletes entries from inactive scanner keys, while `--older-than-days` applies an age-based retention policy.

`picket cache export` and `picket cache import` move only entries for the active scanner configuration key. Pass the same `--config`, `--source`, `--max-decode-depth`, `--max-target-megabytes`, and `--ignore-gitleaks-allow` values used by the scan whose cache is being moved.
