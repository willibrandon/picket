# Native Scan Cache

Picket's native `--cache-dir` stores scan results for unchanged filesystem blobs. The cache is native-only; strict Gitleaks-compatible commands reject `--cache-dir`.

## Identity

Each entry is addressed by:

- SHA-256 of the source content,
- an address discriminator,
- scanner configuration fingerprint.

The address discriminator is the narrowest safe value for the active scan behavior. Path-sensitive rule sets use the logical report path. Path-insensitive native scans that can run file-extension-specific decoders use the file extension. Scans with no path-dependent rule or decoder behavior use a content-only discriminator, so identical blobs can reuse matching work across paths while reports are rehydrated with the current path and symlink provenance.

The scanner configuration fingerprint includes the compiled rule-set fingerprint, maximum decode depth, maximum target size, whether `--ignore-gitleaks-allow` was enabled, the cache address mode when it is not the legacy path mode, and the cache storage mode when the mode is not the legacy raw mode. Changing rules or these scan options invalidates old entries without deleting them.

## Entry Format

Cache entries are UTF-8 line-oriented files under `entries/<blob-shard>/`.

Current entries include:

- schema line,
- scanner key fingerprint,
- blob hash,
- creation time as Unix seconds,
- cache address mode,
- cache storage mode,
- finding count,
- cached finding rows,
- entry authentication tag.

Entries use the authenticated `picket.scan-cache.v2` format. Picket signs each entry body with HMAC-SHA-256 using a per-user key stored outside the cache root. Edited entries, unsigned legacy entries, and imports that cannot authenticate under the current user profile are treated as invalid cache misses. This keeps cache export/import useful across cache roots for the same build identity while preventing an untrusted archive or writable cache directory from silently suppressing findings.

## Privacy

The default cache mode is `secret-hash-only`. Cache rows keep rule, location, entropy, validation, tags, decode path, blob hash, secret hash, and match hash, but omit raw match, secret, and line text. A cache hit in this mode replays hash-only findings, so raw report fields are empty while hash fields, stable fingerprints, and provenance remain available. First-pass scan output still follows the selected report and redaction settings; use `--redact=100` when report output must also avoid raw secrets.

Use `--cache-mode raw` only for trusted private caches that need cached reports to replay match, secret, and line fields exactly. Raw mode may contain recoverable secret material, and the CLI writes a warning when raw mode is active.

Picket creates the cache root, lock directory, entry directories, lock files, and entry files with owner-only permissions. Unix-like systems use owner-only mode bits. Windows uses protected ACLs that grant the current user full control and remove inherited access rules from cache-managed paths.

Baseline suppression still works with secret-hash-only cache hits. Picket compares the cached match and secret hashes to hashes of the baseline evidence rather than requiring raw cached match or secret text.

## Maintenance

`PicketScanCache.GetStats()` reports entry count, active-key entry count, and total entry bytes.

`PicketScanCache.PruneOtherKeys()` removes entries for inactive scanner configuration keys.

`PicketScanCache.PruneOlderThan(...)` removes entries older than the supplied retention age.

`PicketScanCache.Export(...)` writes entries for the active scanner configuration key to a portable zip archive.

`PicketScanCache.Import(...)` restores entries for the active scanner configuration key from a portable zip archive. Import validates archive paths, caps each decompressed cache entry at 100 decimal MB by default, caps archives at 100,000 non-directory entries and 1,000 decimal MB of imported decompressed entry data by default, authenticates entries, and validates cache entry contents before writing files under the cache root.

The native CLI wraps the same APIs:

```text
picket cache stats --cache-dir .picket/cache --source .
picket cache stats --cache-dir .picket/cache --source . --cache-mode raw
picket cache stats --cache-dir .picket/cache --source . --ignore-gitleaks-allow
picket cache prune --cache-dir .picket/cache --source . --other-keys
picket cache prune --cache-dir .picket/cache --source . --older-than-days 14
picket cache export --cache-dir .picket/cache --source . --output .picket/cache.zip
picket cache import --cache-dir .picket/cache --source . --input .picket/cache.zip
```

`picket cache stats` reports total entries, entries for the active scanner configuration key, and total entry bytes. Pass the same rule/config and scan-behavior options that created the cache, including `--cache-mode` and `--ignore-gitleaks-allow` when used, so the active-key count matches the scan behavior being inspected. `picket cache prune` requires an explicit selector: `--other-keys` deletes entries from inactive scanner keys, while `--older-than-days` applies an age-based retention policy.

`picket cache export` and `picket cache import` move only entries for the active scanner configuration key. Pass the same `--config`, `--source`, `--cache-mode`, `--max-decode-depth`, `--max-target-megabytes`, and `--ignore-gitleaks-allow` values used by the scan whose cache is being moved.

When scan diagnostics are enabled with `--diagnostics cpu`, `--diagnostics mem`, or `--diagnostics trace`, the diagnostics artifacts include aggregate `scanInputs`, `findings`, `cacheHits`, `cacheMisses`, and `cacheWrites` counters. Use these counters to verify incremental behavior without parsing report payloads or exposing raw secret evidence.
