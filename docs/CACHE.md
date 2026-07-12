# Native Scan Cache

Picket's native `--cache-dir` stores scan results for unchanged filesystem blobs. The cache is native-only; strict Gitleaks-compatible commands reject `--cache-dir`.

## Identity

Each entry is addressed by:

- SHA-256 of the source content,
- an address discriminator,
- scanner configuration fingerprint.

The cache key includes the rule-set fingerprint, scanner matching-behavior version, randomness-model version, decoder depth, target-size limit, inline-allow behavior, address mode, and storage mode. Matching changes therefore invalidate entries even when the selected rules and CLI options are unchanged.

The address discriminator is the narrowest safe value for the active scan behavior. Path-sensitive rule sets use the logical report path. Path-insensitive native scans that can run file-extension-specific decoders use the file extension. Scans with no path-dependent rule or decoder behavior use a content-only discriminator, so identical blobs can reuse matching work across paths while reports are rehydrated with the current path and symlink provenance.

Large local files are hashed through a bounded stream before cache lookup. The cache key and every cached finding retain the SHA-256 identity of the complete file, not an individual scan fragment. On a cache miss, Picket rewinds the file for scanning and rejects the result if the content identity changes before the scan completes.

The scanner configuration fingerprint includes the randomness model version, compiled rule-set fingerprint, maximum decode depth, maximum target size, whether `--ignore-gitleaks-allow` was enabled, the cache address mode when it is not the legacy path mode, and the cache storage mode when the mode is not the legacy raw mode. Changing the model, rules, or these scan options invalidates old entries without deleting them.

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

Entries use the authenticated `picket.scan-cache.v4` format. Picket signs each entry body with HMAC-SHA-256 using a per-user key stored outside the cache root. Edited entries, unsigned legacy entries, earlier schema versions, and imports that cannot authenticate under the current user profile are treated as invalid cache misses. This keeps cache export/import useful across cache roots for the same build identity while preventing an untrusted archive or writable cache directory from silently suppressing findings.

## Privacy

The default cache mode is `secret-hash-only`. Cache rows keep rule, location, entropy, validation, randomness assessment, tags, decode path, blob hash, and protected secret and match hashes, but omit raw match, secret, and line text. The protected hashes are encrypted at rest with a key derived from the per-user cache authentication key, so a copied cache root does not expose bare SHA-256 values for low-entropy secrets. A cache hit in this mode replays hash-only findings, so raw report fields are empty while hashes, stable fingerprints, randomness metadata, and provenance remain available. First-pass scan output still follows the selected report and redaction settings; use `--redact=100` when report output must also avoid raw secrets.

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

## Interrupted Source Scans

The scan cache and a scan checkpoint solve different problems. `--cache-dir` reuses matching work for unchanged blobs across completed scans. `--checkpoint <path>` preserves the consecutive work completed by one native source scan so an interrupted invocation can produce a complete report when retried.

Checkpointing is available only when `picket scan` uses a native source option such as `--github-repository`, `--s3-bucket`, `--registry-image`, `--docker-archive`, or `--oci-archive`.

```powershell
picket scan --github-repository willibrandon/picket --github-token-env PICKET_GITHUB_SOURCE_TOKEN --checkpoint .picket/github.checkpoint --report-format jsonl --report-path picket-results/github.jsonl --redact=100
```

Run the same command again after cancellation, timeout, or another operational failure. Picket re-enumerates the source, verifies the complete ordered path-and-content manifest, restores findings for the consecutive completed files, and continues at the first unfinished file. A changed source snapshot, rule set, scanner version, decode limit, target-size limit, or `--ignore-gitleaks-allow` setting rejects the checkpoint instead of silently mixing results.

Use `--checkpoint-reset` only when discarding the prior scan is intentional:

```powershell
picket scan --github-repository willibrandon/picket --github-token-env PICKET_GITHUB_SOURCE_TOKEN --checkpoint .picket/github.checkpoint --checkpoint-reset --report-format jsonl --report-path picket-results/github.jsonl --redact=100
```

Picket removes a checkpoint only after all requested reports are written successfully. Output-stage settings such as report format, report path, redaction, baseline, validation-result filtering, and live verification can change on a retry because they are applied again to the restored raw findings.

Checkpoint files contain the raw finding state required to reproduce a complete report, but each header and file record is authenticated and encrypted with a per-user key stored outside the checkpoint location. Records form a hash chain, files and locks use owner-only permissions, concurrent writers are rejected, and the default checkpoint file limit is 100 decimal MB. A copied checkpoint cannot be read under a different user profile. Do not use the same path for a checkpoint and a report.

The repository `.gitignore` excludes `*.checkpoint` and `*.checkpoint.lock`. Keep equivalent entries in repositories that use a different checkpoint naming convention so encrypted incident state is not committed accidentally.
