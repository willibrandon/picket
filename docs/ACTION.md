# GitHub Action

Use the repository root action to scan a checked-out workspace with Picket and publish SARIF-ready output.

```yaml
name: Secret scan

on:
  pull_request:
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write

jobs:
  picket:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.0

      - uses: willibrandon/picket@main
        with:
          upload-sarif: true
```

`security-events: write` is required only when `upload-sarif` is `true`. Use `contents: read` for normal repository checkout. The action currently runs Picket from source, so it restores the solution and uses the configured .NET SDK. Switch `setup-dotnet` to `false` when the job already installs a compatible SDK.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Repository-relative or absolute path to scan. |
| `config-path` | empty | Optional Gitleaks-compatible configuration path. |
| `baseline-path` | empty | Optional Gitleaks-compatible baseline report path. |
| `rule-packs` | empty | Optional comma-separated built-in rule packs: `picket-strict` and `picket-experimental`. |
| `cache` | `true` | Restore and save the native Picket scan cache. |
| `cache-mode` | `secret-hash-only` | Cache storage mode. Use `secret-hash-only` for public CI safety or `raw` for exact cached report replay in trusted private jobs. |
| `cache-path` | `.picket/cache` | Cache directory used by Picket and `actions/cache`. |
| `cache-key` | empty | Optional explicit cache key. Empty uses an OS, cache-mode, branch, and commit scoped default with mode-scoped branch restore keys. |
| `report-directory` | `picket-results` | Directory where `picket.sarif` and `picket.jsonl` are written. |
| `fail-on` | `findings` | Failure policy: `findings`, `errors`, or `never`. |
| `summary` | `true` | Write the Picket scan job summary. |
| `results` | empty | Optional comma-separated validation states to keep before reports, annotations, and failure enforcement. |
| `only-verified` | `false` | Keep only `structurally-valid` offline findings and `active` live-verification findings. Cannot be combined with `results`. |
| `upload-sarif` | `false` | Upload `picket.sarif` through GitHub code scanning. |
| `annotations` | `true` | Emit safe GitHub workflow warning annotations from JSONL findings. |
| `annotation-limit` | `50` | Maximum number of workflow annotations to emit. Use `0` to disable without changing `annotations`. |
| `redact` | `100` | Redaction percentage from `0` through `100`. Public CI defaults to full redaction. |
| `max-target-megabytes` | empty | Optional maximum file size in decimal MB for content rules. |
| `timeout` | empty | Optional scan timeout in seconds. Use `0` to disable. |
| `max-archive-depth` | empty | Optional maximum nested archive traversal depth. Use `0` to disable archive traversal. |
| `max-archive-entries` | empty | Optional maximum number of files extracted from archives. Use `0` to disable. |
| `max-archive-megabytes` | empty | Optional maximum decompressed archive payload in decimal MB. |
| `max-archive-ratio` | empty | Optional maximum archive expansion ratio. Use `0` to disable. |
| `dotnet-version` | `10.0.301` | .NET SDK version used by the source-based action. |
| `setup-dotnet` | `true` | Install the configured SDK before restoring and running Picket. |

## Outputs

| Output | Description |
| --- | --- |
| `exit-code` | Raw Picket scanner exit code before action failure enforcement. |
| `findings` | Number of JSONL finding records emitted by Picket. |
| `sarif-path` | Absolute path to `picket.sarif`. |
| `jsonl-path` | Absolute path to `picket.jsonl`. |
| `annotations` | Number of workflow annotations emitted. |

## Failure Modes

`fail-on: findings` fails the job when Picket reports at least one finding, or when the scanner exits unsuccessfully before producing findings.

`fail-on: errors` fails the job only when the scanner exits unsuccessfully without findings. Use this when code scanning alerts should be advisory and the workflow should fail only on scanner/runtime errors.

`fail-on: never` never fails the job after a completed scanner invocation. Invalid action inputs still fail before scanning.

The action writes SARIF and JSONL before the final failure-enforcement step. This allows `upload-sarif: true` to publish code scanning results even when `fail-on: findings` is selected.

`results` and `only-verified` filter the Picket scan result set before SARIF, JSONL, annotations, summary counts, and failure enforcement are evaluated. Use `results` for an explicit comma-separated state list such as `active,structurally-valid`, or `only-verified: true` for the standard verified-state shorthand.

## CI Matrix Scan

The repository CI runs the local composite action against the repository root on every CI runner. The matrix scan disables cache, annotations, and SARIF upload, keeps the Action summary enabled, uses `fail-on: never` for the repository's intentional test fixtures, and asserts that at least one finding plus both `picket.sarif` and `picket.jsonl` output files are produced.

## Reports And Caching

The action always writes native Picket SARIF and JSONL reports. Formats are inferred from the output extensions, so the action does not pass a global report format flag.

When `cache` is `true`, `actions/cache/restore` restores `cache-path` before scanning and `actions/cache/save` saves it before SARIF upload and final failure enforcement. The same path is passed to `picket scan --cache-dir`, and `cache-mode` is passed to `picket scan --cache-mode`.

The default action cache mode is `secret-hash-only`, so saved cache entries keep finding hashes and provenance without raw match, secret, or line text. Set `cache-mode: raw` only for trusted private CI where exact cached report replay is more important than cache privacy.

When `baseline-path` is supplied, baseline suppression is applied after cache hits and works with the default `secret-hash-only` cache mode by comparing cached evidence hashes to the baseline evidence.

The job summary includes the scanner exit code, finding count, failure policy, result filter, report paths, and capped finding breakdowns by rule and by file. Secret values are not written to the summary, and findings are fully redacted by default. Set `redact: 0` only for trusted private CI where raw secret values are acceptable.

## Annotations

When `annotations` is `true`, the action reads `picket.jsonl` and emits GitHub workflow warning annotations for up to `annotation-limit` findings. Annotation messages include only the rule ID and source location. They do not include `match`, `secret`, source line text, commit messages, or other fields that may contain raw secrets, even when `redact: 0` is selected for report artifacts.
