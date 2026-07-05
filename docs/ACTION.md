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
| `cache` | `true` | Restore and save the native Picket scan cache. |
| `cache-path` | `.picket/cache` | Cache directory used by Picket and `actions/cache`. |
| `cache-key` | empty | Optional explicit cache key. Empty uses an OS, branch, and commit scoped default with branch restore keys. |
| `report-directory` | `picket-results` | Directory where `picket.sarif` and `picket.jsonl` are written. |
| `fail-on` | `findings` | Failure policy: `findings`, `errors`, or `never`. |
| `upload-sarif` | `false` | Upload `picket.sarif` through GitHub code scanning. |
| `annotations` | `true` | Emit safe GitHub workflow warning annotations from JSONL findings. |
| `annotation-limit` | `50` | Maximum number of workflow annotations to emit. Use `0` to disable without changing `annotations`. |
| `redact` | `100` | Redaction percentage from `0` through `100`. Public CI defaults to full redaction. |
| `max-target-megabytes` | empty | Optional maximum file size in MiB for content rules. |
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

## Reports And Caching

The action always writes native Picket SARIF and JSONL reports. Formats are inferred from the output extensions, so the action does not pass a global report format flag.

When `cache` is `true`, `actions/cache/restore` restores `cache-path` before scanning and `actions/cache/save` saves it before SARIF upload and final failure enforcement. The same path is passed to `picket scan --cache-dir`.

The job summary includes the scanner exit code, finding count, failure policy, and report paths. Secret values are not written to the summary, and findings are fully redacted by default. Set `redact: 0` only for trusted private CI where raw secret values are acceptable.

## Annotations

When `annotations` is `true`, the action reads `picket.jsonl` and emits GitHub workflow warning annotations for up to `annotation-limit` findings. Annotation messages include only the rule ID and source location. They do not include `match`, `secret`, source line text, commit messages, or other fields that may contain raw secrets, even when `redact: 0` is selected for report artifacts.
