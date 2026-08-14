# GitHub Action

Use the repository root action to scan a checked-out workspace or container image with Picket and publish SARIF-ready output.

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
      - uses: actions/checkout@v7.0.1

      - uses: willibrandon/picket@main
        with:
          upload-sarif: true
```

`security-events: write` is required only when `upload-sarif` is `true`. Use `contents: read` for normal repository checkout. The action currently runs Picket from source, so it restores the solution and uses the configured .NET SDK. Switch `setup-dotnet` to `false` when the job already installs a compatible SDK.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | GitHub workspace | Repository-relative or absolute path to scan. Mutually exclusive with `docker-archive`, `oci-archive`, and `registry-image`. |
| `docker-archive` | empty | Docker image archive produced by `docker save`. Relative paths resolve from the GitHub workspace. |
| `oci-archive` | empty | OCI image-layout archive. Relative paths resolve from the GitHub workspace. |
| `registry-image` | empty | OCI or Docker registry image reference, including Docker Hub shorthand. |
| `registry-endpoint` | empty | Optional OCI Distribution API endpoint override. Requires `registry-image`. |
| `registry-auth-endpoint` | empty | Optional explicitly trusted cross-host bearer-token endpoint. Requires `registry-image`. |
| `registry-token-env` | empty | Environment variable containing a pre-issued bearer token. Mutually exclusive with Basic authentication inputs. |
| `registry-username-env` | empty | Environment variable containing the registry username. Requires `registry-password-env`. |
| `registry-password-env` | empty | Environment variable containing the registry password or personal access token. Requires `registry-username-env`. |
| `registry-platform` | empty | Optional `os/architecture[/variant]` selector for a multi-platform image. |
| `registry-max-image-megabytes` | empty | Optional positive aggregate download cap for unique manifests, configs, and layers in decimal MB. |
| `allow-non-public-source-endpoints` | `false` | Permit private, loopback, link-local, or otherwise non-public registry endpoint addresses. |
| `allow-insecure-source-endpoints` | `false` | Permit HTTP registry endpoints in explicitly trusted environments. Credentials may be sent in cleartext. |
| `config-path` | empty | Optional configuration path. A custom config replaces Picket's embedded native default rules. |
| `baseline-path` | empty | Optional Gitleaks-compatible baseline report path. |
| `ignore-path` | empty | Optional `.picketignore` path containing native stable finding fingerprints or `sha256:` content hashes. |
| `rule-packs` | empty | Optional comma-separated built-in rule packs: `picket-strict` and `picket-experimental`. |
| `cache` | `true` | Restore and save the native Picket scan cache. |
| `cache-mode` | `secret-hash-only` | Cache storage mode. Use `secret-hash-only` for public CI safety or `raw` for exact cached report replay in trusted private jobs. |
| `cache-path` | runner temp `picket-cache` | Cache directory used by Picket and `actions/cache`. |
| `cache-key` | empty | Optional explicit cache key. Empty uses an OS, cache-mode, branch, and commit scoped default with mode-scoped branch restore keys. |
| `report-directory` | runner temp `picket-results` | Directory where `picket.sarif` and `picket.jsonl` are written. |
| `fail-on` | `findings` | Failure policy: `findings`, `errors`, or `never`. |
| `summary` | `true` | Write the Picket scan job summary. |
| `results` | empty | Optional comma-separated validation states to keep before reports, annotations, and failure enforcement. |
| `only-verified` | `false` | Keep only `structurally-valid` offline findings and `active` live-verification findings. Cannot be combined with `results`. |
| `verify` | `false` | Enable opt-in live provider verification. |
| `live-max-requests` | `100` | Maximum outbound live-verification requests during one scan. |
| `live-max-requests-per-provider` | `25` | Maximum outbound live-verification requests to any one provider during one scan. |
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
| `dotnet-version` | `10.0.302` | .NET SDK version used by the source-based action. |
| `setup-dotnet` | `true` | Install the configured SDK before restoring and running Picket. |

Supplying `config-path` replaces the embedded native default rule set, including Picket-owned high-confidence rules. `[extend] useDefault = true` restores the Gitleaks default rules, not Picket's complete native default profile. Review the resolved rule set with `picket rules check --print-config` before using a custom config as a required CI gate; otherwise the scan can cover fewer credential types than the default Action configuration.

`ignore-path` accepts the same native entries as `.picketignore`. Copy a full `picket:v1:<sha256>` fingerprint from a native report to suppress that stable finding, or use `sha256:<content-sha256>` to suppress an entire file by content identity.

## Container Image Sources

`path`, `docker-archive`, `oci-archive`, and `registry-image` are primary source selectors. Specify at most one. When all four are empty, the action scans `github.workspace`, preserving the original repository-scan default. Source selection changes only how Picket obtains bytes; the same config, ignore file, rule packs, cache, reports, redaction, annotations, validation filters, and `fail-on` policy apply afterward.

To scan an image built in the same job, keep the image export local to the runner and pass the archive directly to the action:

```yaml
- name: Build application image
  run: docker build --tag example-app:ci .

- name: Export application image
  run: docker save --output "${{ runner.temp }}/example-app.tar" example-app:ci

- name: Scan application image
  id: picket
  uses: willibrandon/picket@main
  with:
    docker-archive: ${{ runner.temp }}/example-app.tar
    ignore-path: .picketignore
    max-target-megabytes: 64
    max-archive-depth: 2
    max-archive-entries: 100000
    max-archive-megabytes: 4096
    max-archive-ratio: 1000
    timeout: 900
    redact: 100
    fail-on: findings
```

Use `oci-archive` instead when the producer writes an OCI image-layout archive. Both archive paths may be absolute or relative to `github.workspace`. Findings retain their virtual in-image provenance in SARIF and JSONL; annotations and summaries never include raw match or secret text.

Registry scans are anonymous unless authentication environment variable names are supplied:

```yaml
- name: Scan private registry image
  uses: willibrandon/picket@main
  env:
    PICKET_REGISTRY_TOKEN: ${{ secrets.PICKET_REGISTRY_TOKEN }}
  with:
    registry-image: ghcr.io/example/private-app@sha256:0123456789abcdef
    registry-token-env: PICKET_REGISTRY_TOKEN
    registry-platform: linux/amd64
    registry-max-image-megabytes: 512
    redact: 100
```

The action passes only the environment variable name on the Picket command line; the credential value remains in the step environment. Choose either `registry-token-env` or the complete `registry-username-env` plus `registry-password-env` pair. Mixed or partial authentication is rejected before the scanner starts. Registry-specific controls without `registry-image`, and combinations of multiple primary sources, are also rejected before scanning.

Registry endpoints must be public HTTPS by default. `allow-non-public-source-endpoints` and `allow-insecure-source-endpoints` are explicit exceptions for controlled environments. Review the complete download, redirect, digest-verification, and endpoint policy in [Container Images](https://willibrandon.github.io/picket/generated/containers/).

## Outputs

| Output | Description |
| --- | --- |
| `exit-code` | Raw Picket scanner exit code before action failure enforcement. |
| `findings` | Number of JSONL finding records emitted by Picket. |
| `sarif-path` | Absolute path to `picket.sarif`. |
| `jsonl-path` | Absolute path to `picket.jsonl`. |
| `annotations` | Number of workflow annotations emitted. |

## Failure Modes

`fail-on: findings` fails the job when Picket reports at least one finding.

`fail-on: errors` keeps findings advisory and fails only for scanner or runtime errors.

`fail-on: never` suppresses finding-based failure. Invalid inputs, scanner startup failures, and incomplete scans still fail the action. Native scanner exit code `2` identifies an incomplete or failed scan even when a partial report contains findings.

The action writes SARIF and JSONL before the final failure-enforcement step. This allows `upload-sarif: true` to publish code scanning results even when `fail-on: findings` is selected.

`results` and `only-verified` filter the Picket scan result set before SARIF, JSONL, annotations, summary counts, and failure enforcement are evaluated. Use `results` for an explicit comma-separated state list such as `active,structurally-valid`, or `only-verified: true` for the standard verified-state shorthand.

`verify: true` permits Picket to submit supported candidate credentials to their provider validation endpoints. Each outbound attempt, including retries, consumes both the global and provider request budgets. Cache hits do not consume either budget. The action rejects non-positive budget values before scanning.

## CI Matrix Scan

The repository CI runs the local composite action against the repository root on every CI runner. The matrix scan disables cache, annotations, and SARIF upload, keeps the Action summary enabled, uses `fail-on: never` for the repository's intentional test fixtures, and asserts that at least one finding plus both `picket.sarif` and `picket.jsonl` output files are produced. The Linux x64 job also builds a real `FROM scratch` Docker image, exports it with `docker save`, scans it through the Action's `docker-archive` input, and verifies report production, in-image provenance, and full secret redaction.

## Reports And Caching

The action always writes native Picket SARIF and JSONL reports. Formats are inferred from the output extensions, so the action does not pass a global report format flag. By default, reports are written beneath `runner.temp` rather than the checked-out workspace, preventing an earlier report from becoming scan input. An explicit relative `report-directory` remains workspace-relative.

When `cache` is `true`, `actions/cache/restore` restores `cache-path` before scanning and `actions/cache/save` saves it before SARIF upload and final failure enforcement. The same path is passed to `picket scan --cache-dir`, and `cache-mode` is passed to `picket scan --cache-mode`. The default cache path is beneath `runner.temp`; an explicit relative `cache-path` remains workspace-relative.

The default action cache mode is `secret-hash-only`, so saved cache entries keep finding hashes and provenance without raw match, secret, or line text. Set `cache-mode: raw` only for trusted private CI where exact cached report replay is more important than cache privacy.

When `baseline-path` is supplied, baseline suppression is applied after cache hits and works with the default `secret-hash-only` cache mode by comparing cached evidence hashes to the baseline evidence.

The job summary includes the scanner exit code, finding count, failure policy, result filter, report paths, and capped finding breakdowns by rule and by file. Secret values are not written to the summary, and findings are fully redacted by default. Set `redact: 0` only for trusted private CI where raw secret values are acceptable.

## Annotations

When `annotations` is `true`, the action reads `picket.jsonl` and emits GitHub workflow warning annotations for up to `annotation-limit` findings. Annotation messages include only the rule ID and source location. They do not include `match`, `secret`, source line text, commit messages, or other fields that may contain raw secrets, even when `redact: 0` is selected for report artifacts.
