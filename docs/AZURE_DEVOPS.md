# Azure DevOps

Picket's Azure DevOps support has two layers:

- a pipeline task that scans the checked-out workspace by default,
- optional native Azure DevOps source enumeration for repositories, pull requests, wikis, pipeline artifacts and logs, release artifacts, and Azure Artifacts NuGet packages.

The pipeline task is a distribution wrapper around the same Picket CLI behavior used locally and in other CI systems. Remote Azure DevOps enumeration is native Picket behavior and does not change strict Gitleaks-compatible commands.

## Pipeline Task Contract

The task name is `PicketScan@1`. Task metadata lives in `azure-devops/tasks/PicketScanV1/task.json`, and the Azure DevOps extension manifest lives in `azure-devops/vss-extension.json`. The default execution scans `$(Build.SourcesDirectory)` with the native scan surface and writes JSONL, SARIF, and HTML reports under a task-controlled report directory.

```yaml
steps:
  - checkout: self
    fetchDepth: 0

  - task: PicketScan@1
    inputs:
      target: "$(Build.SourcesDirectory)"
      reportFormats: "sarif,jsonl,html"
      failOn: "findings"
```

The direct CLI equivalent is:

```powershell
picket scan "$env:BUILD_SOURCESDIRECTORY" --report-path picket-results/picket.jsonl --report-path picket-results/picket.sarif --report-path picket-results/picket.html
```

The task keeps task behavior thin and predictable. Input validation, report writing, baseline handling, validation-result filtering, cache behavior, archive limits, redaction, and scanner exit-code classification come from the CLI. The task's `failOn` policy is wrapper behavior applied after the CLI exits and reports are written.

The current task wrapper invokes an existing `picket` executable through the `picketPath` input. Release packaging can later bundle signed CLI binaries or acquire checksummed release artifacts, but that packaging path must keep the same task inputs and CLI behavior.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `target` | `$(Build.SourcesDirectory)` | File, directory, or checked-out repository path to scan. |
| `picketPath` | `picket` | Path to the Picket executable or command name available on `PATH`. |
| `config` | empty | Optional Picket or Gitleaks-compatible configuration path. |
| `profile` | `picket` | Scan profile. Use `gitleaks` only when strict compatibility behavior is desired. |
| `rulePacks` | empty | Optional comma-separated built-in rule packs: `picket-strict` and `picket-experimental`. |
| `reportFormats` | `sarif,jsonl,html` | Comma-separated report formats published by the task. |
| `reportDirectory` | `$(Build.ArtifactStagingDirectory)/picket` | Directory where task reports are written. |
| `failOn` | `findings` | Failure policy: `findings`, `errors`, or `never`. Scanner execution errors always fail the task; `never` only suppresses finding-based failure. |
| `baselinePath` | empty | Optional baseline report used to suppress known findings. |
| `results` | empty | Optional comma-separated validation states to keep before reports and failure enforcement. |
| `onlyVerified` | `false` | Keep only offline structurally valid findings and live active findings. |
| `redact` | `100` | Redaction percentage from `0` through `100`. Public pipeline examples use full redaction. |
| `verify` | `false` | Enable opt-in live provider verification. |
| `annotations` | `true` | Emit safe Azure DevOps log issues when a finding has a source location that can be reported without leaking secrets. |
| `annotationLimit` | `50` | Maximum number of log issues emitted by the task. Use `0` to disable annotation output. |
| `publishSarif` | `true` | Publish SARIF as a build artifact. |
| `publishJsonl` | `true` | Publish native JSONL as a build artifact. |
| `publishHtml` | `true` | Publish the HTML report as a build artifact. |
| `cache` | `true` | Pass a native Picket scan cache directory to the CLI. |
| `cacheMode` | `secret-hash-only` | Cache storage mode. Use `raw` only in trusted private jobs. |
| `cachePath` | `$(Pipeline.Workspace)/.picket/cache` | Cache directory passed to the CLI. |
| `maxTargetMegabytes` | empty | Optional maximum file size in decimal MB for content rules. |
| `maxArchiveDepth` | empty | Optional maximum nested archive traversal depth. |
| `maxArchiveEntries` | empty | Optional maximum number of files extracted from archives. |
| `maxArchiveMegabytes` | empty | Optional maximum decompressed archive payload in decimal MB. |
| `maxArchiveRatio` | empty | Optional maximum archive expansion ratio. |
| `timeout` | empty | Optional scan timeout in seconds. Use `0` to disable. |
| `azureDevOpsOrganization` | empty | Optional organization name or URL for remote Azure DevOps enumeration. |
| `azureDevOpsEndpoint` | empty | Optional endpoint override for Azure DevOps Server. |
| `azureDevOpsTokenEnv` | empty | Environment variable containing the PAT or job token. The token value is not passed on the command line. |
| `azureDevOpsTokenKind` | `pat` | Credential transport: `pat` for personal access tokens or `bearer` for job and Entra tokens. |
| `azureDevOpsProject` | empty | Optional project filter. |
| `azureDevOpsRepository` | empty | Optional repository filter. |
| `azureDevOpsBranch` | empty | Optional branch name. |
| `azureDevOpsPullRequest` | empty | Optional pull request ID to scan. |
| `azureDevOpsIncludeWikis` | `false` | Include Azure DevOps wiki backing repositories. |
| `azureDevOpsBuildId` | empty | Build ID used when scanning build artifacts or build logs. |
| `azureDevOpsIncludeArtifacts` | `false` | Include build artifact contents for the selected build. |
| `azureDevOpsIncludeLogs` | `false` | Include build logs for the selected build. |
| `azureDevOpsReleaseId` | empty | Classic release ID used when scanning release build artifacts. |
| `azureDevOpsIncludeReleaseArtifacts` | `false` | Include build artifact contents referenced by the selected classic release. |
| `azureDevOpsIncludePackages` | `false` | Include the latest NuGet package versions from readable Azure Artifacts feeds. |
| `azureDevOpsFeed` | empty | Optional Azure Artifacts feed name or ID filter. |
| `azureDevOpsPackage` | empty | Optional exact NuGet package name filter. |
| `azureDevOpsPackageVersion` | empty | Optional exact NuGet package version. Requires `azureDevOpsPackage`. |
| `azureDevOpsMaxArtifactMegabytes` | empty | Positive per-artifact archive download cap. |
| `azureDevOpsMaxLogMegabytes` | empty | Positive per-log download cap. |
| `azureDevOpsMaxPackageMegabytes` | empty | Positive per-package archive download cap. Requires `azureDevOpsIncludePackages`. |
| `allowNonPublicSourceEndpoints` | `false` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses. |
| `allowInsecureSourceEndpoints` | `false` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-hosted environments. |
| `extraArgs` | empty | Additional CLI arguments appended after validated task inputs. |

The task rejects contradictory inputs before invoking the scanner. Examples include `results` with `onlyVerified`, invalid redaction percentages, negative archive limits, or report formats that the CLI does not support. Optional `config` and `baselinePath` inputs are forwarded only when they name files rather than the checkout directory supplied by an empty Azure Pipelines file-path control.

## Outputs

| Output | Description |
| --- | --- |
| `exitCode` | Raw scanner exit code before task failure enforcement. |
| `findings` | Number of emitted native JSONL finding records after filters. |
| `sarifPath` | Absolute path to the SARIF report when enabled. |
| `jsonlPath` | Absolute path to the JSONL report when enabled. |
| `htmlPath` | Absolute path to the HTML report when enabled. |
| `annotations` | Number of Azure DevOps log issues emitted. |

The task summary reports scanner exit code, finding count, fail mode, validation-result filters, cache status, report paths, and capped finding breakdowns by rule and file. The summary must not include match text, secret text, source line text, commit messages, or request/response bodies.

## Source Enumeration

Azure DevOps Services and Azure DevOps Server enumeration is opt-in. Workspace scanning remains the default because it is deterministic, uses normal checkout permissions, and avoids surprising remote API access.

The native Azure DevOps source model includes:

- Azure Repos Git repositories,
- project-scoped and organization-scoped repository discovery,
- pull request source heads and branch scopes,
- wiki repositories,
- build artifacts,
- pipeline logs,
- classic release build artifacts where the server exposes them safely,
- Azure Artifacts NuGet packages.

Repository file enumeration is implemented.

Additional source kinds are implemented behind explicit options:

- Pull request source-head enumeration is available behind `--azure-devops-pull-request`. Picket resolves pull request metadata through the Git Pull Requests API and scans the returned source commit in the source repository, including fork sources when Azure DevOps returns them, falling back to the source branch when a commit is not returned.
- Wiki backing repository enumeration is available behind `--azure-devops-include-wikis`. Picket lists wikis through the Wiki REST API, uses the wiki backing repository and mapped path, and scans wiki blobs through the Git Items API.
- Build artifact enumeration is available behind `--azure-devops-include-artifacts` and requires `--azure-devops-project` plus `--azure-devops-build-id`. Picket lists artifacts through the Build Artifacts API, downloads each artifact through the returned download URL, follows allowed signed redirects without forwarding credentials, expands archives through the normal archive safety caps, and scans non-archive artifact responses as a single native source.
- Build log enumeration is available behind `--azure-devops-include-logs` with the same project and build ID requirement. Picket lists logs through the Build Logs API and downloads individual log files.
- Classic release build artifact enumeration is available behind `--azure-devops-include-release-artifacts` and requires `--azure-devops-project` plus `--azure-devops-release-id`. Picket reads the release through the Release REST API, follows supported Build artifact references back to their build artifacts, downloads each artifact through the returned download URL, follows allowed signed redirects without forwarding credentials, expands archives through the normal archive safety caps, and skips unsupported release artifact types with warnings.
- Azure Artifacts NuGet package enumeration is available behind `--azure-devops-include-packages`. Picket lists readable feeds when `--azure-devops-feed` is omitted, lists the latest NuGet version of each selected package, downloads package archives through Microsoft's package-content API, removes credentials before following an HTTPS storage redirect, and expands package entries through the normal archive safety caps. `--azure-devops-feed`, `--azure-devops-package`, and `--azure-devops-package-version` narrow the selection; an exact version requires an exact package name.

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes`, `--azure-devops-max-artifact-megabytes`, `--azure-devops-max-log-megabytes`, and `--azure-devops-max-package-megabytes` can tighten the relevant caps with positive values. Zero keeps its local-scan compatibility meaning, but remote Azure DevOps sources reject zero because remote HTTP bodies are always bounded.

Provider metadata JSON responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Azure Artifacts scanning currently supports NuGet packages because Azure DevOps exposes a documented direct content API for that protocol. Universal Packages use Microsoft's separate ArtifactTool transfer workflow and are not treated as ordinary REST package downloads.

Repositories that explicitly report no default branch are skipped unless `--azure-devops-branch` or `--azure-devops-pull-request` is supplied. `--azure-devops-pull-request` cannot be combined with `--azure-devops-branch` or `--azure-devops-include-wikis` because the scan scope must resolve to one repository version model at a time. If branch metadata is not returned and a repository cannot list items, Picket warns and continues so an empty or unauthorized repository does not fail the rest of an organization or project scan. Disabled wikis, wikis without a backing repository, and wikis without a version are skipped with warnings.

Provider options include:

| Option | Purpose |
| --- | --- |
| `--azure-devops-organization` | Organization name or URL for Azure DevOps Services. |
| `--azure-devops-project` | Optional project filter. |
| `--azure-devops-repository` | Optional repository filter. |
| `--azure-devops-endpoint` | Endpoint override for Azure DevOps Server. |
| `--azure-devops-token-env` | Environment variable containing the PAT or job token. |
| `--azure-devops-token-kind` | Credential transport: `pat` for personal access tokens or `bearer` for job and Entra tokens. |
| `--azure-devops-branch` | Optional branch name. |
| `--azure-devops-pull-request` | Pull request number or ID to scan. |
| `--azure-devops-include-wikis` | Include Azure DevOps wiki backing repositories. |
| `--azure-devops-build-id` | Build ID used when scanning build artifacts or build logs. |
| `--azure-devops-include-artifacts` | Include build artifact contents for the selected build. |
| `--azure-devops-include-logs` | Include build logs for the selected build. |
| `--azure-devops-release-id` | Classic release ID used when scanning release build artifacts. |
| `--azure-devops-include-release-artifacts` | Include build artifact contents referenced by the selected classic release. |
| `--azure-devops-include-packages` | Include the latest Azure Artifacts NuGet package versions. |
| `--azure-devops-feed` | Optional feed name or ID filter. |
| `--azure-devops-package` | Optional exact NuGet package name filter. |
| `--azure-devops-package-version` | Optional exact NuGet package version; requires `--azure-devops-package`. |
| `--azure-devops-max-artifact-megabytes` | Positive per-artifact archive download cap. Defaults to `--max-target-megabytes` when that cap is set; otherwise the source client applies its 100 decimal MB default cap. |
| `--azure-devops-max-log-megabytes` | Positive per-log download cap. Defaults to `--max-target-megabytes` when that cap is set; otherwise the source client applies its 100 decimal MB default cap. |
| `--azure-devops-max-package-megabytes` | Positive per-package archive download cap. Requires `--azure-devops-include-packages`. Defaults to `--max-target-megabytes` when that cap is set; otherwise the source client applies its 100 decimal MB default cap. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for self-hosted Azure DevOps Server. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-hosted environments; source credentials may be sent in cleartext. |

Current enumeration handles repository continuation tokens, wiki mapped paths, branch scope controls, build artifact archives, build logs, classic release build artifacts, Azure Artifacts NuGet packages, allowed credential-free redirect downloads, rejection of responses from injected HTTP handlers that already followed a redirect, bounded paging, bounded retry/backoff for throttling responses, and clear warnings for resources the token cannot read. Picket caps paged lists at 1,000 pages and emits a warning if that safety limit is reached. Repository, wiki, build artifact, build log, and release artifact scopes fail independently so one unavailable source does not hide successful scans of other authorized resources.

## Authentication

Workspace scanning does not require Azure DevOps API credentials. Remote enumeration requires an explicit token environment variable name so that API access is visible in pipeline configuration without putting token values on the command line.

Azure DevOps credentials are sent only to HTTPS endpoints by default. Loopback HTTP is allowed for local test fixtures. Public HTTP endpoints require the CLI's explicit `--allow-insecure-source-endpoints` opt-in, which maps to an explicit library option for insecure credential transport and emits a warning because credentials may be sent in cleartext.

Supported credentials:

- Azure Pipelines job token for the current project when the requested API supports it,
- Azure DevOps PAT for cross-project, organization, or Azure DevOps Server enumeration.

Recommended PAT scopes for the dedicated integration-test organization are:

| Scope | Use |
| --- | --- |
| Project and Team: Read | Resolve projects and project-scoped metadata. |
| Code: Read | Enumerate Azure Repos repositories, branches, commits, file contents, and pull-request source metadata. |
| Build: Read | Read build definitions, pipeline runs, logs, and build artifacts. |
| Release: Read | Read classic release definitions, releases, logs, and release artifacts. |
| Wiki: Read | Read Azure DevOps wiki repositories when wiki scanning is enabled. |
| Packaging: Read | Read Azure Artifacts feeds only when package/feed scanning is enabled. |

Do not grant write, execute, manage, service-connection, agent-pool, token-administration, or full-access scopes for normal scanner tests.

## Live Smoke Workflow

The `Live Azure DevOps` GitHub Actions workflow is manual-only. It uses `AZURE_DEVOPS_TEST_PAT` to scan `https://dev.azure.com/willibrandon/picket` by default with native Azure DevOps repository enumeration and writes a fully redacted JSONL report artifact. The workflow accepts endpoint, project, repository, branch, token-kind, file-size cap, and fail-on-findings inputs.

This workflow is for connector smoke testing against the dedicated test organization. It must not become a required pull-request or push gate unless it is converted to recorded responses or local fakes.

Credential handling requirements:

- no telemetry,
- no token values in command lines, logs, summaries, reports, cache keys, diagnostics, or annotations,
- least-privilege documentation for repository, build, release, and wiki scopes,
- endpoint safety checks for Azure DevOps Server URLs,
- redirect checks before sending credentials,
- bounded response bodies and downloads,
- rate limits and retry caps,
- explicit opt-in for live validation.

## Artifacts, Packages, And Logs

Artifact and log scanning must protect the agent and the pipeline:

- enforce compressed and decompressed byte caps,
- enforce archive entry and recursion caps,
- reject path traversal entries,
- avoid extracting outside task-owned temporary directories,
- keep artifact and log response bytes out of warnings and diagnostics,
- omit request URIs, signed redirect queries, response bodies, and provider-controlled archive paths from failure diagnostics,
- apply requested finding redaction before writing reports,
- keep download and extraction timeouts separate from scanner timeouts,
- preserve source provenance so reports can point back to the build, job, artifact, log, repository, branch, and commit when available.

Findings from artifacts and logs use native report fields because Gitleaks-compatible report fields cannot represent all Azure DevOps provenance without losing information.

## Marketplace Package

The Azure DevOps Marketplace extension packages the task metadata, icon, documentation, license, privacy statement, and agent compatibility matrix. The task major version stays stable as `PicketScan@1` while compatible task inputs evolve additively.

The package follows Microsoft's current [extension manifest](https://learn.microsoft.com/azure/devops/extend/develop/manifest) and [custom task layout](https://learn.microsoft.com/azure/devops/extend/develop/add-build-task): `images/extension-icon.png` is the Marketplace icon, and the 32-by-32 `tasks/PicketScanV1/icon.png` is the task icon. `PRIVACY.md`, `COMPATIBILITY.md`, and `CHANGELOG.md` are packaged with the extension. The manifest links to the public documentation, license, privacy policy, source repository, and issue tracker. Task-settable variables are restricted to the six declared outputs.

The extension can either bundle signed Picket CLI binaries or acquire deterministic release artifacts by version and checksum. Both approaches must use the same scanner behavior, report contracts, and security controls as local CLI execution.

## Test And Release Gates

Before publishing the task:

- validate task metadata and VSIX packaging in CI,
- run task smoke tests on Windows, Linux, and macOS agents,
- run self-hosted marketplace smoke tests only through explicit manual queueing,
- cover workspace scans without remote credentials,
- cover remote Azure DevOps API behavior with recorded responses or local fakes by default,
- keep live Azure DevOps tests opt-in through dedicated test credentials,
- verify reports, annotations, summaries, and artifacts never include raw secrets unless an explicit trusted-private redaction setting allows it.
