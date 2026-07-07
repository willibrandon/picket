# Marketplaces

Picket marketplace packages are distribution wrappers around the same CLI, reports, cache behavior, and security controls used by local execution. They must not fork scanner behavior or introduce CI-specific defaults that change strict compatibility mode.

The planned marketplace surfaces are:

- GitHub Marketplace listing for the repository action,
- Azure DevOps Marketplace extension for `PicketScan@1`.

## Shared Requirements

Marketplace packages use the release provenance of the CLI artifacts:

- semver release tags,
- immutable patch tags,
- mutable major tags that move only after validation,
- SHA-256 checksums,
- artifact attestations where the platform supports them,
- generated input and output references,
- sanitized screenshots and examples,
- MIT license metadata,
- clear privacy statements,
- rollback instructions.

Examples, screenshots, summaries, and generated docs must not contain raw secrets. Redacted sample reports are acceptable when they exercise realistic paths, rule IDs, and counts.

## GitHub Marketplace

The GitHub Action listing is driven by the root `action.yml`, release tags, README content, and marketplace metadata. The action keeps the same input names, output names, summary behavior, annotation behavior, SARIF upload path, cache behavior, fail modes, and redaction rules documented in `docs/ACTION.md`.

Release requirements:

- keep `action.yml` as the source of truth for action inputs and outputs,
- generate the docs reference from `action.yml`,
- publish immutable `vX.Y.Z` tags for every release,
- update the mutable `vX` tag only after CI, docs, action smoke, and release artifact validation pass,
- document least-privilege `permissions` examples,
- include a SARIF/code scanning example,
- keep `security-events: write` required only when SARIF upload is enabled,
- verify the action on pull request and push workflows before updating the marketplace listing.

The listing should describe the scanner in terms of local-first secrets scanning, Native AOT CLI distribution, Gitleaks compatibility, native validation, reports, baselines, cache, and privacy. It should not imply that live network validation runs by default.

## Azure DevOps Marketplace

The Azure DevOps Marketplace extension packages the `PicketScan@1` task and the documentation needed for pipeline authors to use it safely.

Package contents:

- VSIX manifest,
- task metadata,
- task icon,
- README,
- changelog,
- MIT license,
- privacy statement,
- agent compatibility matrix,
- input and output reference generated from task metadata,
- release artifact acquisition or bundled binary metadata.

Release requirements:

- keep task behavior as a thin wrapper around the CLI,
- validate VSIX packaging before publish,
- publish a stable task major line such as `PicketScan@1`,
- evolve compatible task inputs additively,
- use signed or checksummed CLI artifacts,
- document PAT and job-token scope guidance,
- document Azure DevOps Services and Azure DevOps Server support,
- smoke test on Microsoft-hosted Windows, Linux, and macOS agents,
- keep live Azure DevOps API tests opt-in.

## Release Flow

Marketplace publishing happens after the scanner release artifacts are built and verified:

1. Build and test the repository.
2. Run docs generation and stale-doc checks.
3. Publish Native AOT CLI artifacts for supported RIDs.
4. Write per-asset checksums and aggregate checksums.
5. Create artifact attestations where supported.
6. Create or update the GitHub Release.
7. Update the GitHub Action immutable and major tags after release validation.
8. Validate the Azure DevOps VSIX package.
9. Publish the Azure DevOps extension when task packaging is ready.

NuGet publishing remains a separate approval step because package ownership and API compatibility policy need explicit release control.

## Rollback

Rollback must be documented before marketplace publication:

- move the mutable GitHub Action major tag back to the last known-good patch release,
- leave immutable patch tags unchanged,
- remove or deprecate a bad Azure DevOps extension version when the marketplace allows it,
- publish a patched Azure DevOps task version when removal is not possible,
- update release notes with the affected versions and replacement version,
- keep scanner report schemas and baseline formats backward compatible unless the release is explicitly marked breaking.

Rollback instructions must be tested with a dry run before the first marketplace release.

## Required Secrets

Repository and environment secrets should be narrowly scoped:

| Secret | Purpose |
| --- | --- |
| `NUGET_API_KEY` | Publish approved NuGet packages and tools. |
| `AZURE_DEVOPS_MARKETPLACE_PAT` | Publish the Azure DevOps Marketplace VSIX package. |
| `PICKET_GITHUB_SECRET_SCANNING_PAT` | Optional hosted-alert oracle capture for the Picket repository. GitHub Actions secret names cannot start with `GITHUB_`. |
| `AZURE_DEVOPS_TEST_PAT` | Optional live Azure DevOps integration tests against a dedicated test organization. |

`AZURE_DEVOPS_TEST_PAT` is consumed by the manual `Live Azure DevOps` workflow, not by default push or pull-request CI.

GitHub Releases, GitHub Pages, artifact attestations, and normal action publishing should use built-in GitHub workflow credentials wherever possible.

## Gates

Marketplace-related CI gates should cover:

- stale generated docs,
- action smoke tests,
- VSIX package validation,
- metadata validation,
- generated reference consistency,
- no local checkout paths in docs or package metadata,
- no raw secrets in examples, screenshots, summaries, reports, annotations, or fixtures,
- checksum and attestation presence for published CLI artifacts.
