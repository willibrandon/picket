# Upstream Pins

Picket compatibility work is pinned to upstream reference snapshots. Upgrade
these pins deliberately and update oracle fixtures in the same change.

Do not commit machine-specific clone paths. Developers can keep reference
repositories anywhere and point Picket tooling at them with environment
variables. When an environment variable is not set, local scripts try a sibling
clone next to this repository.

## Reference Clone Discovery

| Project | Environment variable | Default sibling clone | Role |
|---|---|---|---|
| Gitleaks | `PICKET_GITLEAKS_REPO` | `../gitleaks` | Primary compatibility oracle |
| Scout | `PICKET_SCOUT_REPO` | `../scout` | Regex, globbing, ignore, and Native AOT behavior reference |
| TruffleHog | `PICKET_TRUFFLEHOG_REPO` | `../trufflehog` | Verification, sources, and analyze reference |
| Nosey Parker | `PICKET_NOSEYPARKER_REPO` | `../noseyparker` | Historical datastore/rule-QA/performance reference |
| Kingfisher | `PICKET_KINGFISHER_REPO` | `../kingfisher` | Validation breadth, revocation, access-map, and reporting reference |
| .NET Runtime | `PICKET_DOTNET_RUNTIME_REPO` | `../runtime` | Native AOT/runtime implementation reference |

## Current Pins

<!-- upstream-pins:start -->
| Project | Version | Commit | Remote |
|---|---:|---|---|
| Gitleaks | `v8.30.0-23-g4c232b5` | `4c232b5014f7618360bd992b4c489cb055881c6b` | `https://github.com/gitleaks/gitleaks.git` |
| Scout | `v0.4.2` | `823716053dcc9a7856ef31ad1b59bed2e1cab3d7` | `https://github.com/willibrandon/scout.git` |
| TruffleHog | `v3.95.8-1-gf2cd191b9` | `f2cd191b97098913a07522227d2b5e40e57252f4` | `https://github.com/trufflesecurity/trufflehog.git` |
| Nosey Parker | `v0.24.0-31-g2e6e7f36` | `2e6e7f36ce36619852532bbe698d8cb7a26d2da7` | `https://github.com/praetorian-inc/noseyparker.git` |
| Kingfisher | `v1.105.0` | `78904df5ea7354a7dc3700e3c41a124524d23083` | `https://github.com/mongodb/kingfisher.git` |
| .NET Runtime | `fe5e47348f8` | `fe5e47348f86013bbe8f3041e56f5208cd632e53` | `https://github.com/dotnet/runtime` |
<!-- upstream-pins:end -->

Refresh the table from local clones with:

```powershell
pwsh ./scripts/Capture-UpstreamPins.ps1 -Update
```

Print the captured table without editing docs with:

```powershell
pwsh ./scripts/Capture-UpstreamPins.ps1
```

## Gitleaks Compatibility

The embedded strict-compatibility default config in
`src/Picket.Compat/EmbeddedGitleaksConfig.cs` is generated from:

```text
<gitleaks clone>/config/gitleaks.toml
```

Resolve `<gitleaks clone>` with `PICKET_GITLEAKS_REPO` or the sibling
`../gitleaks` fallback.

Current Gitleaks code defaults are treated as authoritative when README text and
implementation disagree. For example, `--max-decode-depth` follows the pinned
code default of `5`.

Expected oracle command shapes:

```powershell
gitleaks git <repo> --config <config> --report-format json --report-path <out>
gitleaks dir <path> --config <config> --report-format json --report-path <out>
gitleaks stdin --config <config> --report-format json --report-path <out>
```

Capture pinned Gitleaks oracle outputs with:

```powershell
pwsh ./scripts/Capture-GitleaksOracle.ps1 -Mode dir -Source <fixture-path> -Config <config> -ReportFormat json,sarif
pwsh ./scripts/Capture-GitleaksOracle.ps1 -Mode git -Source <repo> -Config <config> -ReportFormat json
pwsh ./scripts/Capture-GitleaksOracle.ps1 -Mode stdin -StdinPath <input-file> -Config <config> -ReportFormat json
```

For directory fixtures where report paths must stay relative, run from an
explicit fixture working directory and pass the same relative command arguments
that Gitleaks should see:

```powershell
pwsh ./scripts/Capture-GitleaksOracle.ps1 -Mode dir -WorkingDirectory <fixture-root> -Source . -Config .gitleaks.toml -ReportFormat json
```

The script resolves the executable from `-GitleaksPath`, `PICKET_GITLEAKS_BIN`,
or `gitleaks` on `PATH`. It resolves the pinned clone from
`PICKET_GITLEAKS_REPO` or `../gitleaks`, then writes reports, stdout, stderr,
and `metadata.json` under `artifacts/oracles/gitleaks` by default.

Oracle reports can contain raw secrets from fixtures. Keep generated artifacts
out of source control unless a follow-up normalization step has redacted and
reviewed them for use as committed golden files.

Capture a side-by-side Gitleaks/Picket compatibility bundle with:

```powershell
pwsh ./scripts/Capture-CompatibilityOracle.ps1 -Mode dir -Source <fixture-path> -Config <config> -ReportFormat json,sarif
pwsh ./scripts/Capture-CompatibilityOracle.ps1 -Mode dir -WorkingDirectory <fixture-root> -Source . -Config .gitleaks.toml -ReportFormat json
```

The wrapper writes `gitleaks/`, `picket/`, and `comparison.json` under
`artifacts/oracles/compatibility` by default. Set `PICKET_BIN` or pass
`-PicketPath` when the Release `picket` executable has not already been built
in the repository output layout used by the test suite.

Promote a reviewed compatibility bundle into source-controlled golden fixtures
with:

```powershell
pwsh ./scripts/Promote-CompatibilityOracle.ps1 -Name <case-name> -RedactionMapPath <redactions.json>
```

The promotion step writes normalized files under `tests/fixtures/oracles` and a
`manifest.json` with upstream pin metadata, file hashes, and comparison results.
It strips known local paths, normalizes line endings, applies the redaction map,
normalizes volatile Gitleaks stderr timestamps and scan durations, and fails if
promoted files still contain drive-root paths or any redaction-map secret.
`-AllowUnredacted` is only for synthetic no-secret captures.

Picket compatibility tests should compare normalized reports, fingerprints,
config diagnostics, exit codes, and stderr text against this pinned version.

## Provider Revocation References

Native analysis revocation command templates are based on provider
documentation reviewed on 2026-07-06:

- GitHub credential revocation API: `https://docs.github.com/en/rest/credentials/revoke`
- GitHub token expiration and revocation: `https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation`
- AWS IAM `update-access-key`: `https://docs.aws.amazon.com/cli/latest/reference/iam/update-access-key.html`
- AWS IAM `delete-access-key`: `https://docs.aws.amazon.com/cli/latest/reference/iam/delete-access-key.html`
- AWS IAM access-key rotation workflow: `https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html`
- Azure Storage account key renewal: `https://learn.microsoft.com/en-us/cli/azure/storage/account/keys`
- GCP API key delete command: `https://docs.cloud.google.com/sdk/gcloud/reference/services/api-keys/delete`
- GCP service-account key delete command: `https://docs.cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/delete`

## GitHub Secret Scanning Oracle

GitHub Secret Protection secret scanning is a hosted proprietary system, not a
local Gitleaks binary. Use it as an alert oracle for repository parity, not as a
source-code implementation reference. GitHub documents supported secret scanning
patterns and alert scope in its public docs:

- `https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns`
- `https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope`

Capture sanitized GitHub alert metadata with:

```powershell
pwsh ./scripts/Capture-GitHubSecretScanningOracle.ps1 -Repository owner/name -State open -IncludeLocations
```

The script uses `gh api` and writes
`artifacts/oracles/github-secret-scanning/alerts.json` by default. The output
contains alert numbers, states, secret types, URLs, summary counts, and optional
location metadata. It intentionally does not write GitHub's raw `secret` field.

Use this oracle to compare Picket native rule coverage against GitHub alert
classes and locations. Keep Gitleaks compatibility oracles separate because
GitHub and Gitleaks do not have identical allowlist semantics.

When the captured locations include commit SHAs, run a native git-history scan
to JSONL before comparing:

```powershell
picket git . --profile picket --report-format jsonl `
  --report-path artifacts/oracles/github-secret-scanning/picket-git.jsonl
```

For current-tree experiments, a native filesystem `scan` report can still be
useful, but it is not evidence for hosted historical alert parity.

Compare the hosted-alert oracle with:

```powershell
pwsh ./scripts/Compare-GitHubSecretScanningOracle.ps1 `
  -OraclePath artifacts/oracles/github-secret-scanning/alerts.json `
  -PicketReportPath artifacts/oracles/github-secret-scanning/picket-git.jsonl `
  -OutputPath artifacts/oracles/github-secret-scanning/comparison.json
```

The comparison output records mapped alert classes, missing mapped locations,
unexpected mapped findings, hosted alert types without a Picket mapping, and
Picket rule IDs that are not part of the GitHub mapping. It matches by commit
SHA when both sides have commit metadata and otherwise falls back to line-level
path matching. It does not copy raw secret, match, or line fields from the
Picket report.
