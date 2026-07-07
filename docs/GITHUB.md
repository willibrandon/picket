# GitHub

Picket's GitHub support has two native layers:

- repository source enumeration for `picket scan`,
- hosted GitHub Secret Protection alert capture for parity analysis.

Neither layer changes strict Gitleaks-compatible commands.

## Repository Source Scanning

GitHub repository enumeration is opt-in native source behavior. Workspace scans remain the default because they are deterministic and use normal checkout permissions.

```powershell
picket scan --github-repository willibrandon/picket --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

| Option | Purpose |
| --- | --- |
| `--github-repository` | Repository to scan as `owner/name` or a GitHub repository URL. |
| `--github-token-env` | Environment variable containing the GitHub token. |
| `--github-ref` | Optional branch, tag, or commit SHA. Empty uses the repository default branch. |
| `--github-source-api-endpoint` | GitHub API endpoint used for repository enumeration. |
| `--github-api-endpoint` | Shared GitHub API endpoint used when a source-specific endpoint is not supplied. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for GitHub Enterprise Server. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-hosted environments. |

Repository file enumeration uses GitHub's repository metadata API to resolve the default branch, the recursive Git Trees API to list blobs, and the raw Contents API to download file bytes. Redirects are disabled before credentials are sent. Endpoint safety checks run before the first request. `--max-target-megabytes` caps downloaded file content; oversized tree entries are skipped before download when GitHub returns a size.

Repository tree truncation and per-file download failures are warnings. Picket keeps scanning the files it can read so one missing object or permission failure does not hide the rest of the repository.

The initial scope is repository file enumeration. Organization/user repository discovery, pull requests, issues, gists, releases, Actions artifacts, packages, and code-search-backed discovery remain planned explicit opt-ins.

Recommended fine-grained token permissions for repository file enumeration are:

| Permission | Access |
| --- | --- |
| Metadata | Read |
| Contents | Read |

Use the narrowest repository selection possible. Write, administration, workflow, security-event write, and secret-scanning alert permissions are not needed for repository file enumeration.

## Hosted Alert Oracle

GitHub Secret Protection secret scanning is proprietary hosted behavior, so Picket treats it as an alert oracle rather than an implementation reference. `scripts/Capture-GitHubSecretScanningOracle.ps1` captures sanitized alert metadata through `gh api`; it does not write raw secret values. `scripts/Compare-GitHubSecretScanningOracle.ps1` compares a native Picket JSONL report to the sanitized alert metadata by mapped alert type and location.

The manual `Live GitHub Secret Scanning Oracle` workflow uses `PICKET_GITHUB_SECRET_SCANNING_PAT` to capture alerts for `willibrandon/picket` by default, optionally compares them to a redacted native git-history scan of the checkout, and uploads sanitized artifacts.

Recommended fine-grained token permissions for hosted alert capture are:

| Permission | Access |
| --- | --- |
| Metadata | Read |
| Secret scanning alerts | Read |

This token is separate from source-enumeration tokens. It should not have write, administration, workflow, or code-scanning upload permissions.

Official API references:

- GitHub repository metadata REST API: `https://docs.github.com/rest/repos/repos`
- Git trees REST API: `https://docs.github.com/v3/git/trees`
- Repository contents REST API: `https://docs.github.com/en/rest/repos/contents`
- Secret scanning alert REST API: `https://docs.github.com/en/rest/secret-scanning/secret-scanning`
