# GitHub

Picket's GitHub support has two native layers:

- repository source enumeration for `picket scan`,
- hosted GitHub Secret Protection alert capture for parity analysis.

Neither layer changes strict Gitleaks-compatible commands.

## Repository And Gist Source Scanning

GitHub repository and gist enumeration is opt-in native source behavior. Workspace scans remain the default because they are deterministic and use normal checkout permissions.

```powershell
picket scan --github-repository willibrandon/picket --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

Pull request scans resolve the head repository and commit before enumerating files:

```powershell
picket scan --github-repository willibrandon/picket --github-pull-request 42 --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

Issue scans read issue bodies and issue comments. Pull requests returned by GitHub's Issues API are skipped because pull request source is scanned through `--github-pull-request`.

```powershell
picket scan --github-repository willibrandon/picket --github-include-issues --github-issue-state all --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

Organization scans enumerate repositories visible to the token and then scan each selected repository:

```powershell
picket scan --github-organization willibrandon --github-repository-type sources --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

Gist scans can target one gist, the authenticated user's gists, or a user's public gists. Gist files and gist comments are scanned.

```powershell
picket scan --github-gist 0123456789abcdef --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
picket scan --github-gists --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
picket scan --github-user-gists octocat --github-token-env PICKET_GITHUB_SOURCE_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

| Option | Purpose |
| --- | --- |
| `--github-repository` | Repository to scan as `owner/name` or a GitHub repository URL. |
| `--github-organization` | Organization login whose visible repositories should be scanned. |
| `--github-repository-type` | Organization repository filter: `all`, `public`, `private`, `forks`, `sources`, or `member`. Empty uses `all`. |
| `--github-gist` | Single gist identifier to scan. |
| `--github-gists` | Include the authenticated user's gists. |
| `--github-user-gists` | Include public gists for the specified GitHub user login. |
| `--github-token-env` | Environment variable containing the GitHub token. |
| `--github-ref` | Optional branch, tag, or commit SHA. Empty uses each repository's default branch. |
| `--github-pull-request` | Pull request number whose head repository and SHA should be scanned. Requires `--github-repository` and cannot be combined with `--github-ref`. |
| `--github-include-issues` | Include GitHub issue bodies and issue comments. Cannot be combined with `--github-pull-request`. |
| `--github-issue-state` | Issue state filter: `open`, `closed`, or `all`. Supplying this option enables issue enumeration. |
| `--github-source-api-endpoint` | GitHub API endpoint used for repository enumeration. |
| `--github-api-endpoint` | Shared GitHub API endpoint used when a source-specific endpoint is not supplied. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for GitHub Enterprise Server. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-hosted environments. |

Single-repository file enumeration uses GitHub's repository metadata API to resolve the default branch. Pull request enumeration uses the pull request REST API to resolve `head.sha` and `head.repo.full_name`, then scans that commit in the returned head repository, including fork repositories when GitHub returns them. Issue enumeration uses the repository Issues API with `per_page=100`, skips entries that contain a `pull_request` marker, and reads issue comments through the issue comments API. Organization enumeration uses the list organization repositories REST API with `per_page=100` and follows GitHub's `Link` pagination header while a `rel="next"` page is present. Gist enumeration uses the authenticated-user, user-public, and single-gist REST APIs. Picket fetches each selected gist detail before scanning files, warns when GitHub reports a truncated file list, scans inline gist file content when available, falls back to `raw_url` for truncated files without sending the bearer token to the raw host, and scans gist comments through the gist comments API. For every selected repository, Picket lists blobs through the recursive Git Trees API and downloads bytes through the raw Contents API. Redirects are disabled before credentials are sent. Endpoint safety checks run before the first request. `--max-target-megabytes` caps downloaded file content; oversized tree entries are skipped before download when GitHub returns a size, and oversized issue/comment/gist synthetic files are skipped before scanning.

Repository tree truncation and per-file download failures are warnings. Organization scans also treat per-repository tree failures as warnings and continue with the remaining repositories. A single-repository scan still fails when the selected repository tree cannot be read.

The current scope is single-repository file enumeration, repository pull request head enumeration, repository and organization issue body/comment enumeration, organization repository discovery, single gist scans, authenticated-user gist scans, and public user gist scans. User repository discovery, releases, Actions artifacts, packages, and code-search-backed discovery remain planned explicit opt-ins.

Recommended fine-grained token permissions for repository file enumeration are:

| Permission | Access |
| --- | --- |
| Metadata | Read |
| Contents | Read |
| Pull requests | Read, only when `--github-pull-request` is used |
| Issues | Read, only when `--github-include-issues` or `--github-issue-state` is used |
| Gists | Fine-grained tokens do not require repository permissions for read-only gist APIs; classic OAuth tokens use the `gist` scope for private user gists |

Use the narrowest repository selection possible. Organization scans require access to list the organization repositories selected by `--github-repository-type`; the same token also needs Contents Read on repositories whose files should be scanned. Pull request scans need Pull Requests Read on the base repository and Contents Read on the head repository. Issue scans need Issues Read on repositories whose issue bodies and comments should be scanned. Gist scans need only the read access required by GitHub's gist APIs for the selected gist scope. Write, administration, workflow, security-event write, and secret-scanning alert permissions are not needed for repository or gist source enumeration.

## Hosted Alert Oracle

GitHub Secret Protection secret scanning is proprietary hosted behavior, so Picket treats it as an alert oracle rather than an implementation reference. `scripts/Capture-GitHubSecretScanningOracle.cs` captures sanitized alert metadata through `gh api`; it does not write raw secret values. `scripts/Compare-GitHubSecretScanningOracle.cs` compares a native Picket JSONL report to the sanitized alert metadata by mapped alert type and location.

The manual `Live GitHub Secret Scanning Oracle` workflow uses `PICKET_GITHUB_SECRET_SCANNING_PAT` to capture alerts for `willibrandon/picket` by default, optionally compares them to a redacted native git-history scan of the checkout, and uploads sanitized artifacts.

Recommended fine-grained token permissions for hosted alert capture are:

| Permission | Access |
| --- | --- |
| Metadata | Read |
| Secret scanning alerts | Read |

This token is separate from source-enumeration tokens. It should not have write, administration, workflow, or code-scanning upload permissions.

Official API references:

- GitHub repository metadata REST API: `https://docs.github.com/rest/repos/repos`
- GitHub pull requests REST API: `https://docs.github.com/rest/pulls/pulls`
- GitHub issues REST API: `https://docs.github.com/rest/issues/issues`
- GitHub issue comments REST API: `https://docs.github.com/rest/issues/comments`
- GitHub gists REST API: `https://docs.github.com/rest/gists/gists`
- GitHub gist comments REST API: `https://docs.github.com/rest/gists/comments`
- GitHub REST pagination: `https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api`
- Git trees REST API: `https://docs.github.com/v3/git/trees`
- Repository contents REST API: `https://docs.github.com/en/rest/repos/contents`
- Secret scanning alert REST API: `https://docs.github.com/en/rest/secret-scanning/secret-scanning`
