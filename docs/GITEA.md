# Gitea

Picket can scan Gitea repository files through native source enumeration for `picket scan`.

This is opt-in native source behavior. Workspace scans remain the default because they are deterministic and use normal checkout permissions. Strict Gitleaks-compatible commands are unchanged.

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Repository scans resolve the default branch when `--gitea-ref` is omitted, list repository blobs through the Gitea git trees API, and download raw file bytes through the repository raw file API:

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-ref main --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Organization and user scans list repositories first, then scan each returned repository at `--gitea-ref` or its returned default branch:

```powershell
picket scan --gitea-organization willibrandon --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
picket scan --gitea-user willibrandon --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Pull request scans resolve the source commit through the Gitea pull request API, switch to the returned source repository when the pull request comes from a fork, and then scan that source commit:

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-pull-request 7 --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Issue scans read issue bodies and comments. Pull-request issues returned by Gitea are skipped because pull request source is scanned through `--gitea-pull-request`.

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-include-issues --gitea-issue-state all --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Release scans read release notes and release assets. Asset download URLs returned by Gitea are fetched without forwarding the token.

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-include-releases --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Actions artifact scans list repository artifact metadata, download artifact ZIP archives, and expand entries through Picket's archive limits. Redirected ZIP downloads are fetched without forwarding the token.

```powershell
picket scan --gitea-repository willibrandon/picket --gitea-include-actions-artifacts --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
picket scan --gitea-repository willibrandon/picket --gitea-include-actions-artifacts --gitea-actions-run-id 42 --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Generic package scans can enumerate every generic package file owned by a Gitea user or organization. Picket lists generic packages with `type=generic`, lists files for each package version, downloads each selected file, and expands archive package files through Picket's archive limits.

```powershell
picket scan --gitea-generic-package-owner willibrandon --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Use all four generic package coordinates when only one file should be scanned:

```powershell
picket scan --gitea-generic-package-owner willibrandon --gitea-generic-package-name picket-cli --gitea-generic-package-version 1.0.0 --gitea-generic-package-file picket.zip --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

Self-hosted Gitea instances use an explicit API endpoint:

```powershell
picket scan --gitea-api-endpoint https://gitea.example.com/api/v1/ --gitea-repository team/platform --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

The repository selector accepts an `owner/name` path or repository URL:

```powershell
picket scan --gitea-repository https://gitea.com/willibrandon/picket --gitea-token-env PICKET_GITEA_SOURCE_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

| Option | Purpose |
| --- | --- |
| `--gitea-repository` | Repository to scan as an owner/name path or repository URL. |
| `--gitea-organization` | Organization whose repositories should be listed and scanned. |
| `--gitea-user` | User whose owned repositories should be listed and scanned. |
| `--gitea-ref` | Optional branch, tag, or commit SHA. Empty uses the repository default branch. |
| `--gitea-pull-request` | Optional pull request ID. Resolves and scans the source head. Cannot be combined with `--gitea-ref`. |
| `--gitea-include-issues` | Include Gitea issue bodies and comments. Cannot be combined with `--gitea-pull-request`. |
| `--gitea-issue-state` | Issue state filter: `open`, `closed`, or `all`. Supplying this option enables issue enumeration. |
| `--gitea-include-releases` | Include Gitea release notes and release assets. Cannot be combined with `--gitea-pull-request`. |
| `--gitea-include-actions-artifacts` | Include Gitea Actions artifact ZIP contents. Cannot be combined with `--gitea-pull-request`. |
| `--gitea-actions-run-id` | Limit Actions artifact enumeration to one run. Requires `--gitea-include-actions-artifacts`. |
| `--gitea-generic-package-owner` | Owner whose Gitea generic package files should be scanned. |
| `--gitea-generic-package-name` | Generic package name for exact-file scans. |
| `--gitea-generic-package-version` | Generic package version for exact-file scans. |
| `--gitea-generic-package-file` | Generic package file name for exact-file scans. |
| `--gitea-token-env` | Environment variable containing the Gitea token. |
| `--gitea-api-endpoint` | Gitea API endpoint used for repository enumeration. Defaults to `https://gitea.com/api/v1/`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for self-managed Gitea. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-managed environments; source credentials may be sent in cleartext. |

## API Flow

| Source | API behavior |
| --- | --- |
| Organization repositories | Lists organization repositories with `page` and `limit=100`, then scans each returned `full_name` or `owner/name` repository. |
| User repositories | Lists user-owned repositories with `page` and `limit=100`, then scans each returned `full_name` or `owner/name` repository. |
| Repository metadata | Resolves the default branch when `--gitea-ref` is omitted. |
| Branch metadata | Resolves branch names to commit IDs before git tree enumeration when Gitea returns branch metadata. |
| Pull request metadata | Resolves the source commit hash, source branch fallback, and source repository when `--gitea-pull-request` is used. |
| Issues | Lists repository issues with `page`, `limit=100`, `type=issues`, and the selected state; skips entries that contain a `pull_request` marker. |
| Issue comments | Lists repository issue comments with `page` and `limit=100`, then keeps comments whose `issue_url` belongs to a selected non-pull-request issue. |
| Releases | Lists releases with `page` and `limit=100`, scans release body text as synthetic Markdown, and scans embedded release assets. |
| Release assets | Downloads `browser_download_url` values without forwarding the Gitea token. Asset URLs must stay on the configured Gitea host or one of its subdomains, and HTTPS endpoints cannot redirect assets to HTTP. |
| Actions artifacts | Lists repository artifacts through `/repos/{owner}/{repo}/actions/artifacts` or run-scoped artifacts through `/repos/{owner}/{repo}/actions/runs/{run}/artifacts` with `page` and `limit=100`. |
| Actions artifact ZIPs | Downloads `/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip` as `application/octet-stream`, follows one allowed redirect without forwarding the token, and expands ZIP entries through archive limits. |
| Generic packages | Lists owner packages through `/packages/{owner}` with `type=generic`, `page`, and `limit=100`. |
| Generic package files | Lists files through `/packages/{owner}/generic/{package_name}/{package_version}/files`. |
| Generic package file content | Downloads `/api/packages/{owner}/generic/{package_name}/{package_version}/{file_name}` as `application/octet-stream`. |
| Repository tree | Lists repository blobs with recursive git tree enumeration and `per_page=1000`. |
| Raw file content | Downloads selected file bytes through the raw repository file endpoint with `ref` set to the selected branch, tag, or commit. |

## Pagination And Limits

Repository tree enumeration follows Gitea's `truncated` response field while more entries are available. Picket caps REST pagination at 1,000 pages per paged list and emits a warning if that safety limit is reached.

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote Gitea sources reject zero because remote HTTP bodies are always bounded.

Provider metadata JSON responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Oversized tree entries, Actions artifacts, and package files are skipped before download when Gitea returns a size.

Actions artifact ZIPs and generic package archives use `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, and `--max-archive-ratio`. Archive entries also obey `--max-target-megabytes`.

## Redirect And Credential Safety

Endpoint safety checks run before the first request.

Redirects are disabled before credentials are sent, and responses from injected HTTP handlers that already followed a redirect are rejected instead of scanned.

Picket sends the configured token as an `Authorization: token ...` header. It does not send the token as a query string or print it in diagnostics.

## Permissions

Use the narrowest repository or package selection possible. Repository file scanning needs read-only access to repository metadata, branch metadata, repository tree entries, and raw repository file content for the selected repository. Organization and user scans also need read-only access to repository lists for the selected account. Pull request scans also need read-only access to pull request metadata. Issue scans need read-only issue and issue-comment access. Release scans need read-only release metadata and access to the selected release asset download URLs. Actions artifact scans need read-only access to Actions artifact metadata and artifact ZIP downloads. Generic package scans need read-only package metadata, package file metadata, and package file download access. Write, owner, organization administration, package publish/delete, runner, and token-administration scopes are not needed for source enumeration.

## References

- Gitea API documentation: `https://docs.gitea.com/api/`
- Gitea generic package registry: `https://docs.gitea.com/usage/packages/generic`
- Gitea live swagger: `https://gitea.com/swagger.v1.json`
