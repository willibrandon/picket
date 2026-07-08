# GitLab

Picket can scan GitLab project repository files, group project repositories, merge request source heads, and project snippets through native source enumeration for `picket scan`.

This is opt-in native source behavior. Workspace scans remain the default because they are deterministic and use normal checkout permissions. Strict Gitleaks-compatible commands are unchanged.

```powershell
picket scan --gitlab-project willibrandon/picket --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

Project repository scans resolve the default branch when `--gitlab-ref` is omitted, list repository blobs through the GitLab repository tree API, and download raw file bytes through the repository files API:

```powershell
picket scan --gitlab-project willibrandon/picket --gitlab-ref main --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

Group scans list projects in a GitLab group and scan each project repository:

```powershell
picket scan --gitlab-group team/platform --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

Subgroup projects are explicit:

```powershell
picket scan --gitlab-group team/platform --gitlab-include-subgroups --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

Merge request scans resolve the merge request source project and source head before listing repository files:

```powershell
picket scan --gitlab-project willibrandon/picket --gitlab-merge-request 42 --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

`--gitlab-ref` and `--gitlab-merge-request` are mutually exclusive.

Project snippet scans list snippets and download raw snippet content through the GitLab project snippets API:

```powershell
picket scan --gitlab-project willibrandon/picket --gitlab-include-snippets --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

Snippet scanning is additive to repository file scanning. It cannot be combined with `--gitlab-merge-request`.

The project selector accepts a namespace path, numeric project ID, or project URL:

```powershell
picket scan --gitlab-project https://gitlab.com/willibrandon/picket --gitlab-token-env PICKET_GITLAB_SOURCE_TOKEN --report-format jsonl
```

The token is read from an environment variable and is never passed as a command-line value.

| Option | Purpose |
| --- | --- |
| `--gitlab-project` | Project to scan as a namespace path, numeric project ID, or project URL. |
| `--gitlab-group` | Group to scan as a namespace path, numeric group ID, or group URL. |
| `--gitlab-ref` | Optional branch, tag, or commit SHA. Empty uses the project default branch. |
| `--gitlab-merge-request` | Optional merge request internal ID. Scans the merge request source head. |
| `--gitlab-include-subgroups` | Include subgroup projects when scanning a group. |
| `--gitlab-include-snippets` | Include project snippets. |
| `--gitlab-token-env` | Environment variable containing the GitLab token. |
| `--gitlab-api-endpoint` | GitLab API endpoint used for repository enumeration. Defaults to `https://gitlab.com/api/v4/`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for self-managed GitLab. |
| `--allow-insecure-source-endpoints` | Permit HTTP source endpoints for trusted local tests or explicitly accepted self-managed environments. |

## API Flow

| Source | API behavior |
| --- | --- |
| Group projects | Lists group projects with `per_page=100`. `include_subgroups=true` is sent only when `--gitlab-include-subgroups` is set. |
| Project metadata | Resolves the default branch when `--gitlab-ref` is omitted. |
| Merge request metadata | Resolves `source_project_id` and the source ref. Picket prefers `diff_refs.head_sha`, then `sha`, then `source_branch`. |
| Repository tree | Lists blobs recursively with `per_page=100` and page-based pagination. |
| Raw file content | Downloads selected file bytes through the raw repository file endpoint. |
| Project snippets | Lists project snippets with `per_page=100` and downloads raw snippet content through the project snippets API. |

## Pagination And Limits

Repository tree enumeration follows GitLab pagination while `X-Next-Page` or a `rel="next"` link is present. Picket caps REST pagination at 1,000 pages per paged list and emits a warning if that safety limit is reached.

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote GitLab sources reject zero because remote HTTP bodies are always bounded.

Provider metadata JSON responses are separately capped at 10 decimal MB and skipped with a warning when the cap is exceeded, including responses without a reliable `Content-Length`.

Oversized tree entries are skipped before download when GitLab returns a size.

## Redirect And Credential Safety

Endpoint safety checks run before the first request.

Redirects are disabled before credentials are sent, and responses from injected HTTP handlers that already followed a redirect are rejected instead of scanned.

Picket sends the configured token as a `PRIVATE-TOKEN` header. It does not send the token as a query string or print it in diagnostics.

## Permissions

Use the narrowest project or group selection possible. Repository file scanning needs read-only access to project metadata, repository tree entries, and raw repository file content for the selected project. Group scanning also needs read access to the group project listing and to each selected project repository. Merge request scanning needs read access to merge request metadata and the source project when the merge request originates from a fork. Snippet scanning needs read access to project snippets and raw snippet content. Write, maintainer, owner, registry-write, runner, and token-administration scopes are not needed for source enumeration.

Jobs, pipelines, packages, and artifacts remain separate planned source selectors. They should stay explicit opt-ins because they have different pagination, credential, redirect, retention, and redaction behavior.

## References

- GitLab repositories API: `https://docs.gitlab.com/api/repositories/`
- GitLab groups API: `https://docs.gitlab.com/api/groups/`
- GitLab merge requests API: `https://docs.gitlab.com/api/merge_requests/`
- GitLab project snippets API: `https://docs.gitlab.com/api/project_snippets/`
- GitLab repository files API: `https://docs.gitlab.com/api/repository_files/`
- GitLab REST pagination: `https://docs.gitlab.com/api/rest/#pagination`
