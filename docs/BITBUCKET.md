# Bitbucket

Picket can scan Bitbucket Cloud repository files through native source enumeration for `picket scan`.

## Repository Scans

```bash
picket scan --bitbucket-repository willibrandon/picket --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Repository scans resolve the main branch when `--bitbucket-ref` is omitted, list repository directories through the Bitbucket source API, and download raw file bytes through the same source endpoint:

```bash
picket scan --bitbucket-repository willibrandon/picket --bitbucket-ref main --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Workspace scans list repositories in a workspace and scan each visible repository. When `--bitbucket-ref` is provided, the same branch, tag, or commit is used for each repository; otherwise Picket resolves each repository's main branch:

```bash
picket scan --bitbucket-workspace willibrandon --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Workspace snippet scans are explicit opt-ins and run alongside workspace repository scanning:

```bash
picket scan --bitbucket-workspace willibrandon --bitbucket-include-snippets --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Repository download artifacts are explicit opt-ins:

```bash
picket scan --bitbucket-repository willibrandon/picket --bitbucket-include-downloads --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Download artifact scans list the repository downloads, request each artifact by filename, accept Bitbucket's documented redirect response, and fetch the redirected artifact URL without forwarding the Bitbucket credential. Archive artifacts are expanded with the native archive limits.

Workspace snippet scans list snippets in the selected workspace, fetch snippet metadata to discover file names, and download raw snippet files through the snippet file API. Snippet raw-file redirects are followed only when they stay on the configured Bitbucket API endpoint, because those redirected API requests still require the Bitbucket credential.

Pull request scans resolve the source commit through the Bitbucket pull requests API, switch to the returned source repository when the pull request comes from a fork, and then scan that source commit:

```bash
picket scan --bitbucket-repository willibrandon/picket --bitbucket-pull-request 7 --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Repository URLs are accepted:

```bash
picket scan --bitbucket-repository https://bitbucket.org/willibrandon/picket --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

Self-hosted tests or explicitly accepted gateway deployments can use an explicit API endpoint:

```bash
picket scan --bitbucket-api-endpoint https://api.bitbucket.org/2.0/ --bitbucket-repository team/platform --bitbucket-token-env PICKET_BITBUCKET_SOURCE_TOKEN --report-format jsonl
```

## Options

| Option | Behavior |
| --- | --- |
| `--bitbucket-repository` | Repository to scan as a workspace/repository path or repository URL. |
| `--bitbucket-workspace` | Workspace whose visible repositories should be scanned. Cannot be combined with `--bitbucket-repository` or `--bitbucket-pull-request`. |
| `--bitbucket-ref` | Optional branch, tag, or commit SHA. Empty uses the repository main branch. |
| `--bitbucket-pull-request` | Optional pull request ID. Resolves and scans the source commit. Cannot be combined with `--bitbucket-ref`. |
| `--bitbucket-include-downloads` | Also scan repository download artifacts. With `--bitbucket-workspace`, applies to each enumerated repository. Cannot be combined with `--bitbucket-pull-request`. |
| `--bitbucket-include-snippets` | Also scan workspace snippet files. Requires `--bitbucket-workspace`. |
| `--bitbucket-token-env` | Environment variable containing the Bitbucket token or app password. |
| `--bitbucket-token-kind` | Credential mode. `bearer` is the default. `app-password` uses HTTP Basic authentication. |
| `--bitbucket-username-env` | Environment variable containing the Bitbucket username for `app-password` mode. |
| `--bitbucket-api-endpoint` | Bitbucket Cloud API endpoint used for repository enumeration. Defaults to `https://api.bitbucket.org/2.0/`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for trusted tests. |
| `--allow-insecure-source-endpoints` | Permit HTTP endpoints for trusted local tests or explicitly accepted deployments. |

## API Flow

| Source | API behavior |
| --- | --- |
| Workspace repositories | Lists repositories in a workspace with `pagelen=100`, follows Bitbucket pagination, and scans each returned repository path. |
| Workspace snippets | Lists snippets in a workspace with `pagelen=100`, fetches snippet metadata for file names, and downloads raw snippet files through the snippet file API. |
| Repository metadata | Resolves the main branch when `--bitbucket-ref` is omitted. |
| Pull request metadata | Resolves the source commit hash and source repository when `--bitbucket-pull-request` is used. |
| Directory listings | Lists repository directory contents page by page with `pagelen=100`. Picket walks returned `commit_directory` entries instead of relying on `max_depth`. |
| Raw repository files | Downloads raw bytes for returned `commit_file` entries. |
| Download artifacts | Lists repository downloads with `pagelen=100`, requests each artifact by filename, follows Bitbucket's artifact redirect without credentials, and scans the downloaded bytes. |

## Limits

Workspace repository and directory listing pagination follows Bitbucket's `next` response field while more entries are available. Picket caps each paged list at 1,000 pages and emits a warning if that safety limit is reached.

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote Bitbucket sources reject zero because remote HTTP bodies are always bounded.

Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.

Oversized directory entries are skipped before download when Bitbucket returns a size.

Oversized download artifacts are skipped before download when Bitbucket returns a size. Download artifact archives respect `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, `--max-archive-ratio`, and `--max-target-megabytes`.

Snippet file downloads use the same remote byte cap as repository files. Raw snippet redirects are followed only when the redirected URI stays on the configured API endpoint.

## Credentials

Credentials are read from environment variables. Bearer mode sends `Authorization: Bearer ...`. App-password mode sends HTTP Basic authentication using the username from `--bitbucket-username-env` and the app password from `--bitbucket-token-env`.

Least-privilege repository and workspace enumeration requires read-only repository access for repository listings, repository metadata, source directory listings, raw source file content, and download artifacts. Pull request scans also require read-only pull request access. Snippet scans require read-only snippet access. For OAuth-style tokens, Bitbucket documents the `repository` scope for source and download enumeration, the `pullrequest` scope for pull request metadata, and the `snippet` scope for snippet enumeration. For API tokens, Bitbucket documents `read:repository:bitbucket`, `read:pullrequest:bitbucket`, and `read:snippet:bitbucket`.

## Current Scope

The current scope is repository file enumeration, workspace repository enumeration, workspace snippet enumeration, pull request source-head enumeration, and repository download artifacts. Pipelines, projects, and Bitbucket Data Center/Server remain separate planned source selectors. They should stay explicit opt-ins because they have different pagination, credential, redirect, retention, and redaction behavior.

## References

- Bitbucket Cloud REST API: `https://developer.atlassian.com/cloud/bitbucket/rest/`
- Bitbucket source API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-source/`
- Bitbucket repository API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/`
- Bitbucket pull requests API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pullrequests/`
- Bitbucket downloads API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-downloads/`
- Bitbucket snippets API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-snippets/`
