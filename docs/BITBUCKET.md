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
| `--bitbucket-ref` | Optional branch, tag, or commit SHA. Empty uses the repository main branch. |
| `--bitbucket-pull-request` | Optional pull request ID. Resolves and scans the source commit. Cannot be combined with `--bitbucket-ref`. |
| `--bitbucket-token-env` | Environment variable containing the Bitbucket token or app password. |
| `--bitbucket-token-kind` | Credential mode. `bearer` is the default. `app-password` uses HTTP Basic authentication. |
| `--bitbucket-username-env` | Environment variable containing the Bitbucket username for `app-password` mode. |
| `--bitbucket-api-endpoint` | Bitbucket Cloud API endpoint used for repository enumeration. Defaults to `https://api.bitbucket.org/2.0/`. |
| `--allow-non-public-source-endpoints` | Permit private, loopback, link-local, or otherwise non-public endpoint addresses for trusted tests. |
| `--allow-insecure-source-endpoints` | Permit HTTP endpoints for trusted local tests or explicitly accepted deployments. |

## API Flow

| Source | API behavior |
| --- | --- |
| Repository metadata | Resolves the main branch when `--bitbucket-ref` is omitted. |
| Pull request metadata | Resolves the source commit hash and source repository when `--bitbucket-pull-request` is used. |
| Directory listings | Lists repository directory contents page by page with `pagelen=100`. Picket walks returned `commit_directory` entries instead of relying on `max_depth`. |
| Raw repository files | Downloads raw bytes for returned `commit_file` entries. |

## Limits

Directory listing pagination follows Bitbucket's `next` response field while more entries are available. Picket caps each paged list at 1,000 pages and emits a warning if that safety limit is reached.

Remote downloads use a 100 decimal MB default cap. `--max-target-megabytes` overrides that cap with a positive value. Zero keeps its local-scan compatibility meaning, but remote Bitbucket sources reject zero because remote HTTP bodies are always bounded.

Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.

Oversized directory entries are skipped before download when Bitbucket returns a size.

## Credentials

Credentials are read from environment variables. Bearer mode sends `Authorization: Bearer ...`. App-password mode sends HTTP Basic authentication using the username from `--bitbucket-username-env` and the app password from `--bitbucket-token-env`.

Least-privilege repository enumeration requires read-only repository access for repository metadata, source directory listings, and raw source file content. Pull request scans also require read-only pull request access. For OAuth-style tokens, Bitbucket documents the `repository` scope for source enumeration and the `pullrequest` scope for pull request metadata. For API tokens, Bitbucket documents `read:repository:bitbucket` and `read:pullrequest:bitbucket`.

## Current Scope

The current scope is repository file enumeration and pull request source-head enumeration. Downloads, pipelines, artifacts, snippets, workspaces, projects, and Bitbucket Data Center/Server remain separate planned source selectors. They should stay explicit opt-ins because they have different pagination, credential, redirect, retention, and redaction behavior.

## References

- Bitbucket Cloud REST API: `https://developer.atlassian.com/cloud/bitbucket/rest/`
- Bitbucket source API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-source/`
- Bitbucket repository API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/`
- Bitbucket pull requests API: `https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pullrequests/`
