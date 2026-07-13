# Validation and Privacy

Picket separates offline structural validation from live provider verification.

## Defaults

- No telemetry is collected.
- Live network verification is disabled by default.
- Plain `picket scan` and compatibility commands do not contact provider APIs.
- `picket verify --offline` and native scan validation use local checks only.
- `picket scan --verify`, `picket verify --live`, and `picket analyze --live` are explicit opt-in provider calls. The initial live provider is GitHub token validation.
- `picket revoke` commands are separate, explicit, irreversible provider mutations and never run as part of scanning, verification, or analysis.

## Offline Validation

Offline validation never sends secrets, hashes, paths, or metadata to a network endpoint. Current validators inspect local finding data and return one of these report values:

- `unknown`: no validator could prove a stronger state.
- `structurally-valid`: the secret has a valid local shape for the detected rule.
- `test-credential`: the secret appears to be a dummy, example, placeholder, repeated-character, or repeated-pattern credential.
- `invalid`: the secret fails a local structural check.
- `active`, `inactive`, `skipped`, and `error`: reserved for opt-in live verification results.

Use `--results` with native `scan`, `verify`, and `analyze` commands to keep specific validation states. `--only-verified` is shorthand for keeping `structurally-valid` offline findings and `active` live-verification findings; it does not keep `inactive`, `skipped`, `error`, `invalid`, `test-credential`, or `unknown` findings.

Current offline coverage includes:

- AWS access key ID shape and alphabet checks.
- Native AWS access key pair checks that require a valid access key ID and a 40-character secret access key alphabet.
- Azure Storage connection-string structure, account name, endpoint suffix, and 512-bit Base64 account-key checks.
- Database connection URL structure, known database schemes, username, and embedded password checks.
- GCP API key prefix, length, and alphabet checks.
- GCP service account key JSON structure, project ID, private key ID, private-key envelope, service account email, and token URI checks.
- GitHub classic, OAuth, refresh, app, and fine-grained token shape checks.
- JWT and Base64-wrapped JWT segment, header, payload, algorithm, and signature-shape checks.
- private-key envelope checks.
- Sourcegraph `sgp_` access token shape checks.
- common test, dummy, fake, placeholder, repeated-character, and repeated-pattern suppression signals.

Native rule metadata can list supported validation templates with stable identifiers such as `offline:gcp-api-key` or `live:github-rest-user-v1`. These identifiers document available capability and appear in rich native rule catalogs; they do not enable live provider calls unless the user selects an explicit live-verification command or flag.

## Live Verification Model

Live provider calls are opt-in behavior for `picket scan --verify`, `picket verify --live`, and `picket analyze --live`. The reusable verification layer defines the provider contract and safety envelope that provider validators must use:

- `ISecretLiveValidator` describes one provider validator, its endpoint, provider ID, version, and support check.
- `SecretLiveVerifier` chooses the first supporting validator, evaluates the endpoint guard before the validator runs, honors cancellation, and returns `skipped` when no validator supports a finding.
- `SecretLiveVerifierOptions` limits live provider concurrency to four total provider requests and one request per provider by default, spaces requests to the same provider by one second by default, and can also enforce a global request interval.
- `SecretValidationCache` stores live results with rule/provider/config fingerprint invalidation, expiration, authenticated entries, owner-only file permissions on Unix-like systems and Windows, and atomic writes.
- `SecretValidationCacheKey` is built from provider, validator version, rule ID, endpoint, and a SHA-256 secret hash. It rejects raw secret material where a hash is required.
- Cache files store fingerprints, report states, expiration, non-secret reasons, and non-secret analysis metadata such as provider identity, scopes, resources, and evidence. They do not store raw secrets, raw matches, or endpoint query strings.
- Transient provider failures can be request-cached for the current verifier run but are not written to the persistent cache.
- Live results include non-secret audit evidence for the provider, normalized endpoint without query or fragment data, endpoint policy decision, whether the provider was contacted for the current verification call, and whether the result came from the request or persistent cache.
- Findings already marked `invalid` or `test-credential` by offline validation are not sent to live providers.

The first provider validator is GitHub:

- supported compatibility rule IDs: `github-pat`, `github-oauth`, `github-refresh-token`, `github-app-token`, and `github-fine-grained-pat`,
- supported native rule IDs: `picket-github-personal-access-token`, `picket-github-oauth-token`, `picket-github-refresh-token`, `picket-github-app-token`, and `picket-github-fine-grained-personal-access-token`,
- default endpoint: `https://api.github.com/user`,
- endpoint override: `--github-api-endpoint <absolute-uri>`, intended for GitHub Enterprise and recorded/local test hosts,
- proxy override: `--github-api-proxy <https-uri>`, intended for enterprise and CI egress environments and rejected when the URI uses HTTP or includes user info, query, or fragment data,
- TLS mode override: `--live-tls-mode system|tls12-plus`, where `system` uses platform defaults and `tls12-plus` restricts provider requests to TLS 1.2 or TLS 1.3; certificate validation is not bypassed,
- rate-limit overrides: `--live-provider-rate-limit-ms <n>` changes the same-provider minimum interval and `--live-rate-limit-ms <n>` changes the global minimum interval; `0` disables the selected interval,
- default endpoint policy: HTTPS required and non-public addresses blocked,
- explicit non-public endpoint escape hatch: `--allow-non-public-endpoints`,
- transient `408`, `500`, `502`, `503`, and `504` responses and transport timeouts/failures are retried once by default,
- `200 OK` maps to `active` and can add non-secret user login, scope, reachable-resource, and evidence metadata for `picket analyze --live`,
- `401 Unauthorized` maps to `inactive`,
- automatic HTTP redirects are disabled; redirect responses map to `error`,
- `403 Forbidden`, `429 Too Many Requests`, other unexpected statuses, request failures, and endpoint-policy failures map to `error`.
- HTTP responses include non-secret `httpStatus` evidence for audit and troubleshooting.

Before additional providers can be enabled in the CLI, each validator also requires a threat-model entry with:

- data sent,
- endpoint contacted,
- auth required,
- rate limits,
- expected success and failure codes,
- retry policy,
- cache key,
- revocation support and safe command-template output,
- known provider side effects,
- SSRF and redirect protections.

Provider requests must use `Picket.Security` endpoint checks to block loopback, private, link-local, metadata-service, reserved, and non-public redirect targets by default. Redirects are disabled unless a provider implements explicit target re-checking before following. Responses must be size-limited and redacted before diagnostics.

## Explicit Revocation

`picket revoke github` submits exposed GitHub credentials to GitHub's credential revocation API. The workflow is intentionally separate from live verification and analysis:

```text
picket revoke github --credential-env EXPOSED_GITHUB_TOKEN --confirm-revocation
```

Repeat `--credential-env` to submit more than one credential. The named variables must already exist in the process environment; Picket does not accept raw credential values as command arguments. The command requires `--confirm-revocation` because GitHub cannot reactivate a revoked credential.

The GitHub workflow has these boundaries:

- accepted families: `ghp_`, `github_pat_`, `gho_`, `ghu_`, and `ghr_`,
- default endpoint: `https://api.github.com/credentials/revoke`,
- request authentication: none; GitHub rejects authenticated requests to this endpoint,
- request limit: 1,000 credentials and one request per command invocation,
- provider rate limit: 60 unauthenticated requests per hour,
- endpoint policy: HTTPS, preflight and connect-time address checks, non-public addresses blocked by default, no user info/query/fragment in endpoint overrides, and no automatic redirects,
- proxy policy: optional HTTPS proxy with no user info/query/fragment,
- retry policy: none, because replaying an irreversible request after a timeout or transport failure can hide whether the first request succeeded,
- response handling: `202` is accepted, provider validation and client errors are rejected, redirects are blocked, and transport failures, timeouts, unexpected success responses, and server errors are indeterminate,
- output: fixed non-secret reasons and credential counts only; request and response bodies are not logged, cached, or included in diagnostics.

An accepted result exits `0`, a rejected or locally blocked result exits `1`, and an indeterminate provider outcome exits `2`. Invalid command input also exits nonzero without contacting GitHub. The command reports acceptance rather than claiming completed revocation because GitHub's documented success response is `202 Accepted`. See the [GitHub credential revocation API](https://docs.github.com/en/rest/credentials/revoke) for the provider contract.

## Reporting

Native report writers expose validation state in Picket JSON, JSONL, SARIF, CSV, JUnit, HTML, TOON, and GitLab code-quality outputs where the format supports it. Gitleaks-compatible report writers preserve the compatibility schema and do not add Picket-native validation fields.

Native analysis reports can include provider-specific revocation availability, command templates, and guidance. Current offline analysis guidance covers AWS, Azure Storage, database connection URLs, GCP, GitHub, GitLab token families, and Sourcegraph access tokens; live provider verification remains opt-in and GitHub-focused until additional provider validators have endpoint threat models and tests. Revocation is never automatic during scan, verification, or analysis. Command templates must be derived from non-secret identifiers and must never include raw secret values. Direct revocation uses provider-specific typed clients and never executes report command-template text as a shell command.

Secrets must be redacted before logs, action annotations, summaries, diagnostics, and crash data. Secret hashes are intended for deduplication and triage, not as proof that a credential is safe to disclose.
