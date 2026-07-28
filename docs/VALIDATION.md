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

- Anthropic OAuth access and refresh token prefix, length, and alphabet checks.
- AWS access key ID shape and alphabet checks.
- Native AWS access key pair checks that require a valid access key ID and a 40-character secret access key alphabet.
- Azure Storage connection-string structure, account name, endpoint suffix, and 512-bit Base64 account-key checks.
- Buildkite user, agent, package, and portal token prefix, length, and alphabet checks.
- Cast AI API key prefix, segmented length, separator, and lowercase alphanumeric alphabet checks.
- Claude Code session URL host, path, and identifier checks.
- Codex OAuth access-token JWT shape and refresh-token structure checks.
- Database connection URL structure, known database schemes, username, and embedded password checks.
- Docker Hub personal and organization access token prefix, length, and alphabet checks.
- Docker registry basic credential checks after bounded Base64 decoding from an `auths` object.
- GCP API key prefix, length, and alphabet checks.
- GCP service account key JSON structure, project ID, private key ID, private-key envelope, service account email, and token URI checks.
- GitHub classic, OAuth, refresh, app, stateless app installation, and fine-grained token shape checks.
- Groq and xAI API key prefix, length, and alphabet checks.
- private JWK parameter checks within complete RSA, EC, or OKP key objects.
- JWT and Base64-wrapped JWT segment, header, payload, algorithm, and signature-shape checks.
- Kubernetes Secret values selected from bounded YAML structure without alias expansion.
- LangSmith personal and service key prefix, segmented length, and hexadecimal alphabet checks.
- credential-bearing MCP server environment values selected from `mcpServers.<server>.env`, excluding environment-variable references.
- NVIDIA, OpenRouter, Replicate, and Tailscale credential prefix, length, and alphabet checks.
- OpenAI legacy, project, project service-account, and organization-admin API key family checks.
- npm token and decoded basic credential checks from bounded npmrc assignments, excluding interpolation.
- private-key envelope checks.
- Sourcegraph `sgp_` access token shape checks.
- Vercel personal, integration, app access, app refresh, and AI Gateway credential prefix, length, and alphabet checks.
- common test, dummy, fake, placeholder, repeated-character, and repeated-pattern suppression signals.

Native rule metadata can list supported validation templates with stable identifiers such as `offline:gcp-api-key` or `live:github-rest-user-v1`. These identifiers document available capability and appear in rich native rule catalogs; they do not enable live provider calls unless the user selects an explicit live-verification command or flag.

## Live Verification Model

Live provider calls are opt-in behavior for `picket scan --verify`, `picket verify --live`, and `picket analyze --live`. The reusable verification layer defines the provider contract and safety envelope that provider validators must use:

- `ISecretLiveValidator` describes one provider validator, its endpoint, provider ID, version, and support check.
- `SecretLiveVerifier` chooses the first supporting validator, evaluates the endpoint guard before the validator runs, honors cancellation, and returns `skipped` when no validator supports a finding.
- `SecretLiveVerifierOptions` limits live provider concurrency to four total provider requests and one request per provider by default, spaces requests to the same provider by one second by default, and can also enforce a global request interval.
- Each verifier permits at most 100 outbound requests in total and 25 to any one provider by default. Every HTTP attempt, including a retry, consumes both budgets. Request-cache and persistent-cache hits, unsupported findings, and endpoint-policy rejections do not consume them.
- `SecretValidationCache` stores live results with rule/provider/config fingerprint invalidation, expiration, authenticated entries, owner-only file permissions on Unix-like systems and Windows, and atomic writes.
- `SecretValidationCacheKey` is built from provider, validator version, rule ID, endpoint, and a SHA-256 secret hash. It rejects raw secret material where a hash is required.
- Cache files store fingerprints, report states, expiration, non-secret reasons, and non-secret analysis metadata such as provider identity, scopes, resources, and evidence. They do not store raw secrets, raw matches, or endpoint query strings.
- Transient provider failures use the configured in-process error-cache duration to avoid repeating the same failed request during one verifier run. They are never written to the persistent cache.
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
- request-budget overrides: `--live-max-requests <n>` changes the global ceiling and `--live-max-requests-per-provider <n>` changes the per-provider ceiling; both require a positive value,
- default endpoint policy: HTTPS required and non-public addresses blocked,
- explicit non-public endpoint escape hatch: `--allow-non-public-endpoints`,
- transient `408`, `500`, `502`, `503`, and `504` responses and transport timeouts/failures are retried once by default,
- `200 OK` maps to `active` and can add non-secret user login, scope, reachable-resource, and evidence metadata for `picket analyze --live`,
- `401 Unauthorized` maps to `inactive`,
- automatic HTTP redirects are disabled; redirect responses map to `error`,
- `403 Forbidden`, `429 Too Many Requests`, other unexpected statuses, request failures, and endpoint-policy failures map to `error`.
- request-budget exhaustion maps to `error`, reports whether the global or per-provider budget was exhausted, never includes candidate secret material, and does not enter either validation cache,
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

### Direct Known-Secret Verification

`picket verify secret` checks one credential without placing its value in the process argument list. Supply exactly one selector:

- `--provider github` infers the supported GitHub token rule from the credential prefix.
- `--rule-id <id>` selects a supported GitHub live-validation rule explicitly.

By default, the command reads the credential from redirected standard input and removes one trailing line ending. `--secret-env <name>` reads the value from the named environment variable instead. Both input paths reject empty values and values longer than 65,536 characters.

```powershell
$env:PICKET_SECRET | picket verify secret --provider github
picket verify secret --provider github --secret-env PICKET_SECRET
```

```bash
printf '%s\n' "$PICKET_SECRET" | picket verify secret --provider github
picket verify secret --provider github --secret-env PICKET_SECRET
```

The command uses the same endpoint guard, proxy and TLS policy, rate limits, request budgets, retries, timeout, and authenticated validation cache as other live verification. Its `picket.validation.v1` JSON output contains only validation state, provider, rule ID, non-secret reason, identity, scopes, reachable resources, and evidence. It never includes the credential, match text, source line, or secret hash.

An `active` result exits `0`. `inactive`, `invalid`, and `test-credential` exit `1`. Indeterminate states such as `unknown`, `skipped`, and `error`, plus direct-verification validation or operational failures, exit `2`.

## Explicit Revocation

`picket revoke github` submits exposed GitHub credentials to GitHub's credential revocation API. The workflow is intentionally separate from live verification and analysis:

```text
picket revoke github --credential-env EXPOSED_GITHUB_TOKEN --confirm-revocation
```

Repeat `--credential-env` to submit more than one credential. The named variables must already exist in the process environment; Picket does not accept raw credential values as command arguments. The command requires `--confirm-revocation` because GitHub cannot reactivate a revoked credential.

The GitHub workflow has these boundaries:

- accepted families: `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, and `ghr_`,
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

Secrets must be redacted before logs, action annotations, summaries, diagnostics, and crash data. The scanner and TUI outer exception boundaries report only the unexpected exception type and fixed explanatory text; exception messages and stack traces are withheld because they can contain scanned source or credential-bearing provider data. Expected operational failures retain their specific non-secret diagnostics. Secret hashes are intended for deduplication and triage, not as proof that a credential is safe to disclose.
