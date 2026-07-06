# Validation and Privacy

Picket separates offline structural validation from live provider verification.

## Defaults

- No telemetry is collected.
- Live network verification is disabled by default.
- `picket scan` and compatibility commands do not contact provider APIs.
- `picket verify --offline` and native scan validation use local checks only.
- `--live` is reserved for opt-in provider verification and currently returns an error until provider validators are enabled.

## Offline Validation

Offline validation never sends secrets, hashes, paths, or metadata to a network endpoint. Current validators inspect local finding data and return one of these report values:

- `unknown`: no validator could prove a stronger state.
- `structurally-valid`: the secret has a valid local shape for the detected rule.
- `test-credential`: the secret appears to be a dummy, example, placeholder, or repeated-character credential.
- `invalid`: the secret fails a local structural check.
- `active`, `inactive`, `skipped`, and `error`: reserved for opt-in live verification results.

Current offline coverage includes:

- AWS access key ID shape and alphabet checks.
- Native AWS access key pair checks that require a valid access key ID and a 40-character secret access key alphabet.
- Azure Storage connection-string structure, account name, endpoint suffix, and 512-bit Base64 account-key checks.
- GCP API key prefix, length, and alphabet checks.
- GCP service account key JSON structure, project ID, private key ID, private-key envelope, service account email, and token URI checks.
- GitHub classic, OAuth, refresh, app, and fine-grained token shape checks.
- JWT and Base64-wrapped JWT segment, header, payload, algorithm, and signature-shape checks.
- private-key envelope checks.
- common test, dummy, fake, placeholder, and repeated-character suppression signals.

## Live Verification Model

Live provider calls are future opt-in behavior for the CLI. The reusable verification layer already defines the provider contract and safety envelope that provider validators must use:

- `ISecretLiveValidator` describes one provider validator, its endpoint, provider ID, version, and support check.
- `SecretLiveVerifier` chooses the first supporting validator, evaluates the endpoint guard before the validator runs, honors cancellation, and returns `skipped` when no validator supports a finding.
- `SecretValidationCache` stores live results with rule/provider/config fingerprint invalidation, expiration, and atomic writes.
- `SecretValidationCacheKey` is built from provider, validator version, rule ID, endpoint, and a SHA-256 secret hash. It rejects raw secret material where a hash is required.
- Cache files store fingerprints, report states, expiration, and non-secret reasons. They do not store raw secrets, raw matches, or endpoint query strings.

Before a provider can be enabled in the CLI, each validator also requires a threat-model entry with:

- data sent,
- endpoint contacted,
- auth required,
- rate limits,
- expected success and failure codes,
- retry policy,
- cache key,
- revocation support,
- known provider side effects,
- SSRF and redirect protections.

Provider requests must use `Picket.Security` endpoint checks to block loopback, private, link-local, metadata-service, reserved, and non-public redirect targets by default. Redirect targets must be re-checked before following. Responses must be size-limited and redacted before diagnostics.

## Reporting

Native report writers expose validation state in Picket JSON, JSONL, SARIF, CSV, JUnit, HTML, TOON, and GitLab code-quality outputs where the format supports it. Gitleaks-compatible report writers preserve the compatibility schema and do not add Picket-native validation fields.

Secrets must be redacted before logs, action annotations, summaries, diagnostics, and crash data. Secret hashes are intended for deduplication and triage, not as proof that a credential is safe to disclose.
