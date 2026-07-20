# Rule Authoring

Picket's compatibility rule format is Gitleaks TOML. Native rule-pack metadata extends this model, but strict compatibility mode must keep Gitleaks behavior stable.

## Config Loading

Compatibility commands load configuration in this order:

1. `--config`
2. `GITLEAKS_CONFIG`
3. `GITLEAKS_CONFIG_TOML`
4. `{target}/.gitleaks.toml`
5. embedded Gitleaks compatibility rules

Native commands currently use the same rule model with Picket-native environment precedence. `picket rules check` uses native precedence by default and also accepts `--profile picket` explicitly. Gitleaks-compatible `git`, `dir`/`file`/`directory`, and `stdin` scans use this same native precedence only when `--profile picket` is supplied.

1. `--config`
2. `PICKET_CONFIG`
3. `PICKET_CONFIG_TOML`
4. `GITLEAKS_CONFIG`
5. `GITLEAKS_CONFIG_TOML`
6. `{target}/.gitleaks.toml`
7. embedded Picket default config, which extends the embedded Gitleaks compatibility rules and adds `picket-default` coverage

Strict compatibility commands ignore `PICKET_CONFIG` and `PICKET_CONFIG_TOML`. Native commands also understand optional Picket metadata fields on each rule.

File-backed config loads, including `[extend] path`, are capped at 10 MiB per file. Resolved configs are capped at 10,000 rules. Inline `GITLEAKS_CONFIG_TOML` and `PICKET_CONFIG_TOML` values are parsed from the environment value already supplied to the process.

In strict compatibility mode, `[extend] path` follows the pinned Gitleaks/Viper local-file behavior: absolute paths are accepted, and relative paths resolve from the process current working directory. Picket keeps that behavior for compatibility, with the byte cap, extend-depth cap, and cycle detection described above. Treat configs with local `extend.path` values as trusted scanner configuration rather than as scan-root-confined input.

The embedded native default combines `gitleaks` with the high-confidence `picket-default` pack. Current native defaults include Anthropic OAuth and Claude Code session credentials; OpenAI API and Codex OAuth credentials; Groq and xAI keys; AWS key pairs; Azure Storage connection strings; credentialed database URLs; Google API keys and GCP service-account keys; Sourcegraph tokens; GitHub token families; Docker registry auth; private JWKs; Kubernetes Secrets; MCP server environment credentials; and npm tokens and basic credentials. Provider-specific fields receive offline structural validation where a deterministic validator exists.

The database URL rule requires a known database scheme, a username, and an embedded password; passwordless URLs are skipped. Native GitHub token rules replace inherited Gitleaks GitHub token rules so native scans emit Picket-owned IDs and metadata without duplicate findings. The native Sourcegraph rule replaces the inherited broad Sourcegraph rule so native scans do not report arbitrary 40-hex commit IDs as access tokens.

`--rule-pack picket-strict` adds broader medium-confidence rules for semicolon-delimited connection-string passwords, HTTP Basic authorization values, and Azure SAS signatures. `--rule-pack picket-experimental` adds low-confidence opaque bearer-token and session-cookie detectors under active tuning. Repeat `--rule-pack` to add both. These packs are opt-in and do not change the native default or strict Gitleaks compatibility behavior. Compatibility commands require `--profile picket` before accepting either pack.

Native `.cs` scans evaluate deterministic C# string-literal concatenations before matching, so literal-only `string.Concat(...)` calls and binary `+` literal chains can produce findings with `csharp-string-concat` decode provenance. Picket-native `picket-*` rule packs do not inherit Gitleaks compatibility global allowlists; broad compatibility stopwords must not suppress native hosted-scanner parity findings.

Target-local and environment configs replace the embedded native default. Use `[extend] useDefault = true` in a custom config to add local rules over the Gitleaks compatibility default. Explicit `--rule-pack` selections layer over the resolved native config.

## Rule Shape

Supported rule fields:

- `id`: stable rule identifier.
- `description`: human-readable finding description.
- `regex`: content pattern. Empty is valid only when `path` is present.
- `path`: path pattern.
- `secretGroup`: capture group containing the secret. `0` means automatic first non-empty capture behavior.
- `entropy`: minimum Shannon entropy. `0` disables entropy filtering.
- `randomnessThreshold`: minimum native `p(random)` score from `0.0` through `1.0`. `0` disables score filtering. See [Randomness Scoring](randomness.md).
- `detector`: stable built-in structured detector name. The regex and keywords remain the candidate prefilter; the detector parses the selected input and returns exact evidence spans.
- `keywords`: case-insensitive prefilter terms.
- `tags`: classification labels.
- `skipReport`: run supporting detection without reporting normal findings.
- `severity`: native report severity. Defaults to `critical`.
- `confidence`: native report confidence. Defaults to `high`.
- `rulePack`: native rule-pack identifier such as `gitleaks`, `picket-default`, or `picket-strict`.
- `provider`: owning provider or credential family.
- `documentationUrl`: rule documentation or remediation URL.
- `validation`: stable validation template identifiers supported by the rule. Identifiers name existing offline or live validators; they do not trigger network calls by themselves.
- `revocation`: stable revocation template identifiers supported by the rule. Identifiers name report/analyze templates; revocation is never automatic during scan.
- `deprecated`: `true` when the rule remains loadable but should not be used for new rule packs.
- `examples`: positive examples that must produce findings for this rule during rule QA.
- `negativeExamples`: negative examples that must not produce findings for this rule during rule QA.

Example:

```toml
[[rules]]
id = "sample-token"
description = "Sample token"
regex = '''token-[0-9]+'''
keywords = ["token"]
tags = ["example"]
severity = "high"
confidence = "medium"
rulePack = "picket-default"
provider = "example"
documentationUrl = "https://example.invalid/rules/sample-token"
examples = ["token-12345"]
negativeExamples = ["token-value"]
```

Randomness thresholds are native-only. A positive threshold suppresses a finding when its score is lower than the configured value; strict compatibility scans ignore the field. Keep the default of zero until reviewed positive and negative examples establish a safe threshold for that specific rule.

Built-in structured detector identifiers are:

- `codex-credentials`
- `docker-registry-credentials`
- `gcp-service-account-key`
- `jwk-private-key`
- `kubernetes-secret`
- `mcp-server-credentials`
- `npm-credentials`

Structured detectors are native-only. JSON, YAML, and npmrc parse products are bounded and shared for one input so multiple rules do not repeatedly parse the same content. Unknown detector names fail config validation.

Supported validation template identifiers are:

- `offline:anthropic-oauth-token`
- `offline:aws-access-key-id`
- `offline:aws-access-key-pair`
- `offline:azure-storage-connection-string`
- `offline:claude-code-session-url`
- `offline:codex-access-token`
- `offline:codex-refresh-token`
- `offline:database-connection-url`
- `offline:docker-registry-auth`
- `offline:gcp-api-key`
- `offline:gcp-service-account-key-json`
- `offline:github-app-token`
- `offline:github-classic-token`
- `offline:github-fine-grained-pat`
- `offline:groq-api-key`
- `offline:jwk-private-key`
- `offline:jwt`
- `offline:jwt-base64`
- `offline:kubernetes-secret`
- `offline:mcp-server-credential`
- `offline:npm-auth-token`
- `offline:npm-basic-auth`
- `offline:openai-api-key`
- `offline:private-key-envelope`
- `offline:sourcegraph-access-token`
- `offline:xai-api-key`
- `live:github-rest-user-v1`

Supported revocation template identifiers are:

- `revocation:aws-iam-access-key`
- `revocation:azure-storage-account-key`
- `revocation:gcp-api-key`
- `revocation:gcp-service-account-key`
- `revocation:github-credentials-api`

`picket rules check` rejects a template identifier when the current verifier or analyzer cannot honor it for that rule ID.

## Allowlists

Global allowlists use `[[allowlists]]` or the deprecated `[allowlist]` form. Rule allowlists use `[[rules.allowlists]]` or the deprecated `[rules.allowlist]` form.

Supported allowlist fields:

- `description`
- `condition`: `or`, `and`, `||`, or `&&`
- `commits`
- `paths`
- `regexTarget`: `secret`, `match`, or `line`
- `regexes`
- `stopwords`
- `targetRules` for global allowlists only

Deprecated singular allowlist tables cannot be mixed with plural allowlist tables in the same scope.

## Required Rules

Required rules let a primary finding require nearby supporting findings.

```toml
[[rules]]
id = "primary"
description = "Primary"
regex = '''secret-[0-9]+'''

[[rules.required]]
id = "supporting"
withinLines = 3
withinColumns = 80
```

Every required rule ID must exist, and a rule must not require itself.

## Validation

`picket rules check` validates:

- TOML shape for the supported Gitleaks schema.
- duplicate rule IDs.
- missing regex/path combinations.
- invalid regexes and secret capture groups.
- empty keywords, tags, allowlist entries, and required-rule IDs.
- required-rule references.
- required positive and negative examples for Picket-native rules.
- keyword prefilters for Picket-native content rules.
- known built-in detector names and detector-compatible native rules.
- obvious Picket-native regex performance hazards such as unbounded `.*` or `.+` spans outside character classes.
- positive and negative examples without printing example contents in diagnostics.
- validation and revocation template identifiers supported by the current verifier/analyzer.

`picket rules test <rule-id> <input>` scans sample text with one selected rule using Picket-native config precedence by default. It accepts `--source` for target-local `.gitleaks.toml` discovery, `--path` for path-only rules and report location metadata, `--max-decode-depth`, `--max-target-megabytes`, `--ignore-gitleaks-allow`, `--redact[=n]`, and the native report formats `json`, `jsonl`, `csv`, `junit`, `html`, `gitlab`, `sarif`, and `toon`. Use `--` before `<input>` when the sample starts with `-`. The default output is Picket JSON with schema, rule metadata, stable fingerprints, hashes, decode provenance, and offline validation state. Use `--print-config` to emit the resolved selected rule config.

## Scout Regex

Picket compiles rule and allowlist patterns to Scout `ByteRegex`. Unsupported patterns fail at config load with the rule ID and pattern context. Structured detector rules still use `ByteRegex` and keywords as their candidate prefilter; only the selected native rule then runs its bounded structured detector. Picket must not silently fall back to a different regex engine in Native AOT builds.
