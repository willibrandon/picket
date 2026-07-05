# Rule Authoring

Picket's compatibility rule format is Gitleaks TOML. Native rule-pack metadata extends this model, but strict compatibility mode must keep Gitleaks behavior stable.

## Config Loading

Compatibility commands load configuration in this order:

1. `--config`
2. `GITLEAKS_CONFIG`
3. `GITLEAKS_CONFIG_TOML`
4. `{target}/.gitleaks.toml`
5. embedded Gitleaks compatibility rules

Native commands currently use the same rule model with Picket-native environment precedence. Gitleaks-compatible `dir`/`file`/`directory` scans use this same native precedence only when `--profile picket` is supplied.

1. `--config`
2. `PICKET_CONFIG`
3. `PICKET_CONFIG_TOML`
4. `GITLEAKS_CONFIG`
5. `GITLEAKS_CONFIG_TOML`
6. `{target}/.gitleaks.toml`
7. embedded Gitleaks compatibility rules

Strict compatibility commands ignore `PICKET_CONFIG` and `PICKET_CONFIG_TOML`. Native commands also understand optional Picket metadata fields on each rule.

## Rule Shape

Supported rule fields:

- `id`: stable rule identifier.
- `description`: human-readable finding description.
- `regex`: content pattern. Empty is valid only when `path` is present.
- `path`: path pattern.
- `secretGroup`: capture group containing the secret. `0` means automatic first non-empty capture behavior.
- `entropy`: minimum Shannon entropy. `0` disables entropy filtering.
- `keywords`: case-insensitive prefilter terms.
- `tags`: classification labels.
- `skipReport`: run supporting detection without reporting normal findings.
- `severity`: native report severity. Defaults to `critical`.
- `confidence`: native report confidence. Defaults to `high`.
- `rulePack`: native rule-pack identifier such as `gitleaks`, `picket-default`, or `picket-strict`.
- `provider`: owning provider or credential family.
- `documentationUrl`: rule documentation or remediation URL.

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
```

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

`picket rules test <rule-id> <input>` scans sample text with a single rule and writes normal scan output.

## Scout Regex

Picket compiles rule and allowlist patterns to Scout `ByteRegex` through NuGet package references. Unsupported patterns fail at config load with the rule ID and pattern context. Picket must not silently fall back to a different regex engine in Native AOT builds.
