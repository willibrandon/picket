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

The initial embedded `picket-default` pack adds high-confidence coverage that is intentionally outside the pinned Gitleaks compatibility pack. Current native defaults include Azure Storage connection strings with `AccountKey` values, plus offline structural validation for the connection-string fields and 512-bit Base64 account key shape. Target-local and environment configs still replace the embedded native default; use `[extend] useDefault = true` in a custom config when you want to add local rules on top of the Gitleaks compatibility default.

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
- positive and negative examples without printing example contents in diagnostics.

`picket rules test <rule-id> <input>` scans sample text with one selected rule using Picket-native config precedence by default. It accepts `--source` for target-local `.gitleaks.toml` discovery, `--path` for path-only rules and report location metadata, `--max-decode-depth`, `--max-target-megabytes`, `--ignore-gitleaks-allow`, `--redact[=n]`, and the native report formats `json`, `jsonl`, `csv`, `junit`, `html`, `gitlab`, `sarif`, and `toon`. Use `--` before `<input>` when the sample starts with `-`. The default output is Picket JSON with schema, rule metadata, stable fingerprints, hashes, decode provenance, and offline validation state. Use `--print-config` to emit the resolved selected rule config.

## Scout Regex

Picket compiles rule and allowlist patterns to Scout `ByteRegex` through NuGet package references. Unsupported patterns fail at config load with the rule ID and pattern context. Picket must not silently fall back to a different regex engine in Native AOT builds.
