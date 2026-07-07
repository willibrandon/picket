# Agent Guide for Picket

This repository is the current checkout of Picket, a new MIT-licensed .NET secrets scanner based heavily on Gitleaks, built for Native AOT, and optimized around Scout's byte-oriented libraries where their semantics fit.

Read [docs/DESIGN.md](docs/DESIGN.md) before making architectural or behavioral changes. Treat it as the current product contract.

## Non-Negotiable Product Contract

Picket has two surfaces:

- **Gitleaks-compatible surface:** `picket git`, `picket dir`, `picket stdin`, hidden `detect`/`protect` shims, `.gitleaks.toml`, `.gitleaksignore`, baselines, fingerprints, exit codes, and reports must match the pinned Gitleaks oracle.
- **Picket-native surface:** `picket scan ...`, `picket verify`, `picket analyze`, `picket rules check`, `picket rules test`, `picket baseline`, `picket view`, native rule packs, stable fingerprints, richer reports, validation, dedup, and source-host/cloud scanning.

Do not let native features silently affect strict Gitleaks compatibility. New behavior belongs behind an explicit native command, profile, flag, rule pack, or report mode.

## Local Reference Repositories

These clones are read-only references unless the user explicitly says otherwise. **Never modify Scout.** In normal Picket work, do not modify any reference repo.

Use the environment variables below when available; otherwise local scripts and docs assume sibling clones next to this repository.

| Project | Environment variable | Default sibling clone | Role |
|---|---|---|---|
| Scout | `PICKET_SCOUT_REPO` | `../scout` | Read-only API/behavior reference. Picket must consume Scout only through NuGet packages. |
| Gitleaks | `PICKET_GITLEAKS_REPO` | `../gitleaks` | Primary compatibility oracle |
| TruffleHog | `PICKET_TRUFFLEHOG_REPO` | `../trufflehog` | Verification, sources, analyze reference |
| Nosey Parker | `PICKET_NOSEYPARKER_REPO` | `../noseyparker` | Historical datastore/rule-QA/perf reference |
| Kingfisher | `PICKET_KINGFISHER_REPO` | `../kingfisher` | Validation, revocation, access-map, reporting reference |
| .NET runtime | `PICKET_DOTNET_RUNTIME_REPO` | `../runtime` | Native AOT/runtime implementation reference |

Use these repos to verify facts before encoding compatibility behavior. Prefer `rg` for source searches. When a behavior matters, cite the exact upstream file/line in comments, tests, or docs as appropriate.

## Scout Usage Rules

Scout is a core advantage, not a blanket replacement for Gitleaks behavior.

- Picket must reference Scout only through NuGet packages: `Scout.Text.Regex`, `Scout.IO.Globbing`, and `Scout.IO.Ignore`.
- Use `PackageReference` entries with versions pinned through Central Package Management (`Directory.Packages.props`).
- Do not add `ProjectReference` entries to the Scout clone.
- Do not copy Scout source files into Picket.
- Do not use the local Scout clone as a build input; it is for reading APIs, implementation details, docs, and tests only.
- Use `Scout.Text.Regex.ByteRegex` for rule regexes over `ReadOnlySpan<byte>`.
- Use a keyword/literal prefilter to choose candidate rules.
- Do **not** assume one `ByteRegexSet` can replace Gitleaks' per-rule scan loop. `ByteRegexSet` is appropriate for prefilters and native rule packs whose semantics fit its result model.
- Use `Scout.IO.Globbing` for Picket-native glob ignores and path sets. Gitleaks path allowlists remain regex semantics in compatibility mode.
- Use `Scout.IO.Ignore` carefully. Its default hidden-file and ignore-file behavior does not match Gitleaks `dir`; strict compatibility must reproduce Gitleaks traversal.
- Reuse Scout's Native AOT and packaging patterns, but test platform-specific argv/path behavior rather than assuming it is identical on Windows and Unix.

## Compatibility Details to Preserve

Strict Gitleaks compatibility includes:

- Commands and aliases: `git`, `dir`/`file`/`directory`, `stdin`, hidden `detect`, hidden `protect`.
- Config precedence: `--config`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, `{target}/.gitleaks.toml`, embedded Gitleaks default config.
- `PICKET_CONFIG*` is ignored in strict compatibility unless a native profile/command is selected.
- Native profile precedence is `--config`, `PICKET_CONFIG`, `PICKET_CONFIG_TOML`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, `{target}/.gitleaks.toml`, embedded Picket default config. The embedded native default extends the embedded Gitleaks default and adds `picket-default` rules.
- `--platform` compatibility set is empty/unknown autodetect, `none`, `github`, `gitlab`, `azuredevops`, `gitea`, `bitbucket`. Literal `auto` is not Gitleaks-compatible.
- Git scanning follows Gitleaks' patch model: `git log -p -U0 --full-history --all --diff-filter=tuxdb`, additions only, plus staged/pre-commit behavior.
- Matching runs candidate rules independently, including rules with no keywords.
- `secretGroup = 0`, entropy strict `>`, allowlists, skip behavior, baseline fields, fingerprints, and `.gitleaksignore` behavior must match the oracle.
- Report writers are byte-oriented golden-output components. Do not use generic serialization for compatibility JSON/CSV/JUnit/SARIF/template output.
- `extend.url` is parsed and ignored in strict compatibility because local Gitleaks does not implement URL extend loading.

When in doubt, write a differential test against real Gitleaks instead of guessing.

## Performance and Size Strategy

Picket's default shipped CLI is Native AOT.

Release profiles from the design:

- `release-speed`: default public binary, `PublishAot=true`, `SelfContained=true`, RID-specific, `OptimizationPreference=Speed`.
- `release-minsize`: smallest artifact, `OptimizationPreference=Size`, diagnostics reduced only when behavior is unchanged.
- `release-diagnostics`: support artifact with diagnostics, metrics/EventSource, stack traces, and richer symbols.
- `framework-dev`: developer/test build with normal JIT, tiered compilation, Dynamic PGO defaults, and full diagnostics.

Implementation requirements:

- Libraries used by the CLI are `IsAotCompatible=true` and trim/AOT/single-file analyzer clean.
- No unresolved ILLink, AOT, or single-file warnings in CI.
- No dynamic code generation, Reflection.Emit, runtime serializer discovery, dynamic plugin loading, or reflection-only serialization in the Native AOT CLI.
- Use source-generated `System.Text.Json` only for native JSON/internal persistence; compatibility reports remain handwritten.
- Use spans and pooled buffers on hot paths. Avoid string allocation unless the output contract requires it.
- Tune IO, GC, SIMD, parallelism, and feature switches by measurement, not assumption.
- Prefer Scout's SIMD-aware search/regex implementation before adding custom intrinsics.
- Do not use executable compression by default; only use it when benchmarks prove the size/startup tradeoff is acceptable.

## Security and Privacy Requirements

- No telemetry.
- No live verification unless explicitly enabled.
- Offline structural validation may run by default only when it cannot exfiltrate data.
- Secrets are redacted before logs, diagnostics, reports, and crash data.
- Validators require SSRF protection, redirect checks, rate limits, TLS/proxy policy, response truncation, cache invalidation, and audit events.
- Archive processing requires decompressed-byte caps, entry caps, recursion caps, compression-ratio checks, path traversal protection, timeouts, and temp-file policy.
- Revocation is never automatic during scan.

## Planned Architecture

Expected projects/modules:

```text
Picket.Cli
  +-- Picket.Engine
        +-- Picket.Compat
        +-- Picket.Rules
        +-- Picket.Match
        +-- Picket.Sources
        +-- Picket.Decoding
        +-- Picket.Verify
        +-- Picket.Analyze
        +-- Picket.Report
        +-- Picket.Store
        +-- Picket.Security
```

Keep modules focused. Compatibility code belongs in `Picket.Compat` or compatibility-specific adapters. Native features should not leak into strict compatibility defaults.

## Testing Expectations

Use `MSTest.Sdk` with Microsoft.Testing.Platform (MTP) for new test projects. Microsoft currently recommends MSTest.Sdk + MTP for new MSTest projects; do not add legacy `Microsoft.NET.Test.Sdk`, VSTest adapters, or xUnit/NUnit unless the user explicitly changes the testing strategy. The repository opts into .NET 10 MTP mode in `global.json`; run solution tests with `dotnet test --solution Picket.slnx`.

Add tests at the level of risk:

- Unit tests for config parsing, entropy, fingerprints, decoder offset remapping, regex dialect translation, report writers, validators, and security boundaries.
- Differential tests against the pinned Gitleaks binary for compatibility behavior.
- Sanitized GitHub secret-scanning oracle captures for hosted-alert parity; never store GitHub API raw `secret` fields.
- Golden byte tests for every compatibility report format.
- Capture committed oracle fixtures with `-WorkingDirectory <fixture-root>` and relative command arguments whenever report paths are expected to be relative.
- Rule-corpus tests for Gitleaks default rules and selected community configs.
- Security tests for archive bombs, path traversal, SSRF, redaction leaks, cache poisoning, malformed TOML/reports/git patches, and invalid UTF-8.
- BenchmarkDotNet and end-to-end CLI benchmarks for performance-sensitive changes.
- Live provider tests are opt-in only; default CI uses recorded responses or local fakes.

Do not mark a feature complete without either tests or a documented reason why it cannot be tested yet.

## Documentation Expectations

Update docs when behavior changes:

- `docs/DESIGN.md`: product/architecture contract.
- `docs/PARITY.md`: required before v1; records every compatibility deviation.
- `docs/UPSTREAM.md`: required before v1; records upstream commits, source links, and sync process.
- `docs/RULES.md`: rule schema and authoring.
- `docs/VALIDATION.md`: privacy and egress model.
- `docs/REPORTS.md`: compatibility and native schemas.
- `docs/ACTION.md`: GitHub Action behavior.
- `docs/HOOKS.md`: local and server-side Git hook behavior.
- `docs/RELEASE.md`: Native AOT publish profiles and release artifact guidance.
- `docs/EMBEDDING.md`: library API guide.

Prefer precise, testable statements over marketing claims. If a competitor capability is mentioned, verify it against the local clone or current primary docs.

## Working Style for Agents

- Start by reading the relevant local code and docs.
- Preserve unrelated user changes.
- Use `apply_patch` for manual edits.
- Prefer small, coherent changes with focused tests.
- Keep files ASCII unless there is a clear reason otherwise.
- Follow the .NET runtime C# style baseline from `<runtime clone>/docs/coding-guidelines/coding-style.md` when available: Allman braces, four-space indentation, one contiguous using block sorted alphabetically across all namespaces (`Picket.*` before `System.*`), no separated using groups, avoid `this.` unless required, constants in PascalCase, private/internal instance fields as `_camelCase`, private/internal static fields as `s_camelCase`, and primary constructor parameters in normal `camelCase`.
- Keep one explicit type declaration per `.cs` file. Top-level `Program.cs` is allowed for the CLI entry point.
- All public types and members require triple-slash XML documentation.
- Do not leave unused usings; `IDE0005` is an error.
- Do not vendor or copy large code from reference repositories. Reimplement behavior from observed contracts and tests.
- For OpenAI/.NET/current external guidance, use primary official docs and record links in docs when they affect design or implementation.
