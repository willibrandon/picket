# Picket Design

**Picket is a new MIT-licensed secrets scanner for .NET: Gitleaks-compatible where compatibility is promised, Picket-native where the product should move beyond Gitleaks, and Scout-powered on the byte-oriented hot paths where Scout is the right engineering fit.**

- **Status:** Product and implementation design
- **Date:** 2026-07-05
- **Target runtime:** `picket` CLI on .NET 10 Native AOT (`net10.0`); reusable libraries target `net9.0` and `net10.0`
- **Binary name:** `picket`
- **Root namespace:** `Picket`
- **Primary reference:** Gitleaks. Picket intentionally follows its CLI, config model, rule semantics, reports, fingerprints, and operational defaults in compatibility mode.
- **Scout dependencies:** `Scout.Text.Regex`, `Scout.IO.Globbing`, and selected `Scout.IO.Ignore` traversal components when their behavior matches the active scan profile.
- **License:** MIT for the scanner, libraries, action, hooks, and bundled rules.

---

## 1. Product Contract

Picket has two explicit surfaces. They share the same engine, but they do not share every default.

### 1.1 Gitleaks-Compatible Surface

The compatibility surface is for users who want to replace `gitleaks` with `picket` and keep their current automation stable.

- Commands: `picket git`, `picket dir`, `picket stdin`, plus hidden/deprecated `detect` and `protect` shims.
- Config: `.gitleaks.toml`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`, `.gitleaksignore`, baselines, rule schema, allowlists, and report formats follow Gitleaks exactly at the pinned upstream version.
- Defaults: only Gitleaks-compatible rules and Gitleaks-compatible traversal/reporting behavior are enabled.
- Output contract: strict compatibility report modes byte-match pinned Gitleaks fixtures, including identity fields where consumers depend on them. Native report modes identify Picket and are compared with their own golden files.
- Deviations: every intentional difference is recorded in `docs/PARITY.md` with an oracle test.

### 1.2 Picket-Native Surface

The native surface is where Picket becomes a best-in-class scanner rather than a clone.

- Command family: `picket scan ...`, `picket verify`, `picket analyze`, `picket rules check`, `picket rules test`, `picket baseline`, `picket view`.
- Profile: `--profile picket` enables Picket rule packs, stable fingerprints, richer ignore semantics, offline validation, richer reports, and datastore-backed dedup.
- Live network verification remains explicit. Offline structural validation can run by default in native profiles because it does not contact providers.
- Native output includes Picket metadata such as validation state, blob IDs, decode path, confidence, severity, rule pack, and provenance.

The rule is simple: **Gitleaks-compatible commands must not silently adopt Picket-native behavior.** New power belongs behind a native command, profile, flag, or rule pack.

---

## 2. Positioning

Picket is heavily based on Gitleaks because Gitleaks has the clearest open-source contract for config files, ignore files, fingerprints, and CI usage. Picket treats Gitleaks as the compatibility base and then adds the capabilities developers now expect from a leading scanner:

- fast byte-oriented scanning,
- high-quality rule packs with examples and tests,
- low false-positive defaults,
- safe offline validation,
- opt-in live verification,
- credential privilege and blast-radius analysis,
- datastore-backed dedup and incremental scans,
- first-class ignore and baseline workflows,
- SARIF/JSONL/HTML/TOON outputs,
- a free MIT GitHub Action and local hooks,
- embeddable .NET libraries.

Picket is not a SaaS and does not require an account. It has no telemetry. Any feature that can send secrets or metadata to a provider API is opt-in, visibly labeled, rate limited, and covered by a documented egress model.

---

## 3. Reference Pins

The design and differential tests are pinned to local reference snapshots. Upgrades are deliberate, reviewed changes.

| Project | Local path | Role |
|---|---|---|
| Gitleaks | `D:\SRC\gitleaks` | Primary compatibility oracle |
| Scout | `D:\SRC\scout` | Library reference; never modified by Picket work |
| TruffleHog | `D:\SRC\trufflehog` | Verification, sources, and analyze reference |
| Kingfisher | `D:\SRC\kingfisher` | Validation breadth, revocation, access-map, reporting reference |
| Nosey Parker | `D:\SRC\noseyparker` | Historical datastore/rule-QA/performance reference |

`docs/UPSTREAM.md` records exact commits, supported upstream versions, known README/code divergences, and the command lines used by oracle tests. For example, Gitleaks' current code default for `--max-decode-depth` is `5`; if upstream docs say otherwise, Picket follows the code in compatibility tests and records the discrepancy.

---

## 4. Scout Usage Principles

Scout is a core advantage, but Picket only uses Scout APIs where their semantics match the scanner contract.

### 4.1 `Scout.Text.Regex`

Picket uses Scout's byte regex engine for matching rule regexes against `ReadOnlySpan<byte>` buffers. This is the main architectural reason to build Picket in this repository.

Rules:

- Each detector rule compiles to its own `ByteRegex` for exact per-rule matching, captures, entropy, allowlists, and overlapping behavior.
- A keyword prefilter is built from rule keywords and required literals. It narrows the candidate rule set before regex execution.
- `ByteRegexSet` is used only where its result model matches the need: fast prefilters, literal/required-pattern discovery, and native rule packs that do not require Gitleaks-style per-rule overlapping captures.
- Picket does **not** assume a single `ByteRegexSet` can replace Gitleaks' independent per-rule scan loop. That would be faster on paper and wrong in practice.
- Unsupported regex constructs fail at config load with rule ID, pattern, reason, and remediation. There is no silent fallback that changes finding behavior.

### 4.2 `Scout.IO.Globbing`

`Scout.IO.Globbing` powers native glob ignore entries, path include/exclude sets, stable ignore fingerprints, and native rule-pack path scopes. In Gitleaks-compatible mode, regex path allowlists remain regex path allowlists; glob behavior is only used where Gitleaks semantics already call for it or where a Picket-native feature was explicitly selected.

### 4.3 `Scout.IO.Ignore`

`Scout.IO.Ignore` is used carefully.

- Native Picket filesystem scans may honor `.gitignore`, `.ignore`, `.picketignore`, global Git excludes, hidden-file policy, and parallel traversal.
- Gitleaks-compatible `dir` scans must reproduce Gitleaks traversal, which does not automatically honor `.gitignore` and does not skip hidden files just because Scout's `FileWalkerOptions` defaults do.
- Picket may reuse lower-level Scout traversal components, but compatibility mode sets options or uses a compatibility walker so the observable file set matches Gitleaks.

### 4.4 Native AOT

The CLI is Native AOT and single-file/self-contained per RID. Picket reuses Scout's build and packaging patterns, but it does not assume Unix raw-argv handling and Windows wide-argv handling are identical. Path/argument byte behavior is tested per platform.

---

## 5. Architecture

```
Picket.Cli
  +-- Picket.Engine
        +-- Picket.Compat      - Gitleaks command, config, report, and oracle contracts
        +-- Picket.Rules       - rule model, rule packs, examples, validators, RE2/Scout translation
        +-- Picket.Match       - keyword prefilter, ByteRegex execution, captures, entropy, allowlists
        +-- Picket.Sources     - filesystem, git, stdin, archives, source hosts, object stores, Docker
        +-- Picket.Decoding    - recursive decoders with original-offset remapping
        +-- Picket.Verify      - offline validators, live validators, cache, revocation hooks
        +-- Picket.Analyze     - credential privilege and access-map analysis
        +-- Picket.Report      - Gitleaks-exact and Picket-native report writers
        +-- Picket.Store       - content-addressed blob store and incremental scan state
        +-- Picket.Security    - egress policy, redaction, SSRF guards, audit events
```

Hot-path constraints:

- `ReadOnlySpan<byte>` first,
- stable line/column and byte offset mapping,
- pooled buffers,
- no LINQ in match loops,
- no reflection-dependent runtime behavior required for Native AOT,
- explicit allocation and throughput tests.

---

## 6. Gitleaks Compatibility

### 6.1 Commands

| Command | Compatibility behavior |
|---|---|
| `picket git [repo]` | Uses the same Git patch model as Gitleaks: `git log -p -U0 --full-history --all --diff-filter=tuxdb`, additions only. `--log-opts`, `--staged`, and `--pre-commit` reproduce Gitleaks behavior, including its quoting limitations where tests depend on them. |
| `picket dir [path]` | Filesystem scan with Gitleaks traversal semantics. Aliases: `file`, `directory`. Supports `--follow-symlinks`. |
| `picket stdin` | Scans piped input with Gitleaks-compatible path/fingerprint/report behavior. |
| `picket detect` | Hidden/deprecated shim. Maps to `git`, `dir`, or `stdin` the way Gitleaks does. |
| `picket protect` | Hidden/deprecated shim. Maps to pre-commit/staged behavior. |

`--platform` accepts the Gitleaks-compatible set: empty/unknown autodetect, `none`, `github`, `gitlab`, `azuredevops`, `gitea`, and `bitbucket`. Literal `auto` is Picket-native only if added; it is not part of the Gitleaks-compatible surface.

### 6.2 Flags and Exit Codes

Compatibility flags include:

`-c/--config`, `--exit-code`, `-r/--report-path`, `-f/--report-format`, `--report-template`, `-b/--baseline-path`, `-l/--log-level`, `-v/--verbose`, `--no-color`, `--no-banner`, `--max-target-megabytes`, `--ignore-gitleaks-allow`, `--redact[=0..100]`, `--enable-rule`, `-i/--gitleaks-ignore-path`, `--max-decode-depth`, `--max-archive-depth`, `--timeout`, `--diagnostics`, and `--diagnostics-dir`.

Config precedence in compatibility mode is exact:

1. `--config`
2. `GITLEAKS_CONFIG`
3. `GITLEAKS_CONFIG_TOML`
4. `{target}/.gitleaks.toml`
5. embedded Gitleaks default config

`PICKET_CONFIG*` variables are ignored by strict compatibility mode unless `--profile picket` or a native command is selected.

Exit codes:

- `0`: no leaks and no fatal error,
- configured `--exit-code` value, default `1`: leaks found,
- `1`: scan error or partial scan,
- `126`: unknown flag.

Reports are written on partial scans when Gitleaks writes them.

### 6.3 Config Schema

Picket implements the Gitleaks TOML schema:

- `[extend]`: `useDefault`, `path`, `disabledRules`, chain depth, merge ordering, conflict rules, and `minVersion`.
- `extend.url`: parsed and ignored in strict compatibility mode because local Gitleaks has an unimplemented URL extender. Native mode may warn.
- `[[rules]]`: `id`, `description`, `regex`, `path`, `secretGroup`, `entropy`, `keywords`, `tags`, `skipReport`, allowlists, and required/composite rules.
- Allowlists: global and per-rule, plural and deprecated singular forms, `condition`, `commits`, `paths`, `regexTarget`, `regexes`, `stopwords`, and `targetRules`.
- Validation: Picket emits the same config errors Gitleaks emits for empty allowlists, mixed singular/plural allowlists, duplicate IDs, missing regex/path, invalid capture groups, and invalid extend combinations.

The embedded compatibility ruleset is the pinned Gitleaks default ruleset only. Picket rules live in separate rule packs.

### 6.4 Regex Compatibility

Gitleaks rules are Go `regexp` patterns. Picket compiles them to Scout `ByteRegex` through a dialect layer.

The dialect layer defines behavior for:

- UTF-8 and invalid-byte handling,
- `.` and newline semantics,
- anchors and multiline flags,
- named captures,
- POSIX classes,
- case-insensitive matching,
- secret-group extraction,
- unsupported constructs.

Every default Gitleaks rule and selected community config is compiled and run through both real Gitleaks and Picket in the differential suite. The design goal is not "roughly RE2-like"; it is tested Gitleaks rule behavior.

### 6.5 Matching Semantics

Compatibility matching reproduces Gitleaks' observable algorithm:

- keyword prefilter decides candidate rules,
- rules with no keywords still run,
- each candidate rule executes independently,
- all matches for each rule are considered,
- captures are extracted per rule,
- `secretGroup = 0` uses the first non-empty capture group when Gitleaks does,
- entropy uses strict `>` comparison,
- allowlists run in the same order and against the same targets,
- skipped rules and `skipReport` follow Gitleaks.

Picket-native modes can add richer confidence scoring and cross-rule correlation, but compatibility mode does not.

### 6.6 Fingerprints, Ignores, Baselines

Compatibility fingerprints:

- Git: `{commit}:{file}:{rule-id}:{startLine}`
- Dir/stdin: `{file}:{rule-id}:{startLine}`
- Paths normalize to `/`.
- Archive provenance uses a stable inner-path separator compatible with reports and ignore parsing.

`.gitleaksignore` behavior:

- blank lines and comments ignored,
- 3-part and 4-part fingerprints accepted,
- paths normalized,
- commit-less ignore checked before commit-qualified ignore for git findings.

Inline suppression honors `gitleaks:allow` unless `--ignore-gitleaks-allow` is set.

Baselines compare the same fields as Gitleaks. Fingerprint is deliberately not the baseline key.

Native mode adds `.picketignore`, glob ignores, content-hash ignores, stale-ignore auditing, and stable fingerprints. Those features never silently affect strict Gitleaks compatibility.

### 6.7 Reports

Compatibility report writers are byte-oriented golden-output components, not generic serializers.

- JSON: exact field order, escaping, indentation, omitted fields, empty-array behavior, and trailing newline behavior from the pinned Gitleaks version.
- CSV: exact header behavior, including the no-findings case and conditional `Link` column behavior.
- JUnit: exact XML shape, suite names, failure text, escaping, and indentation.
- SARIF: exact Gitleaks-compatible mode for consumers that depend on `tool.driver.name`, semantic version, fingerprints, and snippets.
- Template: Go `text/template` compatibility with the same supported safe Sprig function map as Gitleaks. Template behavior is tested with real templates.

Native reporters add JSONL, richer SARIF, TOON, HTML, GitLab code-quality, and simultaneous multi-output support.

### 6.8 Decoding, Archives, Binary Files

Compatibility mode follows Gitleaks for:

- recursive decoders and default depth,
- original-offset remapping,
- decode tags,
- archive depth defaults,
- binary/MIME skip behavior,
- large-file chunking,
- git binary blob handling,
- decimal megabyte size caps.

Native mode adds stricter archive-safety controls: decompressed byte caps, entry count caps, recursion caps, compression-ratio checks, timeouts, path traversal protection, temp-file policy, and clear diagnostics.

---

## 7. Picket-Native Best-In-Class Features

### 7.1 Rule Packs

Picket ships separate rule packs:

- `gitleaks`: exact compatibility rules,
- `picket-default`: high-confidence modern coverage,
- `picket-strict`: broader coverage with more aggressive heuristics,
- `picket-experimental`: new detectors under active tuning,
- organization-local packs.

Each rule can carry severity, confidence, examples, negative examples, tags, validation metadata, revocation metadata, documentation URL, deprecation state, and owning provider.

### 7.2 Rule QA

`picket rules check` validates:

- schema correctness,
- regex compilation,
- examples and negative examples,
- capture group expectations,
- entropy thresholds,
- path scope behavior,
- validator templates,
- revocation templates,
- duplicate or unstable rule IDs,
- performance hazards.

`picket rules test <rule> <input>` supports interactive authoring. `--print-config` emits fully resolved config after extends, profile selection, and rule-pack layering.

### 7.3 False-Positive Reduction

Native profiles combine:

- provider-specific structural checks,
- checksum validation where token formats support it,
- known dummy/test credential suppression,
- placeholder and fixture detection,
- entropy plus deterministic randomness scoring,
- dependent-rule correlation,
- severity/confidence thresholds,
- explicit reporting of suppressed findings when requested.

`p(random)` is not a vague ML promise. It is a deterministic scoring component with documented training data, calibration fixtures, stable thresholds, and explainable fields in native reports.

### 7.4 Verification

Picket supports two classes of validation.

Offline validation:

- checksum and format validation,
- JWT structural and cryptographic checks where public keys are already available or explicitly configured,
- provider-specific token checks that require no network,
- enabled by default in native profiles when it cannot exfiltrate data.

Live verification:

- opt-in via `--verify` or `picket verify`,
- result states: `active`, `inactive`, `unknown`, `skipped`, `error`,
- result filters: `--results`, `--only-verified` compatibility aliases,
- request cache and persistent cache with rule/config/version invalidation,
- global and per-provider rate limits,
- retries with cache-poisoning protection,
- proxy and endpoint override support,
- TLS mode controls,
- SSRF protection blocking loopback, private, link-local, metadata-service, and non-public redirect targets by default,
- max response length and redaction,
- audit events showing which provider endpoints were contacted.

### 7.5 Revocation

Where provider APIs support safe self-service revocation, Picket can emit and optionally run revocation commands. Revocation is never automatic during scan. Reports include revocation availability and exact command guidance only when redaction settings allow it.

### 7.6 Credential Privilege Analysis

`picket analyze` maps what an active credential can access. It is inspired by TruffleHog analyze and Kingfisher access-map work, not claimed as unique.

Initial targets:

- GitHub and GitHub App tokens,
- AWS access keys,
- GCP service account keys,
- Azure credentials,
- GitLab tokens,
- database connection strings,
- common SaaS API tokens.

Analysis output is separate from scan output and optimized for incident response: identity, scopes, reachable resources, risk summary, recommended rotation/revocation steps, and evidence.

### 7.7 Blob Store and Incremental Scans

`Picket.Store` content-addresses every scanned blob and records provenance separately.

Design requirements:

- SHA-256 blob identity,
- schema versioning and migrations,
- rule-pack/config/version cache invalidation,
- decode/archive-derived blob lineage,
- concurrent CI-safe locking,
- encrypted or secret-hash-only cache modes,
- GC and retention policy,
- portable cache export/import,
- provenance-preserving reports.

Dedup skips duplicate matching work but does not collapse compatibility reports. If Gitleaks would report the same blob at multiple commits/paths, compatibility mode still reports every provenance.

### 7.8 Sources

Native source support:

- filesystem,
- git history,
- stdin,
- archives,
- GitHub repos, orgs, PRs, issues, gists, releases, and Actions artifacts,
- GitLab groups/projects/MRs/snippets/artifacts,
- Bitbucket, Azure Repos, and Gitea,
- S3, GCS, Azure Blob,
- Docker/OCI images and tarballs.

Every remote source requires an auth, pagination, retry, rate-limit, checkpoint, permission, and redaction model. Provider endpoint overrides are required for enterprise/self-hosted use.

### 7.9 Output and Triage

Native outputs:

- JSONL stream,
- rich JSON with schema version,
- SARIF tuned for GitHub code scanning,
- TOON,
- HTML report,
- GitLab code-quality,
- JUnit,
- CSV,
- templates.

Native reports include stable rule metadata, redacted and hashed secret representations, validation state, confidence/severity, provenance, decode path, baseline status, ignore reason, and remediation links.

`picket view` opens local HTML/JSON/JSONL/SARIF reports and can import compatible Gitleaks and TruffleHog reports for cross-tool triage.

### 7.10 CI, Hooks, and Distribution

Picket ships:

- MIT `picket-action`,
- pre-commit, pre-push, and pre-receive hooks,
- Docker images,
- Homebrew, Scoop, winget, MSI,
- `dotnet tool`,
- NuGet packages for embedding.

The GitHub Action supports annotations, SARIF upload, fetch-depth guidance, baseline handling, cache restore/save, least-privilege permissions, summary output, and explicit fail modes.

Pre-receive support handles bare repositories, quarantine environment variables, old/new ref input, timeouts, concurrency, and clear rejection messages.

### 7.11 Embeddable .NET API

`Picket.Engine`, `Picket.Rules`, and `Picket.Report` are AOT-safe NuGet packages for analyzers, MSBuild tasks, CI systems, IDE integrations, and internal security platforms.

Public APIs are documented, cancellation-aware, streaming-first, and stable across minor releases.

---

## 8. Security and Privacy Model

Security requirements:

- default no telemetry,
- default no live network verification unless explicitly enabled,
- no secrets in logs by default,
- redaction applies before reporting and diagnostics,
- secret hashes use keyed or context-safe hashing where appropriate,
- archive extraction is bounded,
- validators are SSRF-hardened,
- provider requests are rate-limited,
- temporary files are avoided or securely managed,
- crash diagnostics are scrubbed,
- action logs are safe for public CI by default.

Every validator has a threat-model entry: data sent, endpoint contacted, auth required, rate limits, expected success/failure codes, retry policy, cache key, revocation support, and known provider side effects.

---

## 9. Testing Strategy

### 9.1 Compatibility Oracle

The Gitleaks oracle suite runs the pinned real Gitleaks binary and Picket over identical fixtures.

Assertions:

- findings,
- fingerprints,
- ignore behavior,
- baseline suppression,
- exit codes,
- stdout/stderr where relevant,
- report bytes,
- config errors,
- timeout and partial-scan behavior.

The suite includes filesystem scans, git-history scans, staged/pre-commit diffs, archives, decoders, binary files, symlinks, Windows paths, invalid UTF-8, templates, SARIF, empty reports, and partial errors.

### 9.2 Rule Corpus

Every bundled Gitleaks rule and selected community rules are compiled through the dialect layer and tested against fixtures under both tools. Picket-native rules require positive and negative examples before release.

### 9.3 Security Tests

Tests cover:

- archive bombs,
- path traversal,
- validator SSRF attempts,
- redirect-to-private-IP attempts,
- redaction leaks,
- cache poisoning,
- malformed reports,
- malformed TOML,
- malformed git patches,
- malformed UTF-8.

### 9.4 Performance Tests

Performance gates are scenario-specific and fair:

- Gitleaks-compatible cold scans compared to Gitleaks with equivalent flags,
- native incremental scans compared against previous Picket runs,
- verification benchmarks separated from scan-only benchmarks,
- retired tools such as Nosey Parker used only as historical datapoints, not live release gates.

Metrics include throughput, allocations, peak memory, startup time, rule compile time, cache hit rate, and report writer throughput.

### 9.5 Live Tests

Live provider tests are opt-in and isolated from the default suite. Default CI uses recorded responses and local fakes. "Zero skipped tests" applies to the required offline suite, not to intentionally opt-in live credential tests.

---

## 10. Compatibility Ledger

`docs/PARITY.md` is required before v1.

Each entry includes:

- upstream behavior,
- Picket behavior,
- mode/profile affected,
- reason,
- user impact,
- test name,
- migration guidance.

Examples:

- Gitleaks-compatible SARIF identity,
- native SARIF identity,
- stable fingerprint mode,
- `.picketignore`,
- `.gitignore` traversal in native mode,
- native rule packs,
- native validation metadata.

---

## 11. Competitive Baseline

Picket should be judged against current local references, not stale marketing claims.

| Capability | Gitleaks | TruffleHog | Nosey Parker | Kingfisher | Picket target |
|---|:--:|:--:|:--:|:--:|:--:|
| MIT/permissive scanner | Yes | No, AGPL | Yes | Yes | Yes, MIT |
| Gitleaks CLI/config compatibility | Native | No | No | Partial import/report awareness | Yes |
| Byte-oriented .NET Native AOT | No | No | No | No | Yes |
| Live verification | No | Yes | No | Yes | Yes |
| Offline structural validation | Limited | Limited | No | Yes | Yes |
| Revocation support | No | Limited/varies | No | Yes | Yes where safe |
| Privilege/access analysis | No | Yes | No | Yes | Yes |
| Content dedup/incremental | No | Limited | Yes | Yes | Yes |
| First-class ignore workflow | Basic `.gitleaksignore` | Inline/path controls, not first-class global ignore | Limited | Baselines/config | Yes |
| Rule examples/self-test | Limited | Detector tests in code | Yes | Strong rule validation | Yes |
| Rich triage viewer | No | TUI/outputs | No | Yes | Yes |
| Native embeddable .NET API | No | No | No | No | Yes |
| Free MIT GitHub Action | Scanner yes, action licensing varies | Yes under project license constraints | No | No | Yes |

Claims of uniqueness must be narrow and testable. Picket's intended unique intersection is: **MIT, Gitleaks-compatible, Scout-powered byte scanning, Native AOT .NET, strong validation/analyze/dedup, and embeddable .NET APIs.**

---

## 12. Milestones

Milestones are integration gates, not marketing promises. Each gate must leave the repository with passing tests and no stubbed public feature.

### M0: Foundation

- project layout,
- Native AOT CLI shell,
- rule/config model,
- finding model,
- basic Gitleaks-compatible reports,
- Scout `ByteRegex` proof of concept,
- oracle harness skeleton.

Gate: fixture `dir` scan matches pinned Gitleaks for a small rule subset.

### M1: Gitleaks Compatibility Core

- commands and flags,
- config precedence,
- Gitleaks rule schema,
- matching semantics,
- fingerprints,
- `.gitleaksignore`,
- baseline,
- JSON/CSV/JUnit/SARIF/template reports,
- git patch scanning through the compatibility pipeline,
- decoders and archives.

Gate: full compatibility suite green for pinned Gitleaks fixtures.

### M2: Scout-Optimized Engine

- keyword/literal prefilter,
- per-rule `ByteRegex` execution,
- regex dialect conformance,
- allocation controls,
- throughput gates.

Gate: equal findings to M1 with materially better scan hot-path metrics.

### M3: Native Rule Packs and FP Reduction

- rule-pack layering,
- examples and rule QA,
- deterministic randomness scoring,
- structural validators,
- dummy/test credential suppression,
- stable fingerprints and native ignores.

Gate: native profile fixtures show lower false positives without compatibility regressions.

### M4: Store and Incremental

- blob store,
- provenance model,
- cache invalidation,
- CI-safe locking,
- GC,
- incremental scan commands.

Gate: second scan skips unchanged blobs while preserving compatibility report provenance.

### M5: Verification, Revocation, Analyze

- offline validators,
- opt-in live validators,
- validation cache,
- SSRF and egress policy,
- revocation metadata,
- `picket analyze`.

Gate: recorded provider suites green; live tests opt-in and documented.

### M6: Native Sources and Triage

- source-host scanners,
- object-store scanners,
- Docker/OCI scanners,
- JSONL/rich JSON/TOON/HTML/GitLab reports,
- `picket view`.

Gate: remote enumeration, checkpointing, redaction, and dedup tests green.

### M7: Distribution

- `dotnet tool`,
- NuGet libraries,
- Docker,
- Homebrew/Scoop/winget/MSI,
- GitHub Action,
- hooks.

Gate: release workflow produces signed/checksummed artifacts and action smoke tests pass.

### M8: Optional Stretch

- honeytokens,
- leak-database checks,
- organization policy packs.

Stretch features are not v1 blockers unless promoted by a separate design update.

---

## 13. Documentation Deliverables

Required before v1:

- `docs/PARITY.md`: compatibility ledger,
- `docs/UPSTREAM.md`: reference pins and sync process,
- `docs/RULES.md`: rule schema, examples, validator/revocation metadata,
- `docs/VALIDATION.md`: privacy and egress model,
- `docs/REPORTS.md`: compatibility and native schemas,
- `docs/ACTION.md`: CI action behavior and security posture,
- `docs/EMBEDDING.md`: library API guide.
