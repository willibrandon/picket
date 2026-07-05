# Picket Design

**Picket is a new MIT-licensed secrets scanner for .NET: Gitleaks-compatible where compatibility is promised, Picket-native where the product should move beyond Gitleaks, and Scout-powered on the byte-oriented hot paths where Scout is the right engineering fit.**

- **Status:** Product and implementation design
- **Date:** 2026-07-05
- **Target runtime:** `picket` CLI on .NET 10 Native AOT (`net10.0`); reusable libraries target `net9.0` and `net10.0`
- **Binary name:** `picket`
- **Root namespace:** `Picket`
- **Primary reference:** Gitleaks. Picket intentionally follows its CLI, config model, rule semantics, reports, fingerprints, and operational defaults in compatibility mode.
- **Scout dependencies:** NuGet package references to `Scout.Text.Regex`, `Scout.IO.Globbing`, and selected `Scout.IO.Ignore` APIs when their behavior matches the active scan profile. The local Scout clone is a read-only reference only.
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
| Scout | `D:\SRC\scout` | Read-only API/behavior reference only. Picket consumes Scout via NuGet packages, never project/source references. |
| TruffleHog | `D:\SRC\trufflehog` | Verification, sources, and analyze reference |
| Kingfisher | `D:\SRC\kingfisher` | Validation breadth, revocation, access-map, reporting reference |
| Nosey Parker | `D:\SRC\noseyparker` | Historical datastore/rule-QA/performance reference |

`docs/UPSTREAM.md` records exact commits, supported upstream versions, known README/code divergences, and the command lines used by oracle tests. For example, Gitleaks' current code default for `--max-decode-depth` is `5`; if upstream docs say otherwise, Picket follows the code in compatibility tests and records the discrepancy.

---

## 4. Scout Usage Principles

Scout is a core advantage, but Picket only uses Scout APIs where their semantics match the scanner contract.

Scout must be consumed only through NuGet package references:

- `Scout.Text.Regex`
- `Scout.IO.Globbing`
- `Scout.IO.Ignore`

Use Central Package Management (`Directory.Packages.props`) to pin Scout package versions. Do not add `ProjectReference` entries to `D:\SRC\scout`, do not include Scout source files in this repository, and do not treat the local Scout clone as part of the build. The local clone exists only for reading implementation details, docs, and tests while designing Picket behavior.

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

## 6. Performance, Size, and AOT Strategy

This section applies current Microsoft .NET deployment, trimming, Native AOT, GC, memory, SIMD, and diagnostics guidance to Picket. The local runtime clone at `D:\SRC\runtime` is a reference for implementation details and Native AOT defaults, but public behavior follows documented SDK/runtime contracts.

### 6.1 Release Profiles

Picket ships multiple publish profiles because "fastest" and "smallest" are not the same artifact.

| Profile | Purpose | Defaults |
|---|---|---|
| `release-speed` | Primary CLI artifact. Fast startup and fastest scan throughput while remaining small. | `PublishAot=true`, `SelfContained=true`, RID-specific publish, `OptimizationPreference=Speed`, symbols stripped into sidecar files, invariant globalization if conformance tests pass. |
| `release-minsize` | Smallest supported artifact for package managers, containers, and constrained runners. | `OptimizationPreference=Size`, diagnostics disabled, stack trace support disabled, resource-key exception messages enabled, invariant globalization, no optional network/XML/HTTP3 features unless needed. |
| `release-diagnostics` | Support artifact for bug reports and performance investigations. | Same code as `release-speed`, but keeps diagnostics, metrics/EventSource support, stack traces, and richer symbols where the runtime supports them. |
| `framework-dev` | Developer/test artifact. | Framework-dependent build with normal JIT, tiered compilation, Dynamic PGO defaults, and full diagnostics for inner-loop debugging. Not the shipped CLI. |

The default public binary is `release-speed`. `release-minsize` is never allowed to change command behavior, reports, rule results, validation behavior, or error classification; it may only reduce diagnostic richness.

### 6.2 Native AOT Publish Contract

The CLI project uses Native AOT as the primary deployment model:

- `PublishAot=true`
- `SelfContained=true`
- explicit `RuntimeIdentifier` per supported platform
- `PublishSingleFile=true` only where it adds useful SDK analysis or packaging behavior; Native AOT already produces a native executable
- `StripSymbols=true` with debug symbols published as separate artifacts
- no runtime JIT dependency, no dynamic code generation, no dynamic plugin loading
- no reflection-only serializer paths
- no dependency that emits unresolved trim, single-file, or AOT warnings

Native AOT is a closed-world contract. If a feature needs dynamic assembly loading, Reflection.Emit, expression compilation, runtime serializer discovery, or unbounded reflection over arbitrary user types, that feature is either redesigned, moved out of the Native AOT CLI, or rejected.

### 6.3 Trim and AOT Analyzer Gates

Every Picket library that can be used by the CLI sets:

- `IsAotCompatible=true`
- `EnableTrimAnalyzer=true`
- `EnableAotAnalyzer=true`
- `EnableSingleFileAnalyzer=true`

The CLI test app also enables reference verification:

- `VerifyReferenceTrimCompatibility=true`
- `VerifyReferenceAotCompatibility=true`
- detailed trimmer warnings in CI (`TrimmerSingleWarn=false`)

All ILLink/AOT warnings are errors in CI. Suppressions require a local comment, a tracking issue, and an oracle test proving the code path is safe. Broad suppressions around public APIs are not allowed.

### 6.4 Runtime Feature Switches

Picket keeps feature switches explicit so size/performance tradeoffs are reviewable.

Default candidates for all release profiles:

- `InvariantGlobalization=true`, if all path, regex, casing, TOML, report, and provider tests prove Picket only needs ordinal/invariant behavior.
- `EnableUnsafeBinaryFormatterSerialization=false`
- `EnableUnsafeUTF7Encoding=false`
- `MetadataUpdaterSupport=false`
- `XmlResolverIsNetworkingEnabledByDefault=false`
- `UseSizeOptimizedLinq=true`; hot paths must not depend on LINQ throughput.
- `Http3Support=false` unless a validator or source requires it.
- `HttpActivityPropagationSupport=false` unless diagnostics builds require it.

Profile-specific candidates:

- `DebuggerSupport=false` in `release-speed` and `release-minsize`; true only for `release-diagnostics`.
- `EventSourceSupport=false` and `MetricsSupport=false` in `release-minsize`; optional in `release-speed`; true in `release-diagnostics`.
- `StackTraceSupport=false` in `release-minsize`; considered for `release-speed` only after bug-report ergonomics are covered by structured diagnostics.
- `UseSystemResourceKeys=true` only in `release-minsize`, because stripped framework exception text hurts supportability.
- `StackTraceLineNumberSupport` is a future .NET 11+ option and is not required for the .NET 10 release plan.

Feature switches are tested as part of release validation. If disabling a switch changes compatibility, validation, or error behavior, the switch stays enabled for that profile.

### 6.5 Serialization and Configuration

Compatibility report writers remain handwritten byte writers.

For native reports and internal persistence:

- use source-generated `System.Text.Json` contexts only,
- disable reflection-based JSON serialization in AOT builds,
- declare every serialized shape explicitly,
- avoid `object`-typed JSON payloads unless every concrete type is listed in the source-generation context,
- keep JSONL writers streaming and allocation-bounded,
- prefer small custom parsers for hot compatibility paths when exact bytes matter.

TOML loading may use a parser library only if it is trim/AOT compatible with zero warnings. Otherwise Picket owns a small schema-focused parser for Gitleaks/Picket config.

### 6.6 Memory and Buffering Rules

Picket follows .NET span/memory guidance:

- synchronous hot-path APIs accept `ReadOnlySpan<byte>` / `Span<byte>`,
- async or stored buffers use `ReadOnlyMemory<byte>` / `Memory<byte>` with documented ownership,
- `IMemoryOwner<T>` ownership is explicit and disposed exactly once,
- pooled buffers come from `ArrayPool<byte>` or a narrow internal pool,
- pooled arrays are returned in `finally` blocks and cleared only when they might contain secrets,
- `stackalloc` is used only for small, bounded scratch buffers,
- line/column extraction operates on spans and does not allocate substrings in the match loop,
- secret redaction works over byte spans before any optional string projection.

No hot path allocates a `string` unless the output contract requires it.

### 6.7 File IO and Source Enumeration

Filesystem scanning is tuned by measurement, not folklore.

- Use `FileStreamOptions` with explicit access, share, buffer size, async mode, and sequential-scan policy.
- Benchmark buffer sizes per platform and file-size bucket; do not assume the default 4 KiB buffer is optimal.
- Avoid double buffering when reading a file fully into a pooled blob buffer.
- For very large files, stream in bounded windows with overlap sufficient for multiline rules and decoder boundaries.
- Memory mapping is optional and benchmark-gated; it must not increase address-space pressure or complicate archive/decoder offset mapping.
- Parallelism is bounded by IO pressure, CPU pressure, and memory budget, not just processor count.

### 6.8 GC and Runtime Configuration

Picket does not blindly tune GC. The .NET defaults remain the baseline unless benchmarks prove a profile-specific change.

- Short-lived local CLI scans default to workstation-style behavior and release memory back to the OS.
- Long-running native source scans may use a measured high-throughput profile with server GC if it improves throughput without unacceptable memory growth.
- `System.GC.ConserveMemory` is considered for `release-minsize` and container profiles, not for the default speed profile unless it wins benchmarks.
- `System.GC.RetainVM` remains false for normal CLI use.
- Container/action profiles may set heap hard limits and concurrency caps through documented runtime configuration rather than hidden code behavior.

GC settings are part of benchmark matrices: throughput, startup, peak RSS, Gen0/Gen1/Gen2 counts, pause time, and allocation rate.

### 6.9 SIMD and CPU-Specific Code

Picket prefers Scout's SIMD-aware search and regex code over new custom intrinsics.

Rules for Picket-owned SIMD:

- keep scalar fallbacks,
- use portable APIs where they are fast enough,
- use hardware intrinsics only behind `IsSupported` checks and benchmark gates,
- do not require AVX2/AVX-512/Arm64 AdvSimd in the default artifact,
- consider CPU-specific artifacts only if they produce a large measured win and packaging remains understandable,
- test Native AOT output on every supported architecture because AOT vector/intrinsic behavior is more constrained than JIT behavior.

### 6.10 ReadyToRun, JIT, and Dynamic PGO

ReadyToRun and Dynamic PGO are relevant only to non-Native-AOT builds.

- The shipped CLI is Native AOT, so it does not rely on JIT tiering or Dynamic PGO.
- Framework-dependent developer builds keep runtime defaults for tiered compilation and Dynamic PGO.
- If Picket ships any non-AOT fallback tool, ReadyToRun is benchmarked separately because it improves startup by precompiling code but increases binary size.

### 6.11 Compression and Post-Processing

Executable compression is not a default. Microsoft's single-file guidance calls out startup cost for compression-style packaging, so Picket only uses compression when a release profile proves that the smaller download is worth the startup penalty.

Post-processing is allowed for:

- signing,
- symbol splitting,
- reproducibility metadata,
- package-manager checksums,
- optional external compression of archives, not the executable startup path.

### 6.12 Measurement Gates

Performance work is accepted only with measurements.

Required gates:

- cold startup time,
- no-op scan time,
- scan throughput by source type,
- rule compile time,
- allocations per MB scanned,
- peak RSS,
- output writer throughput,
- binary size,
- compressed package size,
- first-run and warm-run CI action time,
- Native AOT publish time,
- profile-specific feature-switch diff.

Tools:

- BenchmarkDotNet for microbenchmarks and library-level comparisons,
- `dotnet-counters`, `dotnet-trace`, EventPipe, and Visual Studio profiling for framework-dependent diagnostics builds,
- OS-native profilers and allocation/RSS measurements for Native AOT artifacts,
- hyperfine-style command benchmarks for end-to-end CLI comparisons.

No optimization lands because it "should be faster." It lands because a benchmark, trace, or size report says it is faster or smaller for a Picket scenario.

### 6.13 Microsoft Guidance References

The applied guidance comes from current Microsoft Learn pages. These links are mirrored in `docs/UPSTREAM.md` with access dates and reviewed during runtime upgrades.

- [Native AOT deployment overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/)
- [Optimizing AOT deployments](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/optimizing)
- [Trimming options](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/trimming-options)
- [Prepare .NET libraries for trimming](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/prepare-libraries-for-trimming)
- [Known trimming incompatibilities](https://learn.microsoft.com/en-us/dotnet/core/deploying/trimming/incompatibilities)
- [Single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)
- [.NET runtime configuration settings](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/)
- [GC configuration settings](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/garbage-collector)
- [Globalization configuration settings](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/globalization)
- [`System.Text.Json` source generation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/source-generation)
- [Memory-related and span types](https://learn.microsoft.com/en-us/dotnet/standard/memory-and-spans/)
- [`Memory<T>` and `Span<T>` usage guidelines](https://learn.microsoft.com/en-us/dotnet/standard/memory-and-spans/memory-t-usage-guidelines)
- [SIMD-accelerated types in .NET](https://learn.microsoft.com/en-us/dotnet/standard/simd)
- [ReadyToRun deployment overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/ready-to-run)
- [.NET diagnostic tools overview](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/tools-overview)

---

## 7. Gitleaks Compatibility

### 7.1 Commands

| Command | Compatibility behavior |
|---|---|
| `picket git [repo]` | Uses the same Git patch model as Gitleaks: `git log -p -U0 --full-history --all --diff-filter=tuxdb`, additions only. `--log-opts`, `--staged`, and `--pre-commit` reproduce Gitleaks behavior, including its quoting limitations where tests depend on them. |
| `picket dir [path]` | Filesystem scan with Gitleaks traversal semantics. Aliases: `file`, `directory`. Supports `--follow-symlinks`. |
| `picket stdin` | Scans piped input with Gitleaks-compatible path/fingerprint/report behavior. |
| `picket detect` | Hidden/deprecated shim. Maps to `git`, `dir`, or `stdin` the way Gitleaks does. |
| `picket protect` | Hidden/deprecated shim. Maps to pre-commit/staged behavior. |

`--platform` accepts the Gitleaks-compatible set: empty/unknown autodetect, `none`, `github`, `gitlab`, `azuredevops`, `gitea`, and `bitbucket`. Literal `auto` is Picket-native only if added; it is not part of the Gitleaks-compatible surface.

### 7.2 Flags and Exit Codes

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

### 7.3 Config Schema

Picket implements the Gitleaks TOML schema:

- `[extend]`: `useDefault`, `path`, `disabledRules`, chain depth, merge ordering, conflict rules, and `minVersion`.
- `extend.url`: parsed and ignored in strict compatibility mode because local Gitleaks has an unimplemented URL extender. Native mode may warn.
- `[[rules]]`: `id`, `description`, `regex`, `path`, `secretGroup`, `entropy`, `keywords`, `tags`, `skipReport`, allowlists, and required/composite rules.
- Allowlists: global and per-rule, plural and deprecated singular forms, `condition`, `commits`, `paths`, `regexTarget`, `regexes`, `stopwords`, and `targetRules`.
- Validation: Picket emits the same config errors Gitleaks emits for empty allowlists, mixed singular/plural allowlists, duplicate IDs, missing regex/path, invalid capture groups, and invalid extend combinations.

The embedded compatibility ruleset is the pinned Gitleaks default ruleset only. Picket rules live in separate rule packs.

### 7.4 Regex Compatibility

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

### 7.5 Matching Semantics

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

### 7.6 Fingerprints, Ignores, Baselines

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

### 7.7 Reports

Compatibility report writers are byte-oriented golden-output components, not generic serializers.

- JSON: exact field order, escaping, indentation, omitted fields, empty-array behavior, and trailing newline behavior from the pinned Gitleaks version.
- CSV: exact header behavior, including the no-findings case and conditional `Link` column behavior.
- JUnit: exact XML shape, suite names, failure text, escaping, and indentation.
- SARIF: exact Gitleaks-compatible mode for consumers that depend on `tool.driver.name`, semantic version, fingerprints, and snippets.
- Template: Go `text/template` compatibility with the same supported safe Sprig function map as Gitleaks. Template behavior is tested with real templates.

Native reporters add JSONL, richer SARIF, TOON, HTML, GitLab code-quality, and simultaneous multi-output support.

### 7.8 Decoding, Archives, Binary Files

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

## 8. Picket-Native Best-In-Class Features

### 8.1 Rule Packs

Picket ships separate rule packs:

- `gitleaks`: exact compatibility rules,
- `picket-default`: high-confidence modern coverage,
- `picket-strict`: broader coverage with more aggressive heuristics,
- `picket-experimental`: new detectors under active tuning,
- organization-local packs.

Each rule can carry severity, confidence, examples, negative examples, tags, validation metadata, revocation metadata, documentation URL, deprecation state, and owning provider.

### 8.2 Rule QA

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

### 8.3 False-Positive Reduction

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

### 8.4 Verification

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

### 8.5 Revocation

Where provider APIs support safe self-service revocation, Picket can emit and optionally run revocation commands. Revocation is never automatic during scan. Reports include revocation availability and exact command guidance only when redaction settings allow it.

### 8.6 Credential Privilege Analysis

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

### 8.7 Blob Store and Incremental Scans

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

### 8.8 Sources

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

### 8.9 Output and Triage

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

### 8.10 CI, Hooks, and Distribution

Picket ships:

- MIT `picket-action`,
- pre-commit, pre-push, and pre-receive hooks,
- Docker images,
- Homebrew, Scoop, winget, MSI,
- `dotnet tool`,
- NuGet packages for embedding.

The GitHub Action supports annotations, SARIF upload, fetch-depth guidance, baseline handling, cache restore/save, least-privilege permissions, summary output, and explicit fail modes.

Pre-receive support handles bare repositories, quarantine environment variables, old/new ref input, timeouts, concurrency, and clear rejection messages.

### 8.11 Embeddable .NET API

`Picket.Engine`, `Picket.Rules`, and `Picket.Report` are AOT-safe NuGet packages for analyzers, MSBuild tasks, CI systems, IDE integrations, and internal security platforms.

Public APIs are documented, cancellation-aware, streaming-first, and stable across minor releases.

---

## 9. Security and Privacy Model

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

## 10. Testing Strategy

### 10.1 Compatibility Oracle

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

### 10.2 Rule Corpus

Every bundled Gitleaks rule and selected community rules are compiled through the dialect layer and tested against fixtures under both tools. Picket-native rules require positive and negative examples before release.

### 10.3 Security Tests

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

### 10.4 Performance Tests

Performance gates are scenario-specific and fair:

- Gitleaks-compatible cold scans compared to Gitleaks with equivalent flags,
- native incremental scans compared against previous Picket runs,
- verification benchmarks separated from scan-only benchmarks,
- retired tools such as Nosey Parker used only as historical datapoints, not live release gates.

Metrics include throughput, allocations, peak memory, startup time, rule compile time, cache hit rate, and report writer throughput.

### 10.5 Live Tests

Live provider tests are opt-in and isolated from the default suite. Default CI uses recorded responses and local fakes. "Zero skipped tests" applies to the required offline suite, not to intentionally opt-in live credential tests.

---

## 11. Compatibility Ledger

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

## 12. Competitive Baseline

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

## 13. Milestones

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

## 14. Documentation Deliverables

Required before v1:

- `docs/PARITY.md`: compatibility ledger,
- `docs/UPSTREAM.md`: reference pins and sync process,
- `docs/RULES.md`: rule schema, examples, validator/revocation metadata,
- `docs/VALIDATION.md`: privacy and egress model,
- `docs/REPORTS.md`: compatibility and native schemas,
- `docs/ACTION.md`: CI action behavior and security posture,
- `docs/EMBEDDING.md`: library API guide.
