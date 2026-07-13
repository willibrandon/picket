# Picket Design

**Picket is a new MIT-licensed secrets scanner for .NET: Gitleaks-compatible where compatibility is promised, Picket-native where the product should move beyond Gitleaks, and Scout-powered on the byte-oriented hot paths where Scout is the right engineering fit.**

- **Status:** Product and implementation design
- **Date:** 2026-07-05
- **Target runtime:** RID-specific `picket` release archives and RID-specific `dotnet tool` packages on .NET 10 Native AOT (`net10.0`); reusable libraries target `net9.0` and `net10.0`
- **Binary name:** `picket`; interactive report triage ships as the companion `picket-tui` executable and is also reachable through `picket tui` when the companion is installed beside `picket` or on `PATH`.
- **Root namespace:** `Picket`
- **Primary reference:** Gitleaks. Picket intentionally follows its CLI, config model, rule semantics, reports, fingerprints, and operational defaults in compatibility mode.
- **Scout libraries:** `Scout.Text.Regex`, `Scout.IO.Globbing`, and selected `Scout.IO.Ignore` APIs are used where their behavior matches the active scan profile.
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

- Command family: `picket scan ...`, `picket verify`, `picket analyze`, `picket rules check`, `picket rules test`, `picket baseline`, `picket view`, `picket tui`.
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
- interactive terminal triage for generated reports,
- first-class ignore and baseline workflows,
- SARIF/JSONL/HTML/TOON outputs,
- a free MIT GitHub Action, Azure DevOps pipeline integration, and local hooks,
- embeddable .NET libraries.

Picket is not a SaaS and does not require an account. It has no telemetry. Any feature that can send secrets or metadata to a provider API is opt-in, visibly labeled, rate limited, and covered by a documented egress model.

---

## 3. Reference Pins

The design and differential tests are pinned to upstream reference snapshots. Upgrades are deliberate, reviewed changes. Public docs and tests do not commit machine-specific clone paths; local reference repositories are discovered through environment variables or sibling clone names.

| Project | Environment variable | Default sibling clone | Role |
|---|---|---|---|
| Gitleaks | `PICKET_GITLEAKS_REPO` | `../gitleaks` | Primary compatibility oracle |
| Scout | `PICKET_SCOUT_REPO` | `../scout` | Regex, globbing, ignore, and Native AOT behavior reference |
| TruffleHog | `PICKET_TRUFFLEHOG_REPO` | `../trufflehog` | Verification, sources, and analyze reference |
| Kingfisher | `PICKET_KINGFISHER_REPO` | `../kingfisher` | Validation breadth, revocation, access-map, reporting reference |
| Nosey Parker | `PICKET_NOSEYPARKER_REPO` | `../noseyparker` | Historical datastore/rule-QA/performance reference |
| .NET Runtime | `PICKET_DOTNET_RUNTIME_REPO` | `../runtime` | Native AOT/runtime implementation reference |

`docs/UPSTREAM.md` records exact commits, supported upstream versions, known README/code divergences, and the command lines used by oracle tests. Repository utilities under `scripts/` are .NET file-based apps with documented build/run/cache guidance in `scripts/README.md`. `scripts/Capture-UpstreamPins.cs` refreshes the pin table from local clones. `scripts/Capture-GitleaksOracle.cs` captures pinned Gitleaks reports plus stdout, stderr, command arguments, working directory, binary version, and clone metadata under ignored `artifacts/oracles/gitleaks` output. `scripts/Capture-CompatibilityOracle.cs` captures a side-by-side Gitleaks/Picket bundle with report hashes and exit-code comparisons under ignored `artifacts/oracles/compatibility` output. `scripts/Capture-GitHubSecretScanningOracle.cs` captures sanitized hosted GitHub secret-scanning alert metadata, including alert type and optional location data but never raw secret values, under ignored `artifacts/oracles/github-secret-scanning` output. `scripts/Compare-GitHubSecretScanningOracle.cs` compares that hosted-alert metadata to a Picket native JSONL report by mapped alert type and location without writing raw secrets. Oracle fixtures that depend on relative paths use `-WorkingDirectory <fixture-root>` with relative `-Source`, `-Config`, baseline, and template arguments so committed golden reports never encode a developer's local checkout path. `scripts/Promote-CompatibilityOracle.cs` promotes reviewed captures into normalized, redacted golden fixtures under `tests/fixtures/oracles`. For example, Gitleaks' current code default for `--max-decode-depth` is `5`; if upstream docs say otherwise, Picket follows the code in compatibility tests and records the discrepancy.

---

## 4. Scout Usage Principles

Scout is a core advantage, but Picket only uses Scout APIs where their semantics match the scanner contract.

The relevant Scout APIs are `Scout.Text.Regex`, `Scout.IO.Globbing`, and `Scout.IO.Ignore`.

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

The RID-specific release archive CLI is Native AOT and single-file/self-contained per RID. Picket reuses Scout's build and packaging patterns, but it does not assume Unix raw-argv handling and Windows wide-argv handling are identical. Path/argument byte behavior is tested per platform.

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
  +-- Picket.Docs              - static documentation generator and reference-site build inputs
```

### 5.1 CLI Command Model

The CLI command surface is built with `System.CommandLine` 2.0.9. The command tree is the runtime source of truth for command names, aliases, argument names, option names, option aliases, generated help, and shell suggestions.

Design rules:

- root help is a command index; command-specific options are shown on command-local help,
- command and option names are lowercase kebab-case unless strict Gitleaks compatibility already requires a spelling,
- short aliases are limited to established compatibility aliases and common CLI expectations,
- `System.CommandLine` async actions are used so cancellation can flow through `ParseResult.InvokeAsync`,
- command-local help can append small Picket-specific sections such as supported report import formats, but the main layout stays generated by `System.CommandLine`,
- shell suggestions use the built-in `[suggest]` directive and the normal `dotnet-suggest` integration path,
- response-file expansion is disabled because response files are trusted-input artifacts and Picket must not unexpectedly read extra files during secret-scanning invocations,
- POSIX short-option bundling is disabled so `-abc` does not silently reinterpret Gitleaks-compatible short flags,
- hidden deprecated compatibility shims are hidden from root help and completions but still render direct command help,
- commands that still delegate to compatibility-preserving handlers allow unmatched tokens during execution so the existing Picket/Gitleaks error paths, exit codes, and multi-value handling remain in control,
- help invocations use strict generated presentation so wrapper-only "additional arguments" sections do not appear in normal help output.

The implementation can later move more handlers to typed `ParseResult.GetValue(...)` binding, but only after differential tests prove that unknown-option errors, repeated options, optional values such as `--redact[=n]`, `--` handling, and Gitleaks-compatible exit codes remain stable.

Hot-path constraints:

- `ReadOnlySpan<byte>` first,
- stable line/column and byte offset mapping,
- pooled buffers,
- no LINQ in match loops,
- no reflection-dependent runtime behavior required for Native AOT,
- explicit allocation and throughput tests.

---

## 6. Performance, Size, and AOT Strategy

This section applies current Microsoft .NET deployment, trimming, Native AOT, GC, memory, SIMD, and diagnostics guidance to Picket. The runtime clone resolved from `PICKET_DOTNET_RUNTIME_REPO` or `../runtime` is a reference for implementation details and Native AOT defaults, but public behavior follows documented SDK/runtime contracts.

### 6.1 Release Profiles

Picket ships multiple publish profiles because "fastest" and "smallest" are not the same artifact.

| Profile | Purpose | Defaults |
|---|---|---|
| `release-speed` | Primary CLI artifact. Fast startup and fastest scan throughput while remaining small. | `PublishAot=true`, `SelfContained=true`, RID-specific publish, `OptimizationPreference=Speed`, symbols stripped into sidecar files except current macOS RIDs, macOS native debug symbols disabled in public speed builds while runtime packs carry transient Swift module-cache debug paths, invariant globalization if conformance tests pass. |
| `release-minsize` | Smallest supported artifact for package managers, containers, and constrained runners. | `OptimizationPreference=Size`, diagnostics disabled, stack trace support disabled, resource-key exception messages enabled, invariant globalization, symbols stripped except current macOS RIDs, macOS native debug symbols disabled, no optional network/XML/HTTP3 features unless needed. |
| `release-diagnostics` | Support artifact for bug reports and performance investigations. | Same code as `release-speed`, but keeps diagnostics, metrics/EventSource support, stack traces, and richer symbols where the runtime supports them. |
| `framework-dev` | Developer/test artifact. | Framework-dependent build with normal JIT, tiered compilation, Dynamic PGO defaults, and full diagnostics for inner-loop debugging. Not the shipped CLI. |

The default public binary is `release-speed`. `release-minsize` is never allowed to change command behavior, reports, rule results, validation behavior, or error classification; it may only reduce diagnostic richness.

### 6.2 Native AOT Publish Contract

The CLI project uses Native AOT as the primary deployment model:

- `PublishAot=true`
- `SelfContained=true`
- explicit `RuntimeIdentifier` per supported platform
- public release RIDs cover Windows x64/Arm64, Linux glibc x64/Arm64, Linux musl x64/Arm64, and macOS x64/Arm64
- `PublishSingleFile=true` only where it adds useful SDK analysis or packaging behavior; Native AOT already produces a native executable
- `StripSymbols=true` with debug symbols published as separate artifacts, except current macOS RIDs temporarily use `StripSymbols=false`, `DebugType=none`, `DebugSymbols=false`, and `NativeDebugSymbols=false` for speed/minsize builds while the runtime pack carries transient Swift module-cache debug paths
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
- Local files larger than 100,000 bytes are streamed through pooled fragments instead of being materialized as one managed array. Strict compatibility uses Gitleaks' 100,000-byte primary fragment and reads ahead by at most 25,000 bytes to a blank-line boundary, with no overlap between fragments. Native filesystem and baseline scans inspect the same fragments plus the final 64 KiB of the preceding fragment, expanded backward to a line boundary when available, and deduplicate overlap findings by rule, absolute location, evidence, and decode path. This preserves Gitleaks' hard-boundary behavior on the compatibility surface while allowing native rules and decoders to detect ordinary cross-boundary secrets.
- Fragment positions retain the original one-based line and column. Reports and native cache entries use the SHA-256 identity of the complete file rather than a fragment hash. The first 100,000 bytes provide the Gitleaks-compatible binary probe; safe-boundary read-ahead bytes do not affect classification. Native content-hash ignores and cache lookups prehash the bounded stream. When scanning continues after that prehash, Picket rejects a file that changes before its scan completes.
- Memory mapping is optional and benchmark-gated; it must not increase address-space pressure or complicate archive/decoder offset mapping.
- Filesystem and baseline scans evaluate files concurrently when a batch contains enough independent work. The maximum degree starts with the smaller of the batch size and `Environment.ProcessorCount`, so process affinity, job-object limits, and container CPU quotas are honored.
- Picket applies the same `GC.GetGCMemoryInfo()` pressure bands used by .NET's shared array pool: low pressure keeps the effective CPU degree, medium pressure halves it, and high pressure scans serially.
- Findings are merged in deterministic source order. Checkpointed scans retain ordered serial commits so every durable low-water mark represents a complete prefix of the source manifest.

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

The repository includes `benchmarks/Picket.Benchmarks` for engine-level BenchmarkDotNet scenarios. It must cover native default rules, strict Gitleaks-compatible rules, focused hot rules, rule compilation, and current GitHub-alert parity fixtures before performance changes are called complete.

No optimization lands because it "should be faster." It lands because a benchmark, trace, or size report says it is faster or smaller for a Picket scenario.

Competitive performance work is a late-project hardening gate, not an early implementation driver. After the target feature set is complete, Picket compares end-to-end speed against Gitleaks, TruffleHog, Kingfisher, and other relevant local references only where the comparison can be made fair:

- same repository, fixture, commit range, or source payload,
- equivalent scan mode, rule scope, path filters, redaction, report format, and output destination,
- verification, source enumeration, archive traversal, decoding, and history scanning either disabled on both sides or measured as separate scenarios,
- cold-cache and warm-cache runs reported separately,
- tool versions, commit SHAs, command lines, hardware, OS, filesystem, .NET SDK, and runner type recorded with the results.

Optimization comes near the end of implementation after behavior is feature complete. Earlier performance work is limited to regressions that block correctness, feasibility, or CI reliability.

If profiling shows a material bottleneck in a Scout NuGet package, Picket creates a concise Scout issue with a minimal reproducer, benchmark or trace evidence, exact package version, command line, input shape, and expected impact. If the Scout issue is critical enough that Picket cannot reasonably proceed without it, Picket work pauses and the maintainer is notified so Scout can be fixed first.

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
- [Testing in .NET](https://learn.microsoft.com/en-us/dotnet/core/testing/)
- [MSTest overview](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-mstest-intro)
- [MSTest SDK configuration](https://learn.microsoft.com/en-us/dotnet/core/testing/unit-testing-mstest-sdk)
- [Microsoft.Testing.Platform overview](https://learn.microsoft.com/en-us/dotnet/core/testing/microsoft-testing-platform-intro)
- [System.CommandLine overview](https://learn.microsoft.com/en-us/dotnet/standard/commandline/)
- [System.CommandLine syntax overview](https://learn.microsoft.com/en-us/dotnet/standard/commandline/syntax)
- [System.CommandLine parse and invoke guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/how-to-parse-and-invoke)
- [System.CommandLine parsing and validation guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/how-to-customize-parsing-and-validation)
- [System.CommandLine parser configuration guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/how-to-configure-the-parser)
- [System.CommandLine help customization guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/how-to-customize-help)
- [System.CommandLine tab completion guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/how-to-enable-tab-completion)
- [System.CommandLine command-line design guidance](https://learn.microsoft.com/en-us/dotnet/standard/commandline/design-guidance)
- [System.CommandLine 2.0.0-beta5+ migration guide](https://learn.microsoft.com/en-us/dotnet/standard/commandline/migration-guide-2.0.0-beta5)

---

## 7. Gitleaks Compatibility

### 7.1 Commands

| Command | Compatibility behavior |
|---|---|
| `picket git [repo]` | Uses the same Git patch model as Gitleaks: `git log -p -U0 --full-history --all --diff-filter=tuxdb`, additions only. `--staged` and `--pre-commit` reproduce Gitleaks behavior. `--log-opts` accepts plain revision ranges and a small allowlist of safe revision-filter options; output, pager, external-diff, and unknown option-shaped tokens are rejected before `git` starts. |
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

Native commands and compatibility commands selected with `--profile picket` use Picket precedence:

1. `--config`
2. `PICKET_CONFIG`
3. `PICKET_CONFIG_TOML`
4. `GITLEAKS_CONFIG`
5. `GITLEAKS_CONFIG_TOML`
6. `{target}/.gitleaks.toml`
7. embedded Picket default config

The embedded Picket default config extends the embedded Gitleaks default config and layers Picket-native rule packs on top. Native defaults may disable inherited broad rules when a Picket-owned replacement lowers false positives without changing strict compatibility behavior; these replacements are recorded in `docs/PARITY.md`. Explicit, environment, and target-local configs replace the embedded native default unless those configs opt into `[extend] useDefault = true`.

Exit codes:

- `0`: no leaks and no fatal error,
- configured `--exit-code` value, default `1`: leaks found,
- `1`: scan error or partial scan,
- `126`: unknown flag.

Reports are written on partial scans when Gitleaks writes them.

### 7.3 Config Schema

Picket implements the Gitleaks TOML schema:

- `[extend]`: `useDefault`, `path`, `disabledRules`, chain depth, merge ordering, conflict rules, and `minVersion`.
- File-backed config loads, including extended configs, are capped at 10 MiB per file to keep untrusted config paths from becoming unbounded reads.
- Strict compatibility keeps Gitleaks/Viper local `[extend] path` behavior: absolute paths are accepted and relative paths resolve from the process current working directory. This is a trusted config boundary, not scan-root confinement.
- `extend.url`: parsed and ignored in strict compatibility mode because local Gitleaks has an unimplemented URL extender. Native mode may warn.
- `[[rules]]`: `id`, `description`, `regex`, `path`, `secretGroup`, `entropy`, `keywords`, `tags`, `skipReport`, allowlists, and required/composite rules.
- Allowlists: global and per-rule, plural and deprecated singular forms, `condition`, `commits`, `paths`, `regexTarget`, `regexes`, `stopwords`, and `targetRules`.
- Validation: Picket emits the same config errors Gitleaks emits for empty allowlists, mixed singular/plural allowlists, duplicate IDs, missing regex/path, invalid capture groups, and invalid extend combinations.

The embedded compatibility ruleset is the pinned Gitleaks default ruleset only. Picket rules live in separate rule packs. The native default profile layers `picket-default` over `gitleaks`; strict compatibility loads only `gitleaks`.

### 7.4 Regex Compatibility

Gitleaks rules are Go `regexp` patterns. Picket compiles them to Scout `ByteRegex` through a dialect layer.

The dialect layer defines behavior for:

- UTF-8 and invalid-byte handling,
- `.` and newline semantics,
- anchors and multiline flags,
- named captures,
- POSIX classes,
- Go's ASCII-only `\d`, `\s`, `\w`, `\b`, and complementary forms while preserving explicit Unicode literals, properties, and case folding,
- case-insensitive matching,
- secret-group extraction,
- unsupported constructs.

Malformed UTF-8 is evaluated as one `U+FFFD` replacement rune per invalid byte, matching Go string iteration, while size limits, blob hashes, report locations, and fingerprints remain anchored to the original bytes.

Every default Gitleaks rule and selected community config is compiled and run through both real Gitleaks and Picket in the differential suite. The design goal is not "roughly RE2-like"; it is tested Gitleaks rule behavior.

### 7.5 Matching Semantics

Compatibility matching reproduces Gitleaks' observable algorithm:

- keyword prefilter decides candidate rules,
- rules with no keywords still run,
- each candidate rule executes independently,
- all matches for each rule are considered,
- captures are extracted per rule,
- `secretGroup = 0` uses the first non-empty capture group when Gitleaks does,
- a finding whose rule ID contains `generic` yields to a differently named non-generic rule when both findings have the same start line and commit and the non-generic secret contains the generic secret,
- entropy uses strict `>` comparison and reproduces Gitleaks' Unicode behavior by counting decoded runes against the Go string's UTF-8 byte length,
- allowlists run in the same order and against the same targets,
- skipped rules and `skipReport` follow Gitleaks.

Picket-native modes can add richer confidence scoring and cross-rule correlation, but compatibility mode does not.

### 7.6 Fingerprints, Ignores, Baselines

Compatibility fingerprints:

- Git: `{commit}:{file}:{rule-id}:{startLine}`
- Dir: `{file}:{rule-id}:{startLine}`
- Stdin: `:{rule-id}:{startLine}` because pinned Gitleaks reports an empty file path for `stdin` input.
- Paths normalize to `/`.
- Archive provenance uses a stable inner-path separator compatible with reports and ignore parsing.

`.gitleaksignore` behavior:

- blank lines and comments ignored,
- 3-part and 4-part fingerprints accepted,
- paths normalized,
- commit-less ignore checked before commit-qualified ignore for git findings.

Inline suppression honors `gitleaks:allow` unless `--ignore-gitleaks-allow` is set.

Baselines compare the same fields as Gitleaks. Fingerprint is deliberately not the baseline key.

Native mode adds `.picketignore`, glob ignores, content-hash ignores, stale-ignore auditing, and stable fingerprints. After successful local native scans and baseline creation, stale `sha256:` entries that did not match any scanned file produce stderr warnings with the ignore-file location when known. These features never silently affect strict Gitleaks compatibility.

### 7.7 Reports

Compatibility report writers are byte-oriented golden-output components, not generic serializers.

- JSON: exact field order, escaping, indentation, omitted fields, empty-array behavior, and trailing newline behavior from the pinned Gitleaks version.
- CSV: exact header behavior, including the no-findings case and conditional `Link` column behavior. Native CSV neutralizes spreadsheet formula prefixes in finding-controlled cells, including `=`, `+`, `-`, `@`, tab, and carriage return; strict compatibility CSV preserves the pinned Gitleaks CSV bytes.
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

Native decoding treats percent, Unicode, hex, base64, and deterministic C# string-literal concatenations as bounded candidate transforms with original-offset remapping. Hex and base64 candidates are probed once per maximal token; failed long tokens are skipped as a unit so attacker-controlled encoded-looking text cannot force quadratic decoder retries. C# concatenation transforms are native-only, limited to `.cs` inputs, require literal-only `string.Concat(...)` calls or binary `+` literal chains, and report `csharp-string-concat` in the decode path.

For local files, compatibility large-file chunking is the pinned Gitleaks 100,000-byte primary buffer with up to 25,000 bytes of blank-line read-ahead and no overlap. Native scans add the bounded line-aligned overlap described in section 6.7. Both modes check cancellation between bounded reads and match loops, preserve absolute source positions, and avoid the managed single-array size limit.

Native mode adds stricter archive-safety controls: decompressed byte caps, entry count caps, recursion caps, compression-ratio checks, cooperative timeouts during source enumeration and archive reads, path traversal protection, temp-file policy, and clear diagnostics. Zstandard decoding also caps the native decoder window before expansion; an uncapped target uses a 64 MiB window ceiling. Native directory, git, verify, analyze, and baseline workflows scan first-level archives by default and cap archive enumeration at depth 1, 4096 entries, 512 decimal MB of decompressed archive payload, and a 1000:1 archive expansion ratio; `--max-archive-depth 0` disables archive traversal, and `--max-archive-entries 0`, `--max-archive-megabytes 0`, and `--max-archive-ratio 0` disable those caps for trusted inputs. Linux musl CI and release jobs execute each published scanner against a generated zstandard fixture before packaging.

---

## 8. Picket-Native Best-In-Class Features

### 8.1 Rule Packs

Picket ships separate rule packs:

- `gitleaks`: exact compatibility rules,
- `picket-default`: high-confidence modern coverage, initially including AWS access key ID plus secret access key pairs, Azure Storage connection strings with `AccountKey` values, credentialed database connection URLs, Google API keys, GCP service account key JSON, and GitHub App, OAuth, refresh, fine-grained personal access, and classic personal access tokens,
- `picket-strict`: broader coverage with more aggressive heuristics,
- `picket-experimental`: new detectors under active tuning,
- organization-local packs.

Native `picket-*` rule packs do not inherit Gitleaks compatibility global allowlists. Compatibility rules keep those allowlists, but native hosted-scanner parity rules must not be suppressed by broad Gitleaks stopwords intended for a different contract.

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

`picket rules test <rule> [--] <input>` supports interactive authoring with Picket-native config precedence by default, Scout byte-regex validation, decode and target-size controls, optional redaction, report-path inference, and the same native report formats as `scan`. `--print-config` emits the resolved selected config after extends, profile selection, and rule-pack layering.

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

`p(random)` is implemented by the versioned `picket-random-v1` logistic model described in [Randomness Scoring](randomness.md). Its deterministic synthetic corpus, independent holdout metrics, fixed coefficients, six-decimal quantization, stable thresholds, and reproduction command are committed with the scanner. Native rules opt into suppression with an explicit `randomnessThreshold`; rules without one receive explainable report metadata without losing findings. Strict Gitleaks compatibility never runs or applies this model.

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
- provider validators implement a narrow contract with provider ID, version, endpoint, support check, cancellation, and non-secret result reasons,
- the live verifier evaluates endpoint policy before any provider callback, returns `skipped` for unsupported findings, and never treats cached results as a bypass for current endpoint policy,
- persistent validation cache keys use provider, validator version, rule ID, normalized endpoint, and SHA-256 secret hash; entries are authenticated with a per-user HMAC key, and cache files never store raw secrets, raw matches, or endpoint query strings,
- initial GitHub validator checks supported GitHub token rules against the REST `/user` endpoint, supports explicit endpoint override for enterprise hosts, maps accepted/rejected/rate-limited provider responses to native validation states, and exposes non-secret identity/scope/resource metadata for analysis when GitHub returns it,
- global and per-provider rate limits, including a default same-provider pacing interval and native CLI overrides in milliseconds,
- retries with cache-poisoning protection,
- proxy and endpoint override support,
- TLS mode controls, with platform defaults by default and a TLS 1.2-or-later provider mode but no certificate-verification bypass,
- SSRF protection blocking loopback, private, link-local, metadata-service, and non-public redirect targets by default,
- max response length and redaction,
- audit events showing which provider endpoints were contacted.

### 8.5 Revocation

Where provider APIs support safe self-service revocation, Picket can emit and optionally run revocation commands. Revocation is never automatic during scan. Analysis reports include `revocationAvailable`, `revocationCommands`, and `revocationGuidance`; command templates are emitted only when Picket can build them from non-secret identifiers such as an AWS access key ID, Azure Storage account name, or GCP service-account key ID, or with explicit placeholders such as GitHub's credential revocation API token parameter. Provider workflows that cannot be safely expressed as a command still set revocation availability and explain the manual workflow without raw secret values.

### 8.6 Credential Privilege Analysis

`picket analyze` maps what an active credential can access. It is inspired by TruffleHog analyze and Kingfisher access-map work, not claimed as unique.

Initial targets:

- GitHub and GitHub App tokens,
- AWS access keys,
- GCP service account keys,
- Azure credentials,
- GitLab tokens,
- database connection strings,
- Sourcegraph access tokens,
- common SaaS API tokens.

Analysis output is separate from scan output and optimized for incident response: identity, scopes, reachable resources, risk summary, recommended rotation/revocation steps, revocation command templates where safe, and evidence.

### 8.7 Blob Store and Incremental Scans

`Picket.Store` content-addresses every scanned blob and records provenance separately.

Design requirements:

- SHA-256 blob identity,
- cache entries use the narrowest safe address discriminator: content-only for path-independent scans, file extension when extension-specific native decoders can run, and full logical path for path-sensitive rules or path allowlists,
- authenticated scan-cache entries with per-user HMAC keys outside the cache root so tampered entries and untrusted imports cannot suppress findings,
- schema versioning and migrations,
- rule-pack/config/version and scan-behavior cache invalidation,
- decode/archive-derived blob lineage,
- concurrent CI-safe locking,
- secret-hash-only scan cache storage by default, explicit raw mode for trusted private replay, owner-only cache permissions on Unix-like systems and Windows, and storage mode participation in the cache key,
- GC and retention policy,
- portable cache export/import with per-entry decompressed-size caps, archive entry-count caps, and aggregate imported-byte caps,
- provenance-preserving reports.

Dedup skips duplicate matching work where rule and decoder semantics make it safe, but it does not collapse compatibility reports. If Gitleaks would report the same blob at multiple commits/paths, compatibility mode still reports every provenance.

### 8.8 Sources

Native source support:

- filesystem,
- git history,
- stdin,
- archives,
- GitHub repos, orgs, users, PRs, issues, gists, releases, and Actions artifacts,
- GitLab groups/projects/MRs/snippets/artifacts,
- Gitea repositories,
- Bitbucket Cloud and Bitbucket Data Center repositories,
- Azure DevOps Services and Azure DevOps Server sources, including Azure Repos Git repositories, projects, organizations, pull requests, wiki repositories, build artifacts, pipeline logs, release artifacts, and Azure Artifacts NuGet packages where APIs expose them safely,
- S3, GCS, Azure Blob,
- Docker/OCI images and tarballs.

Every remote source requires an auth, pagination, retry, rate-limit, checkpoint, permission, and redaction model. Provider endpoint overrides are required for enterprise/self-hosted use.

Remote scan checkpointing is explicit native behavior through `--checkpoint <path>`. Picket binds a checkpoint to both the matching-behavior fingerprint and a SHA-256 manifest of the complete ordered source snapshot. Native source files use that deterministic path order whether checkpointing is enabled or not. A retry re-enumerates the source and verifies the manifest before restoring any prior finding. Source or scanner changes fail closed; `--checkpoint-reset` is the explicit instruction to discard incompatible state and start again.

The checkpoint is an append-only low-water journal. A file advances the low-water mark only after it has been skipped by a deterministic filter, restored from the scan cache, or scanned successfully. Each record includes the preceding encrypted-record hash, so removal or reordering is detected. A truncated final record is treated as uncommitted work and rescanned. Raw findings needed to produce a complete resumed report are authenticated and encrypted with a per-user key stored outside the checkpoint location. Checkpoint and lock files are owner-only, concurrent writers are excluded, symbolic-link state files are rejected, and checkpoint size is bounded.

Default repository ignores cover `*.checkpoint` and `*.checkpoint.lock` so resumable incident state is not committed accidentally.

Picket retains checkpoint state after cancellation, timeout, source-file failure, validation failure, or report-write failure. It removes state only after every requested report has been written successfully. Redaction, baseline suppression, validation-result filters, and live verification run again after restoration, so a retry may safely change those output-stage choices. Strict Gitleaks-compatible commands do not accept checkpoint options.

The source-manifest baseline deliberately replays listing and bounded downloads before it trusts a checkpoint. Provider-specific continuation cursors may reduce that replay only when they preserve the same immutable-manifest validation and post-processing low-water invariant; a pagination token alone is never evidence that an item was scanned.

Container image scanning is native Picket behavior, not Gitleaks compatibility behavior.

| Source | Option | Behavior |
| --- | --- | --- |
| Docker archive | `--docker-archive <path>` | Scans a Docker image archive produced by `docker save`. |
| OCI image layout | `--oci-archive <path>` | Scans a local OCI image-layout archive. |
| OCI Distribution registry | `--registry-image <name>` | Pulls one tagged or digest-pinned OCI/Docker image through the registry v2 API. Docker Hub shorthand such as `ubuntu` resolves to `docker.io/library/ubuntu:latest`. |

Picket treats each image as a source envelope. It scans manifests and configs, expands tar, gzip, and zstd layers through the shared archive safety caps, and retains deleted or overwritten content from earlier layers because secret history remains relevant. Local provenance includes the archive and nested layer path, such as `docker-archive/image.tar!layer/layer.tar!app/settings.txt`.

Registry options:

| Purpose | Options | Contract |
| --- | --- | --- |
| Endpoint | `--registry-endpoint`, `--registry-auth-endpoint` | Overrides the image-derived registry endpoint and, when needed, explicitly trusts a bearer-token service. HTTPS is required unless insecure source endpoints are explicitly allowed. |
| Authentication | `--registry-token-env` or `--registry-username-env` with `--registry-password-env` | Reads a pre-issued bearer token or Basic username/password/PAT from environment variables. Anonymous pull is the default. Credential values never appear in arguments, reports, warnings, or status text. |
| Platform | `--registry-platform os/architecture[/variant]` | Selects one platform from an image index. Omitting it scans every supported manifest in the bounded index. Common `x64`, `x86_64`, and `aarch64` aliases normalize to OCI architecture names. |
| Image transfer cap | `--registry-max-image-megabytes` | Caps aggregate unique manifest, config, and layer bytes. The default is 512 decimal MB and the value must be positive. |

Registry behavior and security rules:

- Only exact image references are resolved. Picket does not enumerate registry catalogs or tags.
- OCI image manifests/indexes and Docker schema 2 manifests/lists are supported. Schema 1 and unrelated artifact manifests are skipped.
- Descriptor and `Docker-Content-Digest` SHA-256 values are verified before content is scanned or expanded.
- Standard OCI distributable and nondistributable tar, gzip, and zstd layer media types are recognized, together with Docker uncompressed, gzip, and foreign gzip layer media types.
- Layer bytes are requested from the registry blob endpoint. Descriptor-provided external URLs are not followed.
- Failures warn and continue across independently verifiable manifests and layers. A missing config does not suppress layers when platform selection is already known.
- A bearer challenge may acquire a pull-scoped token. Basic credentials reach only the registry host, its subdomains, Docker Hub's documented auth host, or an explicit `--registry-auth-endpoint`.
- Blob downloads follow at most one safe HTTP redirect. Same-origin requests may retain registry authorization; cross-origin redirects never receive credentials.
- Endpoint checks run before the first request and at connect time. Private, loopback, link-local, and metadata destinations remain blocked unless the user explicitly allows non-public source endpoints.
- Manifest responses are capped at 10 decimal MB, each remote object at 100 decimal MB by default, and streamed reads enforce the cap when `Content-Length` is absent or understated.
- Manifest count, layer count, aggregate image bytes, archive entries, decompressed bytes, expansion ratio, nested depth, target bytes, timeout, and cancellation all have bounded enforcement. Registry entry, decompressed-byte, and ratio caps cannot be disabled while layer traversal is enabled; depth zero provides an explicit metadata-only mode.
- Registry provenance includes the normalized image name, requested tag or digest, resolved root digest, descriptor digest, and nested layer path. Tag scans therefore remain attributable to immutable content.

Container source flags cannot be combined with source-host or object-store enumeration flags because a native scan has one source provider.

Azure Blob source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented Azure Blob entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Container blobs | `--azure-blob-endpoint`, `--azure-blob-container`, `--azure-blob-token-env`, `--azure-blob-token-kind` | Lists blobs in one container and downloads selected blob bytes. Bearer tokens are sent in the Authorization header; SAS credentials are appended to provider request query strings after being read from the environment. |
| Container prefix | `--azure-blob-prefix` | Limits listing to blob names with the supplied prefix. |

Azure Blob source safety rules:

- Endpoint safety checks run before the first request and again at connect time.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- Blob listing uses `maxresults=5000` and follows `NextMarker` until empty.
- Blob listing stops at a 1,000-page safety limit with a warning.
- Metadata XML responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- Remote downloads use a 100 decimal MB default cap.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote Azure Blob sources reject zero because remote HTTP bodies are always bounded.
- Oversized blobs are skipped before download when Azure Blob Storage returns a content length and are capped during streaming even when content length is missing or understated.

S3 source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented S3 entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Bucket objects | `--s3-bucket`, `--s3-region`, `--s3-access-key-id-env`, `--s3-secret-access-key-env`, `--s3-session-token-env` | Lists objects in one bucket with SigV4-signed REST requests and downloads selected object bytes. The access key ID, secret access key, and optional session token are read from environment variables. |
| Bucket prefix | `--s3-prefix` | Limits listing to object keys with the supplied prefix. |
| S3-compatible endpoint | `--s3-endpoint` | Uses an explicit S3 or S3-compatible endpoint while still signing requests with the supplied region. |

S3 source safety rules:

- Endpoint safety checks run before the first request and again at connect time.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- Object listing uses `ListObjectsV2` with `max-keys=1000` and follows `NextContinuationToken` until empty.
- Object listing stops at a 1,000-page safety limit with a warning.
- Metadata XML responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- Remote downloads use a 100 decimal MB default cap.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote S3 sources reject zero because remote HTTP bodies are always bounded.
- Oversized objects are skipped before download when S3 returns a size and are capped during streaming even when content length is missing or understated.
- The secret access key is used only to compute SigV4 signatures and is not logged. Temporary session tokens are sent in `x-amz-security-token` and are not logged.

GCS source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented GCS entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Bucket objects | `--gcs-bucket`, `--gcs-token-env` | Lists objects in one bucket through the Cloud Storage JSON API and downloads selected object bytes. The OAuth bearer token is read from an environment variable. |
| Bucket prefix | `--gcs-prefix` | Limits listing to object names with the supplied prefix. |
| Requester Pays | `--gcs-user-project` | Sends a requester-pays billing project as `userProject` on list and download requests. |
| GCS-compatible endpoint | `--gcs-endpoint` | Uses an explicit Cloud Storage JSON API endpoint. |

GCS source safety rules:

- Endpoint safety checks run before the first request and again at connect time.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- Object listing uses `maxResults=1000`, `projection=noAcl`, and follows `nextPageToken` until empty.
- Object listing stops at a 1,000-page safety limit with a warning.
- Metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- Remote downloads use a 100 decimal MB default cap.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote GCS sources reject zero because remote HTTP bodies are always bounded.
- Oversized objects are skipped before download when GCS returns a size and are capped during streaming even when content length is missing or understated.
- Bearer tokens are sent only in the Authorization header and are not logged.

GitLab source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented GitLab entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Project repository files | `--gitlab-project`, `--gitlab-ref`, `--gitlab-token-env`, `--gitlab-api-endpoint` | Scans a GitLab project path, numeric project ID, or project URL at a branch, tag, or commit. Empty `--gitlab-ref` uses the project default branch. |
| Group project repositories | `--gitlab-group`, `--gitlab-include-subgroups`, `--gitlab-ref`, `--gitlab-token-env`, `--gitlab-api-endpoint` | Lists projects in a GitLab group with `per_page=100` and scans each project repository. Subgroup projects are included only when `--gitlab-include-subgroups` is set. Empty `--gitlab-ref` uses each project's default branch when GitLab returns it, falling back to project metadata when needed. |
| Merge request source head | `--gitlab-project`, `--gitlab-merge-request` | Resolves the merge request through the project merge requests API, scans `diff_refs.head_sha` when available, falls back to `sha` and then `source_branch`, and switches to `source_project_id` for forked merge requests. |
| Project snippets | `--gitlab-project`, `--gitlab-include-snippets` | Lists project snippets with `per_page=100` and downloads raw snippet content through the project snippets API. Snippets are additive to repository file scans and cannot be combined with merge request source-head scans. |
| Project job logs | `--gitlab-project`, `--gitlab-include-job-logs` | Lists project jobs with `per_page=100` and downloads selected job trace logs through the Jobs API. Job logs are additive to project and group repository scans and cannot be combined with merge request source-head scans. |
| Project job artifacts | `--gitlab-project`, `--gitlab-include-job-artifacts` | Lists project jobs with `per_page=100`, downloads jobs that advertise an artifact archive, and expands archive entries through Picket archive limits. Job artifacts are additive to project and group repository scans and cannot be combined with merge request source-head scans. |
| Pipeline job logs and artifacts | `--gitlab-project`, `--gitlab-pipeline-id`, `--gitlab-include-job-logs`, `--gitlab-include-job-artifacts` | Lists jobs through the selected pipeline's jobs API and downloads trace logs or artifact archives for that pipeline only. Pipeline-scoped scans are project-scoped and cannot be combined with group or merge request scans. |
| Generic package files | `--gitlab-project` or `--gitlab-group`, `--gitlab-include-packages` | Lists generic packages with `package_type=generic`, lists each package's files, downloads each package file through the generic package registry endpoint, and expands archive files through Picket archive limits. Package files are additive to project and group repository scans and cannot be combined with merge request source-head scans. |

GitLab API flow:

| Source | API behavior |
| --- | --- |
| Group projects | Lists projects through the GitLab group projects API. `include_subgroups=true` is sent only when requested. |
| Project metadata | Resolves the default branch for project scans. |
| Merge request metadata | Resolves the source project and source ref for merge request scans. |
| Repository tree | Lists repository blobs with recursive tree enumeration and `per_page=100`. |
| Raw repository files | Downloads file bytes through the raw repository file endpoint. |
| Project snippets | Lists project snippets with page-based pagination and downloads raw snippet content through the project snippets API. |
| Project jobs | Lists project jobs with `per_page=100`, follows GitLab REST pagination, and downloads trace logs or job artifact archives only when their explicit flags are set. |
| Pipeline jobs | Lists jobs for one project pipeline with `per_page=100`, follows GitLab REST pagination, and downloads trace logs or job artifact archives only when their explicit flags are set. |
| Generic package files | Lists project packages with `package_type=generic` and `per_page=100`, lists package files through the packages API, then downloads each file through the generic package registry route documented by GitLab. |

GitLab source safety rules:

- Endpoint safety checks run before the first request.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- GitLab REST pagination stops at a 1,000-page safety limit with a warning.
- Remote downloads use a 100 decimal MB default cap.
- Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote GitLab sources reject zero because remote HTTP bodies are always bounded.
- Oversized tree entries are skipped before download when GitLab returns a size.
- Oversized tree entries, job artifacts, and package files are skipped before download when GitLab returns a size.
- GitLab job artifact and generic package file downloads may redirect to signed HTTPS locations. Picket follows those redirects without forwarding the `PRIVATE-TOKEN` header and still uses connect-time endpoint guarding.
- GitLab job artifact and generic package archives use `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, `--max-archive-ratio`, and `--max-target-megabytes`.

GitLab credentials are read from the environment and sent as `PRIVATE-TOKEN` request headers for group project, project repository, merge request source, project snippet, project job, pipeline job, job trace, initial job artifact, package-list, package-file-list, and initial generic package file requests. Least-privilege group project, project repository, merge request, snippet, pipeline, job, and generic package file enumeration requires read-only repository/API and package-registry access appropriate to the selected GitLab instance. Write, maintainer, owner, registry-write, runner, and token-administration scopes are not part of the scanner test contract.

Gitea source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented Gitea entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Repository files | `--gitea-repository`, `--gitea-ref`, `--gitea-token-env`, `--gitea-api-endpoint` | Scans an `owner/name` repository or repository URL at a branch, tag, or commit. Empty `--gitea-ref` uses the default branch. |
| Organization repositories | `--gitea-organization`, `--gitea-ref` | Lists repositories in a Gitea organization with `page` and `limit=100`, then scans each returned repository at `--gitea-ref` or its returned default branch. |
| User repositories | `--gitea-user`, `--gitea-ref` | Lists repositories owned by a Gitea user with `page` and `limit=100`, then scans each returned repository at `--gitea-ref` or its returned default branch. |
| Pull request source head | `--gitea-repository`, `--gitea-pull-request` | Resolves the pull request source commit and source repository, including forks when Gitea returns them, then scans that commit. |
| Issues and comments | `--gitea-include-issues`, `--gitea-issue-state` | Reads issue bodies and repository issue comments, and skips entries that contain a pull request marker. |
| Releases and assets | `--gitea-include-releases` | Scans release body text as synthetic Markdown and scans release assets without forwarding the token to asset download URLs. Asset URLs must stay on the configured Gitea host or one of its subdomains. |
| Actions artifacts | `--gitea-include-actions-artifacts`, `--gitea-actions-run-id` | Lists repository Actions artifacts or artifacts for one run, downloads artifact ZIP archives without forwarding the token to redirected storage URLs, and expands entries through Picket archive limits. Actions artifact scans are explicit opt-ins and cannot be combined with pull request scans. |
| Generic package files | `--gitea-generic-package-owner` | Lists owner packages with `type=generic`, lists each package version's files, downloads selected generic package files through Gitea's documented package route, and expands archive package files through Picket archive limits. Generic package scans are explicit source selectors and cannot be combined with repository refs, pull requests, issues, releases, or Actions artifacts. |
| Exact generic package file | `--gitea-generic-package-owner`, `--gitea-generic-package-name`, `--gitea-generic-package-version`, `--gitea-generic-package-file` | Downloads one exact generic package file without listing all owner packages. |

Gitea API flow:

| Source | API behavior |
| --- | --- |
| Organization repositories | Lists organization repositories through `/orgs/{org}/repos` with `page` and `limit=100`. |
| User repositories | Lists user-owned repositories through `/users/{username}/repos` with `page` and `limit=100`. |
| Repository metadata | Resolves the default branch when `--gitea-ref` is omitted. |
| Branch metadata | Resolves branch names to commit IDs before tree enumeration when Gitea returns branch metadata. |
| Pull request metadata | Resolves the source commit hash, source branch fallback, and source repository when `--gitea-pull-request` is used. |
| Issues | Lists repository issues with `page`, `limit=100`, `type=issues`, and the selected state. |
| Issue comments | Lists repository issue comments with `page` and `limit=100`, then keeps comments whose `issue_url` belongs to a selected non-pull-request issue. |
| Releases | Lists releases with `page` and `limit=100`, scans release body text as synthetic Markdown, and scans embedded release assets. |
| Release assets | Downloads `browser_download_url` values without forwarding the Gitea token. Asset URLs must stay on the configured Gitea host or one of its subdomains, and HTTPS endpoints cannot redirect assets to HTTP. |
| Actions artifacts | Lists repository artifacts through `/repos/{owner}/{repo}/actions/artifacts`, or run-scoped artifacts through `/repos/{owner}/{repo}/actions/runs/{run}/artifacts`, with `page` and `limit=100`. |
| Actions artifact ZIPs | Downloads `/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip` as `application/octet-stream`, follows one allowed redirect without forwarding the token, and expands ZIP entries through archive limits. |
| Generic packages | Lists owner packages through `/packages/{owner}` with `type=generic`, `page`, and `limit=100`. |
| Generic package files | Lists files through `/packages/{owner}/generic/{package_name}/{package_version}/files`. |
| Generic package file content | Downloads `/api/packages/{owner}/generic/{package_name}/{package_version}/{file_name}` as `application/octet-stream`; the route is derived from the configured API endpoint host and self-hosted base path. |
| Repository tree | Lists repository blobs with recursive git tree enumeration and `per_page=1000`. |
| Raw repository files | Downloads file bytes through the raw repository file endpoint. |

Gitea source safety rules:

- Endpoint safety checks run before the first request.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- Gitea REST pagination stops at a 1,000-page safety limit with a warning.
- Remote downloads use a 100 decimal MB default cap.
- Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote Gitea sources reject zero because remote HTTP bodies are always bounded.
- Oversized tree entries, Actions artifacts, and package files are skipped before download when Gitea returns a size.
- Gitea Actions artifact ZIPs and generic package archives use `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, `--max-archive-ratio`, and `--max-target-megabytes`.

Gitea credentials are read from the environment and sent as `Authorization: token ...` request headers for repository scans, artifact-list, initial artifact ZIP, package-list, package-file-list, and initial generic package file requests. Redirected release asset and artifact ZIP downloads are fetched without forwarding the token. Least-privilege repository enumeration requires read-only access to repository metadata, branch metadata, repository tree entries, and raw repository file content for the selected repository. Organization and user scans also require read-only repository-list access for the selected account. Pull request scans also require read-only access to pull request metadata. Issue scans also require read-only issue and issue-comment access. Release scans also require read-only release metadata and access to selected release asset download URLs. Actions artifact scans also require read-only Actions artifact metadata and artifact ZIP download access. Generic package scans require read-only package metadata, package file metadata, and package file download access. Write, owner, organization administration, package publish/delete, runner, and token-administration scopes are not part of the scanner test contract.

Bitbucket Cloud and Bitbucket Data Center source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented Bitbucket entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Repository files | `--bitbucket-repository`, `--bitbucket-ref`, `--bitbucket-token-env`, `--bitbucket-token-kind`, `--bitbucket-username-env`, `--bitbucket-api-endpoint` | Scans a `workspace/repository` repository path or repository URL at a branch, tag, or commit. Empty `--bitbucket-ref` uses the repository main branch. Bearer-token auth is the default; app-password basic auth is explicit. |
| Workspace repositories | `--bitbucket-workspace`, `--bitbucket-ref`, `--bitbucket-token-env`, `--bitbucket-token-kind`, `--bitbucket-username-env`, `--bitbucket-api-endpoint` | Lists repositories visible in a workspace and scans each repository. Empty `--bitbucket-ref` resolves each repository's main branch; a non-empty ref is applied to every repository. Cannot be combined with `--bitbucket-repository` or `--bitbucket-pull-request`. |
| Project repositories | `--bitbucket-workspace`, `--bitbucket-project`, `--bitbucket-ref` | Validates the project key, filters workspace repository enumeration by `project.key`, and scans each returned repository. Cannot be combined with repository, pull request, or workspace snippet scans. |
| Pull request source head | `--bitbucket-repository`, `--bitbucket-pull-request` | Resolves the pull request source commit and source repository, including forks when Bitbucket returns them, then scans that commit. |
| Download artifacts | `--bitbucket-repository` or `--bitbucket-workspace`, `--bitbucket-include-downloads` | Lists repository download artifacts, downloads each selected artifact through Bitbucket's redirect endpoint, follows redirected artifact URLs without forwarding credentials, and expands archive artifacts through the native archive safety caps. With workspace scans, the option applies to every enumerated repository. Cannot be combined with `--bitbucket-pull-request`. |
| Pipeline step logs | `--bitbucket-repository`, `--bitbucket-pipeline-id`, `--bitbucket-include-pipeline-logs` | Lists steps for the selected repository pipeline and scans each step log. Pipeline log scans are repository-scoped, additive to repository file scans, and cannot be combined with workspace or pull request scans. |
| Workspace snippets | `--bitbucket-workspace`, `--bitbucket-include-snippets` | Lists workspace snippets, fetches snippet metadata for file names, and downloads raw snippet files through the snippet file API. Snippets are additive to workspace repository scans and cannot be combined with repository or pull request scans. |

Bitbucket API flow:

| Source | API behavior |
| --- | --- |
| Workspace repositories | Lists repositories in a workspace with `pagelen=100`, follows Bitbucket pagination, and scans each returned repository path. |
| Project metadata | Validates `--bitbucket-project` through the workspace project API before listing repositories. |
| Project repositories | Lists workspace repositories with a `project.key` query filter and scans each returned repository path. |
| Workspace snippets | Lists snippets in a workspace with `pagelen=100`, fetches snippet metadata for file names, and downloads raw snippet files through the snippet file API. |
| Repository metadata | Resolves the main branch when `--bitbucket-ref` is omitted. |
| Pull request metadata | Resolves the source commit hash, source branch fallback, and source repository when `--bitbucket-pull-request` is used. |
| Directory listings | Lists repository directory contents page by page with `pagelen=100`. Picket walks returned `commit_directory` entries instead of relying on `max_depth`. |
| Raw repository files | Downloads raw bytes for returned `commit_file` entries. |
| Download artifacts | Lists repository downloads with `pagelen=100`, requests each artifact by filename, accepts Bitbucket's documented 302 response, and fetches redirected artifact bytes without an `Authorization` header. |
| Pipeline step logs | Lists steps through `/repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}/steps` with `pagelen=100`, downloads `/steps/{step_uuid}/log`, accepts Bitbucket's documented 307 log redirects, and fetches redirected log bytes without an `Authorization` header. |

Bitbucket source safety rules:

- Endpoint safety checks run before the first request.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Retryable throttling and service responses are retried once with bounded `Retry-After` backoff.
- Project-scoped scans validate the project first and only then issue the filtered workspace repository listing.
- Bitbucket workspace repository and directory pagination follows the `next` response field and stops at a 1,000-page safety limit per paged list with a warning.
- Remote downloads use a 100 decimal MB default cap.
- Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote Bitbucket sources reject zero because remote HTTP bodies are always bounded.
- Oversized directory entries are skipped before download when Bitbucket returns a size.
- Oversized download artifacts are skipped before download when Bitbucket returns a size.
- Pipeline step logs use the same remote byte cap as repository files.
- Snippet file downloads use the same remote byte cap as repository files.
- Raw snippet redirects are followed only when the redirected URI stays on the configured Bitbucket API endpoint because those redirected API requests still require the Bitbucket credential.
- Download artifact archives respect `--max-archive-depth`, `--max-archive-entries`, `--max-archive-megabytes`, `--max-archive-ratio`, and `--max-target-megabytes`.
- Pipeline step logs are explicit opt-ins. Pipeline artifact downloads are not exposed as a direct Bitbucket Cloud REST download endpoint; users who need artifact scanning should publish artifacts to repository downloads or another supported source.

Bitbucket credentials are read from environment variables. Bearer mode sends `Authorization: Bearer ...`. App-password mode sends HTTP Basic authentication using the username from `--bitbucket-username-env` and the app password from `--bitbucket-token-env`. Least-privilege repository and workspace enumeration requires read-only repository access for repository listings, repository metadata, source directory listings, raw source file content, and download artifacts. Project-scoped workspace scans also require read-only project access for project metadata. Pull request scans also require read-only pull request access. Snippet scans require read-only snippet access. Pipeline log scans require read-only pipeline access. For OAuth-style tokens, Bitbucket documents the `repository` scope for source and download enumeration, the `project` scope for project metadata, the `pullrequest` scope for pull request metadata, the `snippet` scope for snippet enumeration, and the `pipeline` scope for pipeline step and log enumeration. For API tokens, Bitbucket documents `read:repository:bitbucket`, `read:project:bitbucket`, `read:pullrequest:bitbucket`, `read:snippet:bitbucket`, and `read:pipeline:bitbucket`.

Implemented Bitbucket Data Center entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Repository files | `--bitbucket-data-center-api-endpoint`, `--bitbucket-data-center-project`, `--bitbucket-data-center-repository`, `--bitbucket-data-center-ref`, `--bitbucket-data-center-token-env` | Scans one repository at an immutable commit. Empty ref resolves the default branch; a named ref is resolved through the commits API before file enumeration. |
| Project repositories | `--bitbucket-data-center-api-endpoint`, `--bitbucket-data-center-project`, `--bitbucket-data-center-token-env` | Lists every readable repository in the project and resolves each repository independently. |
| Pull request source head | `--bitbucket-data-center-repository`, `--bitbucket-data-center-pull-request` | Resolves `fromRef.latestCommit` and the source repository/project, including a fork, then scans that exact commit. |
| Basic authentication | `--bitbucket-data-center-token-kind basic`, `--bitbucket-data-center-username-env`, `--bitbucket-data-center-token-env` | Reads the username and credential from named environment variables and sends HTTP Basic authentication. Bearer authentication is the default. |

Bitbucket Data Center API flow and safety rules:

- The API endpoint is required and includes the installation's `rest/api/1.0` path. No public default endpoint is inferred.
- Project repositories use `/projects/{projectKey}/repos`; recursive file listings use `/files`; raw bytes use `/raw/{path}`.
- Default branches, named refs, and pull request source heads resolve to immutable commit IDs before file enumeration.
- Project and file lists request `limit=100`, use the server-provided `nextPageStart`, reject non-advancing cursors, and stop at 1,000 pages.
- Provider metadata JSON is capped at 10 decimal MB. File bodies use the 100 decimal MB remote default or a positive `--max-target-megabytes` override, enforced while streaming even when `Content-Length` is absent or understated.
- Paths are normalized, deduplicated, and checked against global path ignores before raw content is requested.
- Endpoint safety checks run before the first request and at connection time. HTTPS is required unless insecure source endpoints are explicitly allowed. Redirects are disabled, including rejection of responses already redirected by an injected handler.
- Retryable throttling and service responses are retried once with bounded `Retry-After` handling.
- Data Center credentials are read from environment variables and sent only in request headers. The required permission set is read access to selected projects, repositories, refs/commits, file content, and pull request metadata when selected; write and administration permissions are not required.

GitHub source support is native Picket behavior, not Gitleaks compatibility behavior.

Implemented GitHub entry points:

| Scope | Options | Behavior |
| --- | --- | --- |
| Repository files | `--github-repository`, `--github-ref`, `--github-token-env`, `--github-source-api-endpoint` | Scans an `owner/name` repository or repository URL at a branch, tag, or commit. Empty `--github-ref` uses the default branch. |
| Pull request head | `--github-repository`, `--github-pull-request` | Resolves the pull request head SHA and head repository, including forks when GitHub returns them, then scans that commit. |
| Organization repositories | `--github-organization`, `--github-repository-type` | Lists visible organization repositories with GitHub's organization repository type filter. |
| Public user repositories | `--github-user`, `--github-repository-type` | Lists public repositories for a user with the `all`, `owner`, or `member` filter. |
| Issues and comments | `--github-include-issues`, `--github-issue-state` | Reads issue bodies and comments, and skips entries that contain a pull request marker. |
| Releases and assets | `--github-include-releases` | Scans release body text as synthetic Markdown and scans release assets. |
| Actions artifacts | `--github-include-actions-artifacts` | Downloads artifact ZIP archives through GitHub's short-lived redirect and expands entries with the native archive safety caps. |
| Gists | `--github-gist`, `--github-gists`, `--github-user-gists` | Scans gist files and gist comments, including detail records for listed gists. |

GitHub API flow:

| Source | API behavior |
| --- | --- |
| Repository metadata | Resolves default branches for single-repository scans. |
| Recursive Git Trees | Lists repository blobs for each selected repository. |
| Raw Contents | Downloads repository blob bytes. |
| Pull Requests | Resolves `head.sha` and `head.repo.full_name`. |
| Releases | Lists releases with `per_page=100`, scans embedded assets when present, and falls back to the release-assets API when needed. |
| Actions Artifacts | Lists repository artifacts with `per_page=100` and fetches redirected ZIP downloads without forwarding the bearer token. |
| Issues | Lists issues with `per_page=100` and reads issue comments through the issue comments API. |
| Gists | Uses authenticated-user, user-public, and single-gist APIs; truncated file lists are reported as warnings and truncated files fall back to `raw_url` without forwarding the bearer token. |
| Repository lists | Organization and user repository-listing modes follow the REST `Link` header while a `rel="next"` page is present. |

GitHub source safety rules:

- Endpoint safety checks run before the first request.
- Redirects are disabled before credentials are sent.
- Responses from injected HTTP handlers that already followed a redirect are rejected.
- Release asset requests use `Accept: application/octet-stream` and handle GitHub `200` or `3xx` responses.
- Redirected release asset, Actions artifact, and gist raw downloads are fetched without forwarding the bearer token.
- Retryable throttling responses are retried once with bounded `Retry-After` backoff.
- Paged GitHub REST lists stop at a 1,000-page safety limit with a warning.
- Remote downloads use a 100 decimal MB default cap.
- Provider metadata JSON responses are capped at 10 decimal MB and skipped with a warning when the cap is exceeded.
- A positive `--max-target-megabytes` value overrides the default remote cap.
- Zero keeps its local-scan compatibility meaning, but remote GitHub sources reject zero because remote HTTP bodies are always bounded.
- Oversized blobs, Actions artifact ZIPs, and issue/comment/release/gist synthetic files are skipped before or during download.
- Tree and gist-file-list truncation are warnings.
- Per-file download failures do not abort a repository scan.
- Per-repository tree failures do not abort an organization or user scan.

GitHub credentials use least-privilege read scopes. Repository enumeration requires Metadata Read plus Contents Read. Hosted GitHub Secret Protection oracle capture requires Secret scanning alerts Read plus Metadata Read. Write, administration, workflow, security-event upload, and secret write scopes are not part of the scanner test contract.

Azure DevOps source support is native Picket behavior, not Gitleaks compatibility behavior. Pipeline task defaults scan the job's checked-out workspace unless the user explicitly opts into remote enumeration.

Supported Azure DevOps scopes are project- and organization-scoped Azure Repos, branch and pull-request source heads including returned fork repositories, wiki backing repositories, build artifacts, build logs, classic release build artifacts, and Azure Artifacts NuGet packages. Package scanning is explicit through `--azure-devops-include-packages`; optional feed, package, and version selectors narrow the scan, and the latest package version is used when no version is selected. Other Azure Artifacts protocols remain separate until their documented transfer mechanisms can satisfy the same bounded-download and credential rules.

Azure DevOps requests use PAT or bearer authentication as selected, a 1,000-page safety limit, one bounded retry for throttling, a 10 decimal MB provider metadata cap, 100 decimal MB default file/artifact/log/package caps, archive safety caps, HTTPS credential transport by default, and connect-time endpoint checks. Signed package and artifact redirects are followed without forwarding credentials. Failures on independently enumerable repositories, wikis, artifacts, logs, feeds, or packages warn and continue where a broader scan can still make progress. Artifact and log response bytes are never copied into warnings or diagnostics. Request failures use fixed messages that omit request URIs, signed redirect queries, response bodies, and provider-controlled archive paths; diagnostics contain aggregate scan and runtime data only.

Azure DevOps credentials use least-privilege read scopes. Repository enumeration requires Project and Team Read plus Code Read; build logs and artifacts require Build Read; classic releases require Release Read; wikis require Wiki Read; package/feed scanning requires Packaging Read. Write, execute, manage, service-connection, agent-pool, token-administration, and full-access scopes are not part of the scanner test contract.

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

`picket verify` and `picket analyze` accept Picket JSON, Picket JSONL, and Gitleaks JSON reports as finding input when those reports retain raw secret material. Report input uses the same native triage pipeline as scan output: ignore and baseline filtering, offline validation, optional live validation, validation-result filters, redaction, and report writing. Summary-only formats such as SARIF, HTML, GitLab code-quality JSON, and third-party reports without raw secrets remain `picket view` inputs rather than verification inputs.

`picket view` opens local HTML/JSON/JSONL/SARIF reports and can import compatible Gitleaks and TruffleHog reports for cross-tool triage.

### 8.10 Terminal Triage UI

`picket tui <report>` opens an interactive scanner console for non-secret report triage. `picket tui --scan` opens the native scan workspace without loading an existing report. The main `picket` executable keeps the scanner binary focused and delegates to the companion `picket-tui` executable when it is installed beside `picket` or discoverable on `PATH`. The companion's RID-specific release archive is also Native AOT and uses the same release profiles as `picket`; it is separate so terminal UI code and terminal-native assets do not increase the default scanner payload. The companion loads the same non-secret report summaries as `picket view`: rule IDs, detector names, paths, line numbers, fingerprints, counts, and format names. It does not load raw secret, match, or source-line evidence into the initial console.

The full-screen console is an operator interface, not a marketing screen. Opening without a report starts on the Scan page; opening a report with findings starts on Findings. The Scan page is for setting up and running a scan: Run scan, target inputs, command preview, status, exit code, scan timing, report path, result count summary, and an output-availability signal. The Logs page owns captured scanner output. The Findings page owns row triage: filtering, selected-row focus, finding details, and finding-specific yank text. This prevents the Scan page from becoming a duplicate findings browser while still making the next action obvious after a scan completes. It favors readable scanner-console density, stable row keys, clear focus, keyboard navigation, and text labels over decorative graphics.

The scanner console also has a native scan workspace. The workspace covers local paths, local container archives, remote registry images, source hosts, and object stores. Profile, config, ignore behavior, verification, result filters, limits, redaction, and report controls are grouped into Source, Output, Validation, and Limits sections.

GitHub setup uses one explicit scope picker for repository, organization repositories, user repositories, one gist, authenticated-user gists, or public gists for one user. The workspace renders and emits only the selected scope. Repository input is `owner/name`, including personal repositories where `owner` is the account login. Retained values from another scope must not create an ambiguous command, and incomplete input must identify the required field and accepted value shape rather than report a combined selector-count error.

The workspace displays the command-equivalent `picket scan` request and runs that scanner executable. It shows text status, exit code, start/completion/elapsed timing, output availability, and cancellation state. The Logs view owns captured stdout and stderr.

Before launch, the workspace prepares the report directory and moves any report from an earlier run aside. A readable report produced by the current scanner process replaces the earlier report and is loaded even when the scan is incomplete, because findings collected before an input failure remain useful for triage. Clean completion still requires the report count to agree with the scanner exit code: exit `0` requires zero findings, and exit `1` requires at least one finding. Native scans that encounter an input error emit an explicit incomplete-scan diagnostic after writing available results; the workspace labels the report as partial and keeps operational success false. An exit/report mismatch is shown as a failure but does not destroy the readable artifact. A missing or malformed report restores the previous report and loaded results.

Completed scans show the loaded finding count and a direct `g f` path to Findings instead of duplicating findings on Scan. While a scan is running, the primary action changes from Run scan to Cancel and `Ctrl+C` requests cancellation without closing the console. The TUI must not create a separate scanner behavior path from the CLI.

`picket tui <report> --flow` renders interactive steps inline in the normal terminal buffer. The inline flow can prompt for a report path, show a frozen summary in scrollback, and open the same full-screen console through a full-screen step when the user needs a larger workspace. Inline steps keep output suitable for normal terminal history; full-screen steps use the alternate screen buffer only for the scanner console.

The TUI follows WCAG 2.2 AA principles adapted to terminal constraints:

- keyboard access for every action, with mouse support optional,
- visible focus states for controls, navigation, and focused rows,
- status expressed in text so color is never the only signal,
- normal text contrast of at least 4.5:1,
- non-text UI, borders, and focus indicators of at least 3:1,
- no flashing or motion-only progress; progress must have text status.

TUI coverage uses Hex1b's headless terminal and automation APIs as first-class tests. Tests render the real widget tree, capture terminal snapshots, verify keyboard behavior, and cover practical desktop and narrow terminal dimensions.

### 8.11 CI, Hooks, and Distribution

Picket ships:

- MIT `picket-action`,
- Azure DevOps pipeline task and marketplace extension,
- pre-commit, pre-push, and pre-receive hooks,
- `picket-tui` interactive report triage companion,
- Docker images,
- Homebrew, Scoop, winget, MSI,
- `dotnet tool`,
- NuGet packages for embedding.

The GitHub Action supports annotations, SARIF upload, fetch-depth guidance, baseline handling, validation-result filtering, cache restore/save, least-privilege permissions, summary output, and explicit fail modes.

The Azure DevOps pipeline integration supports a first-class `PicketScan@1` task, workspace scans, optional Azure Repos/project/org enumeration, pipeline/build/release artifact scanning, JSONL/SARIF/HTML report publication, build annotations where Azure DevOps supports safe source locations, explicit fail modes, scan-cache use through task inputs, and no telemetry. Task metadata lives under `azure-devops/tasks/PicketScanV1`, and the marketplace extension manifest lives at `azure-devops/vss-extension.json`. Release-phase packaging validates the VSIX and agent smoke tests before publication. Self-hosted marketplace smoke tests run only through explicit manual queueing; pull-request and push validation use hosted agents, recorded responses, or local fakes. The task works on Microsoft-hosted and self-hosted Windows, Linux, and macOS agents when `picket` is available through `picketPath` or the agent `PATH`.

Marketplace distribution is planned for the public release phase, after core scanner behavior, compatibility, reports, and security controls are stable:

- GitHub Marketplace listing for the GitHub Action with semver tags, immutable release tags, least-privilege permission examples, clear SARIF/code-scanning setup, screenshots or summary examples that contain no real secrets, MIT license metadata, and generated input/output reference from `action.yml`.
- Azure DevOps Marketplace extension with a VSIX manifest, task metadata, icon, README, privacy and license details, agent compatibility matrix, a versioned task major line such as `PicketScan@1`, and installation-free execution through bundled signed binaries or deterministic acquisition from Picket releases.
- Both marketplace packages use the same release provenance as CLI artifacts: checksums, attestations where the platform supports them, generated docs, dry-run validation, and a rollback path.

Marketplace promotion is manual-only through `.github/workflows/marketplace-release.yml`. A dispatch accepts one stable release tag, a target surface, and a dry-run switch that defaults to enabled. Promotion requires an existing non-draft, non-prerelease GitHub Release and a successful Release workflow for the tag commit. GitHub Action promotion creates or moves only the mutable `vMAJOR` tag; immutable release tags are never rewritten. Azure DevOps promotion downloads the release VSIX and checksum, verifies the GitHub artifact attestation, validates bounded package structure and identity through `scripts/Validate-MarketplaceRelease.cs`, and publishes through `tfx` without validation or TLS bypasses. Real mutations use the `marketplaces` environment; rerunning a reviewed older stable release in GitHub Action mode is the rollback path for the mutable major tag.
- Marketplace packaging must not fork scanner behavior. It is a distribution wrapper around the same CLI/library contracts used by local and CI execution.

Pre-receive support handles bare repositories, quarantine environment variables, old/new ref input, timeouts, concurrency, and clear rejection messages.

### 8.12 Embeddable .NET API

`Picket.Engine`, `Picket.Rules`, `Picket.Report`, and `Picket.Security` are AOT-safe NuGet packages for analyzers, MSBuild tasks, CI systems, IDE integrations, and internal security platforms.

The initial public package surface is intentionally narrow:

- `Picket.Rules` contains rule, allowlist, required-rule, and embedded compatibility-rule models.
- `Picket.Engine` contains compiled rule sets, findings, entropy helpers, scan requests, and byte-oriented scanning.
- `Picket.Report` contains Gitleaks-compatible and Picket-native report writers.
- `Picket.Security` contains egress policy and endpoint safety primitives for live validation, source connectors, and user-configured provider endpoints.

`Picket.Compat`, `Picket.Sources`, `Picket.Store`, `Picket.Verify`, `Picket.Analyze`, and TUI internals are not public library NuGet packages until their contracts are explicitly designed and documented. The CLI and TUI companion ship as RID-specific Native AOT `dotnet tool` packages for Windows, Linux, and macOS x64/Arm64 package-manager workflows; the Native AOT archives remain the direct executable distribution.

Public APIs are documented, cancellation-aware where operations can block or stream, streaming-first where result volume can be large, and stable across minor releases.

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

Test projects use `MSTest.Sdk` with Microsoft.Testing.Platform (MTP), Microsoft's modern recommended test platform for new MSTest projects. The repository opts into .NET 10 MTP mode through `global.json` (`"test": { "runner": "Microsoft.Testing.Platform" }`), so solution tests run with `dotnet test --solution Picket.slnx`. This avoids legacy VSTest project plumbing by default and lets Picket choose MTP extension profiles explicitly.

### 10.1 Compatibility Oracle

The Gitleaks oracle suite runs the pinned real Gitleaks binary and Picket over identical fixtures. Raw captures come from `scripts/Capture-GitleaksOracle.cs`; side-by-side compatibility captures come from `scripts/Capture-CompatibilityOracle.cs`. Committed golden files come from `scripts/Promote-CompatibilityOracle.cs`, must be normalized, reviewed for redaction, tied back to the upstream pin metadata, and captured with an explicit working directory whenever relative source paths are part of the expected report contract.

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

### 10.2 GitHub Secret Scanning Oracle

GitHub Secret Protection secret scanning is a hosted proprietary oracle, so Picket compares against sanitized alert metadata rather than an implementation clone. `scripts/Capture-GitHubSecretScanningOracle.cs` captures alert numbers, states, secret types, URLs, and optional source locations through `gh api` while dropping raw secret values. `scripts/Compare-GitHubSecretScanningOracle.cs` compares a native Picket JSONL report to that metadata, reports mapped alert classes, missing mapped locations, unexpected mapped findings, and hosted alert types that do not yet map to a Picket rule. The comparison is commit-aware when GitHub location metadata includes a commit SHA, so hosted historical alerts should be compared with a native `picket git --profile picket` report rather than a current filesystem scan. Strict Gitleaks compatibility remains a separate oracle because Gitleaks allowlists and GitHub hosted alerts are not the same contract.

### 10.3 Rule Corpus

Every bundled Gitleaks rule and selected community rules are compiled through the dialect layer and tested against fixtures under both tools. Picket-native rules require positive and negative examples before release.

### 10.4 Security Tests

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

### 10.5 Performance Tests

Performance gates are scenario-specific and fair:

- Gitleaks-compatible cold scans compared to Gitleaks with equivalent flags,
- native rule-pack scans compared to sanitized GitHub secret-scanning alert metadata where the hosted alert family has a local deterministic equivalent,
- native incremental scans compared against previous Picket runs,
- verification benchmarks separated from scan-only benchmarks,
- retired tools such as Nosey Parker used only as historical datapoints, not live release gates.

Metrics include throughput, allocations, peak memory, startup time, rule compile time, cache hit rate, and report writer throughput. Engine changes use `benchmarks/Picket.Benchmarks`; end-to-end comparisons use the oracle capture scripts under `scripts/`.

### 10.6 Live Tests

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
- local Docker/OCI archive scanners,
- GitLab project repository file scanner,
- JSONL/rich JSON/TOON/HTML/GitLab reports,
- `picket view`.

Gate: remote enumeration, checkpointing, redaction, and dedup tests green.

### M7: Distribution

- `dotnet tool`,
- NuGet libraries,
- Docker,
- Homebrew/Scoop/winget/MSI,
- GitHub Action,
- GitHub Marketplace listing,
- Azure DevOps pipeline task,
- Azure DevOps Marketplace extension,
- hooks,
- generated static documentation site.

Gate: release workflow produces signed/checksummed artifacts, action smoke tests pass, marketplace packages validate without publishing, and the docs site builds and deploys through GitHub Pages from the default branch.

Marketplace publishing can be implemented late in the milestone. It is a release-readiness task, not a prerequisite for engine, rule, report, or local CLI work.

### M8: Performance Hardening and Fair Comparison

- feature-complete benchmark matrix,
- end-to-end Picket versus Gitleaks comparisons for strict compatibility scenarios,
- end-to-end native Picket comparisons against TruffleHog, Kingfisher, and other relevant tools only where rules, verification, source enumeration, and history mode are equivalent or explicitly separated,
- cold-start, warm-start, scan-only, verification, report-writing, and CI-action timings,
- binary size, package size, peak RSS, allocation, and cache-hit measurements,
- trace-based bottleneck attribution before optimization,
- Scout issue creation when a Scout package is the measured bottleneck.

Gate: performance results are reproducible enough to review, behavior is unchanged, and any optimization is justified by measured wins for a named Picket scenario.

Critical Scout performance blockers pause Picket work until the Scout issue is fixed or the design is updated with an acceptable fallback.

End-to-end measurements use `scripts/Measure-ScannerPerformance.cs` and checked-in manifests under `benchmarks/scenarios/`. The harness stages exact blobs from an immutable Git commit, invokes direct scanner executables without a shell, rotates tool order, separates pre-warmup and warmed fresh-process rounds, records tool, executable byte count, binary, source, host, and resource evidence, deletes generated reports by default, and hashes canonical finding sets for scenarios that are genuinely parity-comparable. Picket scenarios fail before measurement when the executable version does not identify the staged repository commit. Scenario conditions must state when host-level caches were not reset; a warmed filesystem run is not described as a cold OS-cache measurement. Tools with different rules, validation, history, decoding, or source behavior are measured in separate capability scenarios without a parity claim.

Report-writing scenarios verify every requested report exists and record its exact byte count. Multi-report scenarios additionally record the report count, total bytes, and a stable manifest hash over each configured report identity, size, and SHA-256 digest. Release automation writes `release-artifacts.json` from the final release payloads so compressed package and installer sizes are reviewable independently of transient workflow artifacts.

The capability-separated native filesystem scenario runs Picket, TruffleHog, and Kingfisher over the same immutable corpus with Git history, live verification, update checks, and persistent caches disabled. Each scanner retains its own rules, offline filtering, decoders, archive traversal, ignore semantics, and native JSON Lines schema, so the result records full tool-native cost and finding volume without a parity group or universal winner claim. Scanner reports written to stdout are streamed directly into ephemeral files rather than retained as decoded process output.

`docs/PERFORMANCE.md` records reviewed baselines with exact Picket, Scout package, and competitor versions; corpus identity; host conditions; finding parity; elapsed time; CPU time; and peak working set. Results remain scoped to their named scenario and host.

The native cache scenario compares the same Picket binary and native finding set with caching disabled and with an initially empty secret-hash-only cache. A stable generated session path keeps cache state outside the staged corpus and across measured process rounds. Because secret-hash-only cache hits intentionally omit raw line, match, and secret evidence, canonical parity excludes those three top-level report properties plus the match hash that cannot be reconstructed from missing context. Secret hashes, stable fingerprints, report hashes, and every other finding property remain in the comparison. The harness records bounded non-secret diagnostic counters for scan inputs, findings, cache hits, misses, and writes; it never retains diagnostic text or finding evidence.

### M9: Optional Stretch

- honeytokens,
- leak-database checks,
- organization policy packs.

Stretch features are not v1 blockers unless promoted by a separate design update.

---

## 14. Documentation Deliverables

Picket uses a static documentation system. The public site is generated during CI and published to GitHub Pages at the repository Pages URL, for example `https://willibrandon.github.io/picket/`.

The ideal implementation mirrors the useful parts of Dotsider's documentation system while avoiding Dotsider's custom website server:

- `docs/` remains the source of truth for durable hand-written Markdown.
- `docs-site/` contains the Astro/Starlight static site shell, styling, navigation, and GitHub Pages base-path configuration.
- `tools/Picket.Docs/` is a .NET generator that produces deterministic Starlight-compatible Markdown and MDX into `docs-site/src/content/docs/generated/`.
- DocFX metadata generation is used only as a build-time API metadata extractor. The generator converts DocFX YAML and XML documentation comments into Picket-styled Starlight pages.
- `docs-site/dist/` is never committed. GitHub Actions uploads it with `actions/upload-pages-artifact` and deploys it with `actions/deploy-pages`.
- The site build is offline except package restore. It must not require live credentials, local reference clone paths, a domain, or a server.
- The GitHub Pages workflow runs on pushes to the default branch, on manual dispatch, and as a pull-request build check without deployment.

Generated documentation includes:

- API reference for public packages and embeddable APIs from XML documentation comments,
- CLI reference generated from command metadata or stable `--help` output,
- GitHub Action input and output reference generated from `action.yml`,
- Azure DevOps task input and output reference generated from task metadata once the extension exists,
- rule-pack catalog generated from embedded Gitleaks and Picket rule sources,
- report-schema reference generated from report writer contracts and sample outputs,
- config-schema reference generated from Gitleaks-compatible and Picket-native loaders,
- validation/analyze reference generated from validator states, confidence/severity metadata, and provider threat-model metadata,
- release-profile reference generated from publish profiles and package metadata.

Documentation quality gates:

- the generator is deterministic and can be run locally with one command,
- CI fails if generated docs are stale when generated source pages are committed,
- CI fails if the site cannot build,
- every public API included in shipped NuGet packages has XML documentation and appears in the generated API reference unless explicitly excluded,
- generated docs never include local filesystem paths such as reference clone paths,
- generated examples use redacted, fake, or structurally invalid secrets,
- links are checked for local docs and generated API references,
- pages work under the `/picket/` GitHub Pages base path and do not assume site-root deployment.

Required before v1:

- `docs/PARITY.md`: compatibility ledger,
- `docs/UPSTREAM.md`: reference pins and sync process,
- `docs/RULES.md`: rule schema, examples, validator/revocation metadata,
- `docs/VALIDATION.md`: privacy and egress model,
- `docs/REPORTS.md`: compatibility and native schemas,
- `docs/TUI.md`: terminal triage UI, Flow mode, and terminal accessibility requirements,
- `docs/ACTION.md`: CI action behavior and security posture,
- `docs/GITHUB.md`: GitHub source enumeration, hosted-alert oracle capture, and permission guidance,
- `docs/GITLAB.md`: GitLab source enumeration and permission guidance,
- `docs/AZURE_DEVOPS.md`: Azure DevOps task, source enumeration, artifact scanning, and marketplace behavior,
- `docs/OBJECT_STORES.md`: object-store source enumeration and permission guidance,
- `docs/MARKETPLACES.md`: GitHub Marketplace and Azure DevOps Marketplace packaging, release, and rollback guidance,
- `docs/HOOKS.md`: local and server-side Git hook behavior,
- `docs/PERFORMANCE.md`: benchmark and oracle comparison process,
- `docs/RELEASE.md`: Native AOT publish profiles and release artifact guidance,
- `docs/EMBEDDING.md`: library API guide,
- `docs-site/`: static site shell for GitHub Pages,
- `tools/Picket.Docs/`: generated documentation pipeline,
- `.github/workflows/docs.yml`: build and deploy workflow for GitHub Pages.
