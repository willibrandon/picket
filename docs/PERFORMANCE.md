# Performance

Picket performance work is measured with BenchmarkDotNet for engine-level
changes and with scanner-oracle scripts for end-to-end behavior.

Optimization is a late-project activity. Do not do broad hot-path rewrites
until the relevant feature set is complete, unless a measured regression blocks
correctness, feasibility, or CI reliability.

Run the engine benchmarks with:

```powershell
dotnet run -c Release --project benchmarks/Picket.Benchmarks -- --filter "*SecretScanBenchmarks*"
```

Run the report writer benchmarks with:

```powershell
dotnet run -c Release --project benchmarks/Picket.Benchmarks -- --filter "*ReportWriterBenchmarks*"
```

Current benchmark scenarios cover:

- native default rules over the embedded Gitleaks config,
- strict Gitleaks-compatible rules over the same file,
- the focused native Google API key rule over the embedded Gitleaks config as a
  local hosted-alert parity proxy,
- mapped native rules over the sanitized GitHub secret-scanning oracle fixture
  in `tests/fixtures/github-secret-scanning`,
- native default rules over credential-analyzer tests,
- steady-state and fresh-rule-set scans for native default and strict
  Gitleaks-compatible rules,
- complete native default, strict Gitleaks-compatible, and mapped GitHub-alert
  regex compilation, including deferred rule, path, and allowlist regexes,
- compatibility JSON report writer throughput,
- native JSON, JSON Lines, SARIF, HTML, and TOON report writer throughput across
  deterministic 1, 100, and 1000 finding report sizes.

Run benchmarks before and after hot-path changes and keep the output in ignored
`BenchmarkDotNet.Artifacts/` or `artifacts/` directories. Do not commit
machine-specific benchmark output unless it has been normalized into a reviewed
fixture.

## End-to-End Scanner Harness

`scripts/Measure-ScannerPerformance.cs` measures Native AOT scanner processes
from a checked-in JSON scenario. The default strict-compatibility scenario is
`benchmarks/scenarios/gitleaks-compatible-tracked.json`. It creates an immutable
copy of the selected Git-tracked files, runs Picket and the pinned Gitleaks
binary from the same working directory, and removes the generated corpus and
reports after measurement.

The native incremental scenario is
`benchmarks/scenarios/native-cache-tracked.json`. It compares the same Picket
binary and native scan with cache disabled and with an initially empty
secret-hash-only cache. Its one recorded cold run populates the cache before the
warmup and warm rounds. Report parity is mandatory, and bounded CPU diagnostics
record scan inputs, findings, cache hits, misses, and writes for every run.
Canonical parity excludes raw `line`, `match`, and `secret` fields because
secret-hash-only cache hits intentionally omit them, plus `matchSha256` because
the missing match context cannot be reconstructed. Secret hashes, stable
fingerprints, full report hashes, and all other finding properties are still
recorded and compared.

Publish the current scanner, identify the two direct executable paths, build the
file-based app once, and run the scenario:

```powershell
dotnet publish src/Picket.Cli/Picket.Cli.csproj --configuration Release --no-restore -p:PublishProfile=release-speed -r win-x64 -o artifacts/performance/tools/picket
$env:PICKET_BIN = (Resolve-Path artifacts/performance/tools/picket/picket.exe).Path
$env:PICKET_GITLEAKS_BIN = (Resolve-Path artifacts/tools/gitleaks.exe).Path
dotnet build ./scripts/Measure-ScannerPerformance.cs --nologo --verbosity quiet
dotnet run --file ./scripts/Measure-ScannerPerformance.cs --no-build -- -ScenarioPath ./benchmarks/scenarios/gitleaks-compatible-tracked.json -FailOnParityDifference
```

Run the cache scenario with the same `PICKET_BIN` value:

```powershell
dotnet run --file ./scripts/Measure-ScannerPerformance.cs --no-build -- -ScenarioPath ./benchmarks/scenarios/native-cache-tracked.json -FailOnParityDifference
```

Run the capability-separated native filesystem scenario after setting direct
paths for Picket, TruffleHog, and Kingfisher:

```powershell
$env:PICKET_TRUFFLEHOG_BIN = (Resolve-Path ../trufflehog/trufflehog.exe).Path
$env:PICKET_KINGFISHER_BIN = (Resolve-Path ../kingfisher/target/release/kingfisher.exe).Path
dotnet run --file ./scripts/Measure-ScannerPerformance.cs --no-build -- -ScenarioPath ./benchmarks/scenarios/native-filesystem-competitors.json
```

This scenario does not use `-FailOnParityDifference`. It holds the corpus,
filesystem source mode, live-verification state, persistent-cache state, and
JSON Lines output category constant, and disables competitor update checks, but
each scanner retains its own built-in rules, offline filtering, decoders,
archive handling, ignores, and report schema. Finding counts and timings
describe those complete tool-native capabilities; they do not establish an
equivalent winner.

Run the native report fan-out scenario with the same `PICKET_BIN` value:

```powershell
dotnet run --file ./scripts/Measure-ScannerPerformance.cs --no-build -- -ScenarioPath ./benchmarks/scenarios/native-report-writing-tracked.json -FailOnParityDifference
```

The control writes JSON Lines. The fan-out variant writes the same primary
JSON Lines finding set plus SARIF, HTML, and TOON. The harness requires the
primary finding sets to match, verifies every additional file exists, and
records their aggregate byte count and content manifest hash.

On Unix-like systems, set `PICKET_BIN` and `PICKET_GITLEAKS_BIN` to the
corresponding executable paths before running the same `dotnet build` and
`dotnet run` commands. A scenario falls back to executable names on `PATH` when
its environment variable is not set.

The result schema is `picket.performance-result.v1`. Each capture records:

- scenario, corpus manifest, Picket commit, tool repository commit, executable
  byte count, SHA-256, and version output,
- OS, architecture, processor, effective processor count, GC-visible memory,
  filesystem, runner type, .NET runtime, and SDK,
- wall time, child-process CPU time, peak child-process working set, exit code,
  output byte counts and hashes, report byte count and hash, and finding count,
- a canonical finding-set hash for parity groups, so report ordering does not
  create a false difference,
- optional bounded diagnostic artifact metadata and non-secret scan-input,
  finding, cache-hit, cache-miss, and cache-write counters.

Picket scenarios set `RequireRepositoryCommitInVersion`. A measurement fails
before its first timed process when the Native AOT binary version does not
identify the selected repository commit. Corpus staging reads exact blobs from
the recorded Git `HEAD`; dirty tracked working-tree bytes cannot enter a result
that claims to represent that commit.

The default schedule records one pre-warmup run, discards one warmup round, then
records five warmed rounds. Tool order rotates between rounds to reduce fixed
order and thermal bias. Every scanner invocation is a fresh process. "Warm"
therefore describes warmed host and filesystem state, not retained in-process
scanner caches. A genuinely cold OS-cache measurement requires a fresh host or
an explicit host-level cache reset and must be recorded in the scenario
conditions.

The harness invokes executables directly through `ProcessStartInfo.ArgumentList`.
Do not benchmark `dotnet run`, a shell wrapper, or a build command as if it were
scanner time. It stores only hashes and byte counts for scanner stdout, stderr,
and canonical findings. Generated reports can contain secrets and are deleted by
default. `-KeepWork` is an explicit debugging option and must be used only for a
trusted artifact location.

Tools that emit reports on standard output use the scenario's `ReportSource`
value. The harness streams stdout directly into the ephemeral report file and
does not retain decoded report text in the result.

Only tools in the same `ParityGroup` are required to produce the same canonical
finding set. Native comparisons with TruffleHog, Kingfisher, or another scanner
must omit a parity group unless rules, decoding, verification, source traversal,
history behavior, ignores, and report filtering have actually been aligned.
Capability-separated measurements remain valid, but they are not presented as
an equivalent winner/loser comparison.

### Reviewed Baseline: 2026-07-12

The first reviewed strict-compatibility baseline used Picket commit
`0b8d4ee45b0caa06db089e7a1bcee1b4dc29f6a4`, Scout packages `0.4.4`, and
Gitleaks commit `4c232b5014f7618360bd992b4c489cb055881c6b`. The checked-in
`gitleaks-compatible-tracked` scenario staged 455 tracked files from `src/` and
`tests/` totaling 4.26 MiB. Its corpus manifest SHA-256 was
`d241be5cbf2ad33ab0aa2246d317eb30623142cb3a5253470fef8bb27d39b785`.

Both scanners produced 30 findings with canonical finding-set SHA-256
`f698ed7bfd496569085b1655ecc297596d56c34820797597b86540724f4a197e`.
The parity gate passed.

| Tool | Pre-warmup elapsed | Warm elapsed median | Warm CPU median | Warm peak working set median |
|---|---:|---:|---:|---:|
| Picket | 594.43 ms | 592.24 ms | 3,375.00 ms | 88.34 MiB |
| Gitleaks | 1,762.73 ms | 1,704.48 ms | 7,828.12 ms | 88.87 MiB |

On this scenario and host, Picket's warm elapsed median was 2.88 times faster.
This is not a claim about other repositories, rules, source modes, or machines.
The run used Windows `10.0.26200`, NTFS, an AMD64 Family 26 Model 68 processor
with 32 effective processors, .NET `10.0.9`, and SDK `10.0.301`. Host-level
filesystem caches were not reset, so the pre-warmup values are not cold OS-cache
measurements.

The `native-cache-tracked` run used Picket commit
`efa74bf9aca0de74dc150e961f2ac86a2e59d42e` and preserved the same 55
canonical findings with and without its secret-hash-only cache. The uncached
warm median was 8,052.54 ms with 104.55 MiB
peak working set. The cache-hit warm median was 150.51 ms with 32.75 MiB peak
working set and reported 442 hits, zero misses, and zero writes. These values
establish a regression baseline for Picket's own incremental mode; they are not
a competitor comparison.

### Reviewed Capability Baseline: 2026-07-12

The first reviewed capability-separated baseline used Picket commit
`a81363ec0d0994b9ab00df3ddfd8a5af1599d855` with Scout packages `0.4.4`,
TruffleHog commit `f2cd191b97098913a07522227d2b5e40e57252f4`
(`v3.95.8-1-gf2cd191b9`), and Kingfisher commit
`78904df5ea7354a7dc3700e3c41a124524d23083` (`1.105.0`). The checked-in
`native-filesystem-competitors` scenario staged 455 tracked files from `src/`
and `tests/` totaling 4,464,165 bytes. Its corpus manifest SHA-256 was
`d4db6f3f916ee638591ade8413ec90d63abac8842c81b9ad3a5d2d6ca11e8b11`.

| Tool | Findings | Pre-warmup elapsed | Warm elapsed median | Warm elapsed p95 | Warm CPU median | Warm peak working set median |
|---|---:|---:|---:|---:|---:|---:|
| Picket native | 55 | 8,419.04 ms | 7,920.62 ms | 8,488.61 ms | 25,921.88 ms | 107.52 MiB |
| TruffleHog filesystem | 30 | 1,362.75 ms | 1,350.40 ms | 1,421.73 ms | 437.50 ms | 116.63 MiB |
| Kingfisher filesystem | 21 | 258.13 ms | 246.87 ms | 260.31 ms | 453.12 ms | 152.72 MiB |

The finding sets are not equivalent. Picket exercised its native rules,
offline filtering, decoding, archive traversal, and ignore behavior;
TruffleHog and Kingfisher exercised their own defaults with network
verification and update checks disabled. The scenario therefore has no parity
group and these timings do not identify a universal winner. They establish a
repeatable full-capability baseline for later profiling after implementation is
feature complete.

The run used Windows `10.0.26200`, NTFS, an AMD64 Family 26 Model 68 processor
with 32 effective processors, 47.13 GiB of GC-visible memory, .NET `10.0.9`, and
SDK `10.0.301`. Host-level filesystem caches were not reset, so the pre-warmup
values are not cold OS-cache measurements.

### Reviewed Report-Writing Baseline: 2026-07-12

The first end-to-end report fan-out baseline used Picket commit
`dc7383e6dace5e6e5595558a08dfe4c9c1c84621`, Scout packages `0.4.4`, and the
`release-speed` Windows x64 Native AOT executable. The executable was
13,666,816 bytes and identified the same commit in `picket version`. The
scenario staged 455 committed files from `src/` and `tests/` totaling 4,473,072
bytes. Its corpus manifest SHA-256 was
`00d9a1849f40342e86063bfdbc43f368cd8d88016c20813b36ce9976906dc792`.

Both variants produced 55 primary JSON Lines findings with canonical
finding-set SHA-256
`3ed86436141af5b83478ad97d2777c3883aa8dadbff8b4efa2b9a4d9a264813a`.
The fan-out variant also produced three deterministic reports totaling 678,075
bytes. Their content manifest SHA-256 was
`fbc8bdc3d0c00ecf966c8c2013645a1fd615a206b97e2c1416541697a52a2ad1`
in every retained round.

| Report set | Pre-warmup elapsed | Warm elapsed median | Warm elapsed p95 | Warm CPU median | Warm peak working set median |
|---|---:|---:|---:|---:|---:|
| JSON Lines | 8,377.18 ms | 8,051.07 ms | 8,186.68 ms | 26,250.00 ms | 101.67 MiB |
| JSON Lines, SARIF, HTML, and TOON | 8,163.54 ms | 8,181.89 ms | 8,254.22 ms | 26,265.63 ms | 104.28 MiB |

The observed warm-median difference was 130.82 ms, or 1.62% of the JSON Lines
control. This is an end-to-end repository result, not an isolated writer
microbenchmark; use `ReportWriterBenchmarks` for allocation and writer-only
throughput. Host-level filesystem caches were not reset. The host otherwise
matched the reviewed Windows conditions above: Windows `10.0.26200`, NTFS, 32
effective processors, .NET `10.0.9`, and SDK `10.0.301`.

Release automation writes `release-artifacts.json` after assembling all final
payloads. The deterministic manifest records each archive, installer, NuGet
bundle, Marketplace package, and package-manager bundle with its exact byte
count and SHA-256. Mutable checksum sidecars are excluded. The manifest is
included in `checksums.txt`, attested, and published with the release so package
size regressions can be compared without downloading and unpacking every asset.

Steady-state scan scenarios compile deferred regexes during global setup. The
fresh-rule-set scenarios create a new compiled rule set for every operation and
therefore include candidate regex compilation on first use. Compilation
scenarios force every deferred regex so they measure actual Scout compilation,
not only Picket rule-wrapper and fingerprint construction.

Filesystem and baseline file evaluation is bounded by source count, effective CPU
availability, and current memory pressure. [`Environment.ProcessorCount`](https://learn.microsoft.com/en-us/dotnet/api/system.environment.processorcount?view=net-10.0)
honors processor affinity and CPU limits. Picket uses
[`GC.GetGCMemoryInfo()`](https://learn.microsoft.com/en-us/dotnet/api/system.gc.getgcmemoryinfo?view=net-10.0)
and follows the 70% medium-pressure and 90% high-pressure bands used by
[`ArrayPool<T>` in the .NET runtime](https://github.com/dotnet/runtime/blob/41ec8890ed351082aecb9ec6da189a450941b18f/src/libraries/System.Private.CoreLib/src/System/Buffers/Utilities.cs#L37-L58).
Low pressure permits one worker per effective processor, medium pressure halves
that degree, and high pressure uses one worker. Results are merged in source
order, so report bytes do not depend on scheduling. Checkpointed scans commit
serially because a checkpoint low-water mark must always identify a complete
source-manifest prefix.

For incremental-scan changes, run with `--cache-dir` and opt-in diagnostics.
The `cpu.json`, `mem.json`, and `trace.jsonl` artifacts include `scanInputs`,
`findings`, `cacheHits`, `cacheMisses`, and `cacheWrites` counters, which are the
preferred evidence for cache hit-rate changes.

## Large Local Files

Local files larger than 100,000 bytes are read through pooled, bounded
fragments. Strict Gitleaks-compatible commands use a 100,000-byte primary
fragment and read ahead by at most 25,000 bytes to a blank-line boundary. They
do not overlap fragments because a hard boundary is part of the pinned
Gitleaks behavior.

Binary classification uses only the first 100,000 bytes, before safe-boundary
read-ahead, matching the compatibility source reader. Binary files therefore
stop after one bounded probe even when native caching is enabled.

Native filesystem and baseline scans also inspect a combined window containing
the current fragment and the final 64 KiB of the preceding fragment. The
overlap expands backward to a line boundary when one is available, and duplicate
findings from the standalone and combined windows are removed. Source positions
remain absolute, and `blobSha256` identifies the complete file.

This path does not allocate an array proportional to the file length, so local
files beyond the managed single-array limit can be scanned or rejected as
binary without a full-buffer failure. A positive `--max-target-megabytes`
continues to skip files above the requested cap.

For repository-level comparison:

- use `scripts/Capture-CompatibilityOracle.cs` for Gitleaks parity,
- use `scripts/Capture-GitHubSecretScanningOracle.cs` for sanitized hosted
  GitHub secret-scanning alert metadata,
- use `scripts/Compare-GitHubSecretScanningOracle.cs` to compare native JSONL
  scan output against mapped hosted alert classes and locations,
- use `picket git . --profile picket --report-format jsonl` when captured
  hosted locations include commit SHAs,
- compare native scans against the GitHub alert classes and locations only after
  confirming whether differences are compatibility allowlists, history-only
  alerts, or true rule gaps.

## Fair Competitor Comparisons

End-to-end speed comparisons are useful only after the behavior being compared is
feature complete. Compare Picket with Gitleaks, TruffleHog, Kingfisher, and other
local references only when the scenario can be described precisely enough to
review.

Each comparison must record:

- tool name, version, commit SHA, and command line,
- Picket commit SHA, build profile, and runtime identifier,
- OS, CPU, memory, filesystem, runner type, and .NET SDK,
- source payload, repository commit range, path filters, and ignored paths,
- rule/config set and whether compatibility or native behavior is selected,
- output format, report destination, redaction, and baseline/cache settings,
- whether verification, source enumeration, archive traversal, decoding, and
  history scanning are enabled,
- cold-cache and warm-cache timing separately.

Do not compare a scan-only Picket run against a competitor run that also performs
network verification, source enumeration, archive expansion, or full git history
unless those costs are explicitly the scenario being measured. When capabilities
cannot be made equivalent, report them as separate measurements instead of a
single winner.

## Scout Escalation

Scout is a dependency through NuGet packages. If profiling attributes a
material bottleneck to a Scout package, capture a minimal reproducer, benchmark
or trace, exact package version, command line, input shape, and expected impact.
Open a concise Scout issue with that evidence.

If the Scout bottleneck is critical enough to block Picket's feature-complete
path, pause Picket implementation work and fix Scout first. Non-critical Scout
performance issues stay tracked, but Picket optimization waits until the
late-project hardening phase.
