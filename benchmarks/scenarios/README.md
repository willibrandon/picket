# End-to-End Performance Scenarios

Scenario manifests are consumed by
`scripts/Measure-ScannerPerformance.cs`. The current schema is
`picket.performance-scenario.v1`.

`gitleaks-compatible-tracked.json` stages tracked `src/` and `tests/` files into
a generated corpus, then runs Native AOT Picket and the pinned Gitleaks binary
with the same strict-compatible directory command. Set `PICKET_BIN` and
`PICKET_GITLEAKS_BIN` to direct executable paths. The executable names on
`PATH` are fallbacks.

`native-cache-tracked.json` runs the same Native AOT Picket binary and native
rule set with cache disabled and with an initially empty secret-hash-only cache.
The recorded cold run populates the cache; the discarded warmup and recorded
warm runs reuse it. Both tools emit CPU diagnostics, and the harness extracts
only scan-input, finding, cache-hit, cache-miss, and cache-write counters. Keep
the manifest's single cold iteration when using this cache-state contract.

`native-filesystem-competitors.json` runs Picket native mode, TruffleHog, and
Kingfisher over the same immutable tracked-file corpus with Git history, live
verification, update checks, and persistent caches disabled. Set `PICKET_BIN`,
`PICKET_TRUFFLEHOG_BIN`, and `PICKET_KINGFISHER_BIN` to direct executable paths.
The tools retain their own built-in rules, offline filtering, decoders, archive
handling, ignores, and report schemas. The scenario is therefore
capability-separated and intentionally has no parity group or universal winner.

`native-report-writing-tracked.json` compares one native JSON Lines report with
the same scan writing JSON Lines, SARIF, HTML, and TOON. Both variants use the
same Native AOT binary and primary JSON Lines parity group. The fan-out variant
declares every additional path so the harness verifies each file and records
its aggregate byte count and stable content manifest hash.

The manifest records the capability conditions, corpus selection, process
arguments, accepted exit codes, report parser, and optional parity group. Paths
use `{repositoryRoot}`, `{scenarioDirectory}`, `{session}`, `{corpus}`, and
`{report}` placeholders. `{session}` identifies the generated per-measurement
workspace and is suitable for persistent caches shared across rounds. Arguments
are passed as individual process arguments, not through a shell.

Tools may declare `DiagnosticsFile` and `DiagnosticsFormat`. The supported
`picket-cpu-json` format records only bounded artifact metadata and non-secret
scan counters in the result. Diagnostic text and timestamps are not retained.

`ReportSource` defaults to `file`, where the scanner receives `{report}` in its
arguments. Use `"ReportSource": "stdout"` for scanners such as TruffleHog that
emit machine-readable findings only to standard output. The harness streams
those bytes directly to the ephemeral report file instead of retaining decoded
finding text.

`ReportFileExtension` defaults to `.report`. Set it to a real extension when a
scanner infers its writer from the report path. `AdditionalReportPaths` lists
other files that the invocation must produce. Their contents are not retained;
the result records only count, aggregate size, and a manifest hash.

Each resolved tool records the direct executable byte count and SHA-256. Set
`RequireRepositoryCommitInVersion` for binaries whose version output embeds
their source revision. The harness then rejects a stale executable instead of
attributing its measurements to the scenario repository commit.

`ParityExcludedProperties` may contain only `line`, `match`, `matchSha256`, and
`secret`. Use it when comparing a secret-hash-only cache hit with an uncached
scan because that cache mode omits raw evidence and cannot reconstruct the
redacted match context used to calculate `matchSha256`. Report hashes still
expose byte-level differences, and every other finding property remains part of
the canonical parity hash.

Only assign the same `ParityGroup` to tools expected to produce the same finding
set. Different built-in rules, decoders, validation behavior, history modes, or
source traversal make a throughput comparison capability-separated rather than
parity-equivalent.

Generated work and scanner reports are deleted by default. `-KeepWork` retains
them for debugging and can retain secret material; use it only with trusted
inputs and an access-controlled artifact directory.
