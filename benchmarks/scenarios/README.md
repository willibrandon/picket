# End-to-End Performance Scenarios

Scenario manifests are consumed by
`scripts/Measure-ScannerPerformance.cs`. The current schema is
`picket.performance-scenario.v1`.

`gitleaks-compatible-tracked.json` stages tracked `src/` and `tests/` files into
a generated corpus, then runs Native AOT Picket and the pinned Gitleaks binary
with the same strict-compatible directory command. Set `PICKET_BIN` and
`PICKET_GITLEAKS_BIN` to direct executable paths. The executable names on
`PATH` are fallbacks.

The manifest records the capability conditions, corpus selection, process
arguments, accepted exit codes, report parser, and optional parity group. Paths
use `{repositoryRoot}`, `{scenarioDirectory}`, `{corpus}`, and `{report}`
placeholders. Arguments are passed as individual process arguments, not through
a shell.

Only assign the same `ParityGroup` to tools expected to produce the same finding
set. Different built-in rules, decoders, validation behavior, history modes, or
source traversal make a throughput comparison capability-separated rather than
parity-equivalent.

Generated work and scanner reports are deleted by default. `-KeepWork` retains
them for debugging and can retain secret material; use it only with trusted
inputs and an access-controlled artifact directory.
