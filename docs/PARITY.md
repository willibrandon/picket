# Picket Compatibility Ledger

This ledger records intentional differences from the pinned Gitleaks reference.
Each entry must have an oracle or regression test before the behavior is treated
as deliberate.

## Diagnostics Output

- **Upstream behavior:** Gitleaks `--diagnostics=cpu,mem,trace` writes Go
  profiler artifacts (`cpu.pprof`, `mem.pprof`, `trace.out`), and
  `--diagnostics=http` starts a local pprof server.
- **Picket behavior:** Picket `--diagnostics=cpu,mem,trace` writes AOT-safe
  structured diagnostics (`cpu.json`, `mem.json`, `trace.jsonl`) to
  `--diagnostics-dir` or the current directory. `--diagnostics=http` fails
  explicitly because Picket does not yet ship an equivalent local diagnostics
  server.
- **Mode/profile affected:** Gitleaks-compatible CLI commands.
- **Reason:** Go pprof artifacts are not a native .NET diagnostic format.
  Picket's default Native AOT artifact needs deterministic, trim-safe, low-risk
  diagnostics that do not require dynamic runtime infrastructure.
- **User impact:** Automation that only needs the flag to collect local
  diagnostics works, but consumers expecting Go pprof files or an HTTP pprof
  endpoint need to use Picket's JSON/JSONL diagnostics or wait for a dedicated
  diagnostics profile/server.
- **Test name:** `DirectoryScanWritesDiagnosticsArtifacts`,
  `DirectoryScanRejectsHttpDiagnostics`.
- **Migration guidance:** Use `--diagnostics=cpu,mem,trace` with
  `--diagnostics-dir <dir>` and collect `cpu.json`, `mem.json`, and
  `trace.jsonl`.
