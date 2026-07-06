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

## Native Google API Key Coverage

- **Upstream behavior:** The pinned Gitleaks `gcp-api-key` rule detects Google
  API key shapes but also carries rule allowlists for several example-looking
  values in the embedded Gitleaks config.
- **GitHub behavior:** GitHub Secret Protection is a hosted proprietary oracle.
  Its secret scanning alerts classify the same credential family as
  `google_api_key` and can flag values that Gitleaks suppresses as compatibility
  allowlist examples.
- **Picket behavior:** Strict Gitleaks-compatible scans keep the Gitleaks
  allowlist behavior. Native scans include `picket-google-api-key` in the
  `picket-default` rule pack and `picket-*` rule packs do not inherit Gitleaks
  compatibility global allowlists.
- **Mode/profile affected:** Picket-native `scan` and `--profile picket`.
- **Reason:** Native coverage should track modern hosted scanner expectations
  where that can be done locally and safely, while strict compatibility must not
  change Gitleaks results.
- **User impact:** Native scans may report Google API key examples that strict
  Gitleaks-compatible scans suppress through rule-specific or global
  compatibility allowlists. The finding uses a Picket rule ID, provider
  metadata, and offline structural validation.
- **Test name:** `ScanSeparatesNativeGoogleApiKeyDetectionFromGitleaksAllowlist`.
- **Migration guidance:** Use strict compatibility commands for Gitleaks byte
  parity. Use native `scan` when comparing to hosted GitHub secret scanning
  alerts or when richer Picket metadata is preferred.

## Native C# String-Literal Concatenation

- **Upstream behavior:** Gitleaks scans source bytes and does not evaluate C#
  string-literal concatenations before matching.
- **GitHub behavior:** GitHub Secret Protection can alert on credentials built
  from deterministic source-code string literals.
- **Picket behavior:** Strict Gitleaks-compatible scans keep byte-oriented
  Gitleaks behavior. Native `.cs` scans evaluate literal-only
  `string.Concat(...)` calls and binary `+` literal chains as derived input,
  then attach `csharp-string-concat` decode provenance to any findings.
- **Mode/profile affected:** Picket-native `scan`, `verify`, `analyze`, and
  `rules test` when the logical path ends in `.cs`.
- **Reason:** Native hosted-alert parity should catch simple split literals
  without requiring live services, dynamic code, or a general C# compiler.
- **User impact:** Native scans can report additional findings in C# source when
  a credential is split across deterministic string literals. Findings point to
  the literal construction span; hosted scanners may report a downstream call
  site for the same secret.
- **Test name:** `ScanFindsNativeRuleMatchInCSharpStringConcat`.
- **Migration guidance:** Use strict compatibility commands for Gitleaks byte
  parity. Use native `scan` when source-code literal normalization is desired.
