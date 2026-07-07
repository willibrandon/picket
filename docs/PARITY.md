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
  `--diagnostics-dir` or the current directory. `--diagnostics=http` starts a
  loopback-only diagnostics server at `http://localhost:6060/debug/pprof/`, but
  serves Picket JSON/JSONL snapshots instead of Go pprof profiles.
- **Mode/profile affected:** Gitleaks-compatible CLI commands.
- **Reason:** Go pprof artifacts are not a native .NET diagnostic format.
  Picket's default Native AOT artifact needs deterministic, trim-safe, low-risk
  diagnostics that do not require dynamic runtime infrastructure.
- **User impact:** Automation that only needs the flag to collect local
  diagnostics works, and `http` mode exposes live CPU, heap, and trace
  snapshots while the process is running. Consumers expecting Go pprof file or
  wire formats need to use Picket's JSON/JSONL diagnostics instead.
- **Test name:** `DirectoryScanWritesDiagnosticsArtifacts`,
  `StdinScanServesHttpDiagnostics`, `DirectoryScanRejectsHttpDiagnosticsDirectory`,
  `DirectoryScanRejectsMixedHttpDiagnostics`.
- **Migration guidance:** Use `--diagnostics=cpu,mem,trace` with
  `--diagnostics-dir <dir>` and collect `cpu.json`, `mem.json`, and
  `trace.jsonl`, or use `--diagnostics=http` and read
  `/debug/pprof/profile`, `/debug/pprof/heap`, and `/debug/pprof/trace`.

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

## Native GitHub Token Coverage

- **Upstream behavior:** The pinned Gitleaks default config includes GitHub App,
  OAuth, refresh, fine-grained PAT, and classic PAT rules under `github-*` rule
  IDs, with Gitleaks metadata and selected compatibility allowlists.
- **Picket behavior:** Strict Gitleaks-compatible scans keep those upstream
  `github-*` rules unchanged. The embedded native default disables the inherited
  GitHub token rules and replaces them with `picket-github-*` rules in
  `picket-default`, including Picket provider metadata, remediation links, and
  offline/live validation support.
- **Mode/profile affected:** Picket-native `scan`, `verify`, and `analyze`
  when no target-local or environment config replaces the embedded native
  default.
- **Reason:** Native findings should be stable Picket records with Picket-owned
  rule IDs and metadata, while strict compatibility must continue to report the
  pinned Gitleaks IDs.
- **User impact:** Native default scans report GitHub token findings once under
  `picket-github-*` IDs instead of duplicating them under both native and
  compatibility IDs. Custom configs that explicitly define `github-*` rules are
  still validated and verified.
- **Test name:** `PicketConfigLoaderEmbeddedDefaultUsesNativeGitHubRules`,
  `NativeScanUsesEmbeddedGitHubPersonalAccessTokenRule`.
- **Migration guidance:** Use strict compatibility commands for exact Gitleaks
  rule identity. Use native `scan`, `verify`, or `analyze` for Picket metadata,
  validation states, and stable native rule IDs.

## Native Sourcegraph Token Coverage

- **Upstream behavior:** The pinned Gitleaks `sourcegraph-access-token` rule can
  report either prefixed `sgp_` Sourcegraph tokens or any 40-hex value when a
  Sourcegraph keyword appears in the same scan fragment.
- **Picket behavior:** Strict Gitleaks-compatible scans keep the inherited
  `sourcegraph-access-token` rule unchanged. The embedded native default
  disables that inherited rule and replaces it with
  `picket-sourcegraph-access-token`, which requires the `sgp_` token prefix.
- **Mode/profile affected:** Picket-native `scan`, `verify`, and `analyze`
  when no target-local or environment config replaces the embedded native
  default.
- **Reason:** Native defaults should avoid reporting ordinary commit hashes as
  access tokens while keeping strict Gitleaks compatibility intact.
- **User impact:** Native default scans no longer report bare 40-hex hashes as
  Sourcegraph credentials. Prefixed Sourcegraph access tokens still produce
  findings with Picket-owned rule metadata.
- **Test name:** `ScanUsesNativeSourcegraphAccessTokenRule`,
  `ScanSkipsBareCommitHashForNativeSourcegraphAccessTokenRule`,
  `ScanFindsNativeSourcegraphAccessToken`.
- **Migration guidance:** Use strict compatibility commands for pinned Gitleaks
  behavior. Use native `scan`, `verify`, or `analyze` for lower-noise
  Sourcegraph token detection.

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
  site for the same secret. Hosted historical alerts should be compared against
  native git-history reports, not current-tree filesystem scans, because GitHub
  alert locations include the commit that introduced the secret.
- **Test name:** `ScanFindsNativeRuleMatchInCSharpStringConcat`.
- **Migration guidance:** Use strict compatibility commands for Gitleaks byte
  parity. Use native `scan` when source-code literal normalization is desired.

## Git Log Option Guard

- **Upstream behavior:** Gitleaks forwards `--log-opts` tokens to `git log`
  after shell-style splitting.
- **Picket behavior:** Picket accepts plain revision ranges and a small allowlist
  of safe revision-filter options, but rejects output, pager, external-diff, and
  unknown option-shaped tokens before `git` starts.
- **Mode/profile affected:** `picket git`.
- **Reason:** `git log` options such as `--output=<path>` can create or
  overwrite files even though Picket correctly avoids shell execution.
- **User impact:** Common ranges such as `main..HEAD` and safe filters such as
  `--all`, `--branches`, `--tags`, `--since`, `--author`, `--grep`, and
  `--max-count` remain usable. Workflows that relied on arbitrary `git log`
  options need an explicit Picket feature instead.
- **Test name:** `EnumerateRejectsUnsafeLogOptionsWithoutCreatingOutput`.
- **Migration guidance:** Pass revision ranges directly through `--log-opts`.
  Avoid using `--log-opts` as a general `git log` escape hatch.
