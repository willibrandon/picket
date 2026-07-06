# Performance

Picket performance work is measured with BenchmarkDotNet for engine-level
changes and with scanner-oracle scripts for end-to-end behavior.

Run the engine benchmarks with:

```powershell
dotnet run -c Release --project benchmarks/Picket.Benchmarks -- --filter "*SecretScanBenchmarks*"
```

Current benchmark scenarios cover:

- native default rules over the embedded Gitleaks config,
- strict Gitleaks-compatible rules over the same file,
- the focused native Google API key rule over the embedded Gitleaks config as a
  local hosted-alert parity proxy,
- native default rules over credential-analyzer tests,
- native rule compilation.

Run benchmarks before and after hot-path changes and keep the output in ignored
`BenchmarkDotNet.Artifacts/` or `artifacts/` directories. Do not commit
machine-specific benchmark output unless it has been normalized into a reviewed
fixture.

For repository-level comparison:

- use `scripts/Capture-CompatibilityOracle.ps1` for Gitleaks parity,
- use `scripts/Capture-GitHubSecretScanningOracle.ps1` for sanitized hosted
  GitHub secret-scanning alert metadata,
- compare native scans against the GitHub alert classes and locations only after
  confirming whether differences are compatibility allowlists, history-only
  alerts, or true rule gaps.
