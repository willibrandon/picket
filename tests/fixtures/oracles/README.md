# Oracle Fixtures

This directory holds reviewed compatibility oracle fixtures promoted from
ignored raw captures.

Do not copy raw `artifacts/oracles` output here. Use
`scripts/Promote-CompatibilityOracle.cs` with a redaction map unless the
capture is a synthetic no-secret fixture and `-AllowUnredacted` is intentional.

Promoted fixtures must not contain machine-specific paths, executable paths, or
unredacted realistic credentials.

When a fixture is expected to report relative file paths, capture it with
`-WorkingDirectory <fixture-root>` and relative command arguments such as
`-Source . -Config .gitleaks.toml`.
