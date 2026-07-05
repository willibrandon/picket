# Oracle Fixtures

This directory holds reviewed compatibility oracle fixtures promoted from
ignored raw captures.

Do not copy raw `artifacts/oracles` output here. Use
`scripts/Promote-CompatibilityOracle.ps1` with a redaction map unless the
capture is a synthetic no-secret fixture and `-AllowUnredacted` is intentional.

Promoted fixtures must not contain machine-specific paths, executable paths, or
unredacted realistic credentials.
