# Reports

Picket has two reporting surfaces: Gitleaks-compatible reports for replacement workflows and Picket-native reports for richer triage.

## Gitleaks-Compatible Reports

Compatibility commands support:

- JSON
- CSV
- JUnit XML
- SARIF
- template output

Compatibility writers preserve the Gitleaks-shaped fields, names, ordering, and behavior that downstream tools depend on. They do not add Picket-native validation, severity, confidence, provenance, or secret-hash fields.

## Picket-Native Reports

Native commands support:

- JSON
- JSON Lines
- SARIF
- CSV
- JUnit XML
- HTML
- TOON
- GitLab code-quality JSON

Native finding records use schema `picket.finding.v1`. Rich JSON reports use schema `picket.report.v1`.

Native reports can include:

- rule ID and description,
- file and symlink path,
- line and column range,
- match and secret text according to redaction settings,
- secret, match, and source blob SHA-256 hashes,
- source line,
- commit and author metadata when available,
- entropy,
- tags,
- fingerprint,
- validation state,
- severity and confidence,
- provenance,
- decode path,
- baseline status,
- ignore reason,
- remediation links.

## Report Selection

When `--report-format` is provided, it controls the writer. Without `--report-format`, Picket infers the writer from `--report-path`:

- `.csv` selects CSV.
- `.json` selects JSON.
- `.sarif` selects SARIF.
- `.jsonl` selects JSON Lines for native commands.
- `.html` or `.htm` selects HTML for native commands.
- `.toon` selects TOON for native commands.
- `.junit.xml` selects JUnit for native commands.
- `gl-code-quality-report.json` or `*.gitlab-code-quality.json` selects GitLab code-quality for native commands.

When no path or format is supplied, JSON is written to standard output.

## Triage View

`picket view <report>` reads Picket JSON, Picket JSONL, Gitleaks JSON, TruffleHog JSON/JSONL, GitLab code-quality JSON, SARIF, and HTML summaries. It prints non-secret counts and up to ten finding summaries. `--open` launches the report with the operating system shell after the summary is written.

Report readers must not print raw secrets. They extract rule IDs, detector names, paths, line numbers, fingerprints, counts, and format names for triage. Imported TruffleHog reports synthesize fingerprints from the detector, path, and line when the report does not provide one, and never use `Raw`, `RawV2`, or `Redacted` in terminal output.
