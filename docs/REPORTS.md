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

Gitleaks-compatible git, filesystem, and stdin commands can opt into this native report surface with `--profile picket`. Without that explicit profile, `picket git`, `picket dir`, `picket file`, `picket directory`, and `picket stdin` keep Gitleaks-compatible report selection and reject native-only formats such as JSON Lines, HTML, TOON, and GitLab code-quality.

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
- stable Picket fingerprint,
- validation state,
- severity and confidence,
- rule pack, provider, and rule documentation URL when available,
- provenance,
- decode path,
- baseline status,
- ignore reason,
- remediation links.

Native fingerprints are versioned as `picket:v1:<sha256>`. The hash input includes the normalized logical path, rule ID, secret or match hash, and decode path. It intentionally excludes line, column, commit, author, and message metadata so native triage IDs remain stable when a finding moves inside the same file or appears across multiple commits. Gitleaks-compatible reports keep Gitleaks fingerprints.

`picket analyze` writes incident-response reports as JSON, JSON Lines, or text. Analysis records include provider, credential type, stable fingerprint, secret hash, validation state, risk, identity, scopes, reachable resources, risk summary, recommended actions, revocation availability, revocation command templates, revocation guidance, and non-secret evidence. `picket analyze --live` can enrich analysis with provider metadata from guarded live validation; offline analysis keeps identity, scopes, and resources as explicit offline placeholders.

Revocation command templates never include raw secret values. Picket emits concrete provider commands when the finding includes enough non-secret identifiers, such as an AWS access key ID, Azure Storage account name, or GCP service-account key ID. GitHub token reports include a placeholder command for the GitHub credential revocation API rather than writing the detected token. When the provider supports revocation but the report cannot safely or accurately produce an exact command, `revocationAvailable` remains `true`, `revocationCommands` is empty or placeholder-based, and `revocationGuidance` explains the provider workflow.

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

`picket view <report>` reads Picket JSON, Picket JSONL, Gitleaks JSON, TruffleHog JSON/JSONL, GitLab code-quality JSON, SARIF, and HTML summaries. It prints non-secret counts and up to ten finding summaries. `--open` launches the report with the operating system shell after the summary is written. Picket HTML reports include embedded non-secret summary metadata so `picket view` can show counts and locations without scraping visible secret or match cells. Arbitrary HTML reports keep the generic `html` fallback with unknown counts.

Report readers must not print raw secrets. They extract rule IDs, detector names, paths, line numbers, fingerprints, counts, and format names for triage. Imported TruffleHog reports synthesize fingerprints from the detector, path, and line when the report does not provide one, and never use `Raw`, `RawV2`, or `Redacted` in terminal output.
