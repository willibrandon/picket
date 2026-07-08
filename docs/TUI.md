# Terminal UI

Picket includes an interactive scanner console for report triage.

## Commands

`picket tui <report>` opens a full-screen scanner console when the `picket-tui` companion executable is installed beside `picket` or is available on `PATH`.

`picket-tui <report>` runs the companion directly.

`picket tui --scan` and `picket-tui --scan` open the native scan workspace without loading an existing report.

`picket tui <report> --flow` and `picket-tui <report> --flow` render interactive steps inline in the normal terminal buffer. `picket-tui --flow` can prompt for the report path before loading the report.

## Supported Inputs

The TUI reads the same summary inputs as `picket view`:

- Picket JSON and JSON Lines,
- Gitleaks JSON,
- TruffleHog JSON and JSON Lines,
- GitLab code-quality JSON,
- SARIF,
- Picket HTML summary metadata.

The initial console uses only non-secret fields: rule IDs, detector names, paths, line numbers, fingerprints, counts, and format names. It does not load raw secret, match, or source-line evidence into TUI state.

## Full-Screen Console

The full-screen console is designed as a scanner console:

- a top command strip with view switching and Run scan,
- a sectioned Scan page for target selection, output settings, validation filters, limits, command preview, status, scan timing, report path, and result counts,
- a findings triage list with stable row focus,
- focused-finding details,
- rule and file frequency views,
- scanner output on the Logs view,
- a compact status footer with non-wrapping command hints.

Opening without a report starts on the Scan page. Opening an existing report with findings starts on the Findings page. The interface favors readable scanner-console density, predictable keyboard navigation, and text status over decorative layout.

## Native AOT Packaging

The companion is a separate executable for packaging and surface-area isolation. It is published as Native AOT with the same release profiles as `picket` and is staged beside `picket` in RID-specific release archives.

Keeping the TUI in `picket-tui` prevents Hex1b terminal UI code and terminal-native assets from increasing the default scanner binary while preserving a first-class installed experience through `picket tui`.

## Scan Workspace

The TUI includes a scan workspace for running native scans interactively. It builds and displays the command-equivalent `picket scan` request, then runs the scanner executable.

The workspace keeps the normal path short: choose a target, check the command preview, press Run scan, then jump to Findings when row triage is needed. It exposes commonly changed options directly:

- local path or source-host target,
- profile and config,
- ignore behavior,
- verification mode,
- result filters,
- archive and target-size limits,
- redaction,
- report formats and output paths.

The Scan page groups controls into Source, Output, Validation, and Limits sections so the default view stays readable while every scan option remains reachable.

For GitHub targets, the workspace includes repository, organization, user, gist, authenticated-gist, and user-gist selectors; repository type and issue state filters; issue, release, and Actions artifact toggles; token environment variable; ref and pull request selectors; source API endpoint override; and explicit source endpoint policy toggles.

For Azure DevOps targets, the workspace includes endpoint, organization, project, repository, branch, pull request, token environment variable, token kind, build ID, release ID, wiki/artifact/log/release-artifact toggles, artifact and log size caps, and explicit source endpoint policy toggles.

During a scan it shows text status, exit code state, started/completed/elapsed-time diagnostics, output availability, and cancellation status. The Logs view owns captured stdout/stderr so the Scan page does not compete with finding triage. While the scanner is running, the Run scan button becomes Cancel and `Ctrl+C` requests cancellation without closing the console. It prepares the report output directory before launch, writes normal Picket reports, reloads the generated report summary when the scan completes, and shows the loaded finding count and report path on the Scan page. The dedicated Findings view uses the same non-secret report readers as `picket view` and owns filtering, selected-row focus, finding details, and finding-specific yank text.

## Inline Flow Mode

Flow mode renders interactive steps in the normal terminal buffer. Steps reserve terminal rows, complete to frozen scrollback output, and can open the same full-screen scanner console when a larger workspace is needed.

Use Flow mode when the user should keep terminal history visible, such as guided report selection or a short triage summary before returning to a scriptable shell session.

## Testing

TUI changes require first-class Hex1b tests. Tests should run the actual widget tree in a headless Hex1b terminal, wait for rendered screen state, capture terminal snapshots, verify keyboard exits/navigation, and exercise practical desktop and narrow terminal dimensions.

## Input and Contrast

The TUI follows WCAG 2.2 AA principles adapted to terminal UI:

- every action is keyboard reachable,
- focus is visible for controls, navigation, and focused rows,
- color is never the only status signal,
- normal text contrast targets at least 4.5:1,
- borders, focus indicators, and other non-text UI target at least 3:1,
- progress and long-running states include text status.
