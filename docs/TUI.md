# Terminal UI

Picket includes an interactive scanner console for report triage.

## Commands

`picket tui <report>` opens a full-screen scanner console when the `picket-tui` companion executable is installed beside `picket` or is available on `PATH`.

`picket-tui <report>` runs the companion directly.

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

- a top menu/status row,
- a navigation rail,
- a findings table with stable row focus,
- focused-finding details,
- rule and file frequency views,
- an accessibility view,
- a diagnostics/status panel.

The interface favors dense tables, predictable keyboard navigation, and text status over decorative layout.

## Native AOT Packaging

The companion is a separate executable for packaging and surface-area isolation. It is published as Native AOT with the same release profiles as `picket` and is staged beside `picket` in RID-specific release archives.

Keeping the TUI in `picket-tui` prevents Hex1b terminal UI code and terminal-native assets from increasing the default scanner binary while preserving a first-class installed experience through `picket tui`.

## Scan Workspace

The TUI also has a planned scan workspace for running scans interactively. It uses the same engine and option model as `picket scan`.

The workspace should let users configure:

- local path or source-host target,
- profile and config,
- ignore behavior,
- verification mode,
- result filters,
- archive and target-size limits,
- redaction,
- report formats and output paths.

During a scan it shows live progress, discovered targets, warnings, findings, validation state, elapsed time, and cancellation status. It writes normal Picket reports and shows the command-equivalent settings before execution so the TUI does not become a separate behavior path.

## Inline Flow Mode

Flow mode renders interactive steps in the normal terminal buffer. Steps reserve terminal rows, complete to frozen scrollback output, and can open the same full-screen scanner console when a larger workspace is needed.

Use Flow mode when the user should keep terminal history visible, such as guided report selection or a short triage summary before returning to a scriptable shell session.

## Testing

TUI changes require first-class Hex1b tests. Tests should run the actual widget tree in a headless Hex1b terminal, wait for rendered screen state, capture terminal snapshots, verify keyboard exits/navigation, and exercise practical desktop and narrow terminal dimensions.

## Accessibility

The TUI follows WCAG 2.2 AA principles adapted to terminal UI:

- every action is keyboard reachable,
- focus is visible for controls, navigation, and focused rows,
- color is never the only status signal,
- normal text contrast targets at least 4.5:1,
- borders, focus indicators, and other non-text UI target at least 3:1,
- progress and long-running states include text status.

WCAG 3.0 is tracked as a draft. WCAG 2.2 AA is the implementation and test baseline.
