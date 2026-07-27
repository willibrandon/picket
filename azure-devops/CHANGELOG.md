# Changelog

## 0.1.12

- Add native ignore-path support, stable fingerprint ignores, safer report and cache defaults, and clearer custom-config guidance.

## 0.1.11

- Report invalid `--ignore-path` files and malformed ignore patterns without unhandled exceptions.

## 0.1.10

- Publish the GitHub Action under the unique Picket Secret Scanner Marketplace name.

## 0.1.9

- Keep `picket tui` attached to the invoking terminal when the companion is installed as a separate .NET tool.

## 0.1.8

- Publish the public Marketplace extension without applying private sharing metadata.

## 0.1.7

- Validate WinGet manifests through a current-user package-manager repair on hosted release runners.

## 0.1.6

- Make the NuGet tool-install gate inspect expected nonzero companion exits without failing the release shell.

## 0.1.5

- Publish stable Marketplace releases automatically after provenance and package validation.
- Resolve the TUI companion from Windows global-tool command shims.
- Strengthen release checks for installed tools, containers, Homebrew, and WinGet.

## 0.1.4

- Align the scanner, task, extension, and package release versions for the first public release.
- Add Azure Artifacts package scanning and fail-closed scanner error handling.

## 0.1.3

- Add validated opt-in built-in rule-pack selection.

## 0.1.2

- Add Marketplace and task icons.
- Package privacy, compatibility, and changelog documentation.
- Restrict task-settable variables to declared outputs.

## 0.1.1

- Add the `PicketScan@1` workspace and Azure DevOps source scanning task.
- Publish SARIF, JSON Lines, and HTML reports with explicit fail modes, annotations, caching, redaction, and bounded source options.
