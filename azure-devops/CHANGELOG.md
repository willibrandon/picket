# Changelog

## 0.2.7

- Match Gitleaks fragment boundaries, retain findings from partial directory scans, and reduce malformed UTF-8 and decoder allocation costs.

## 0.2.6

- Keep directory scans parallel on memory-loaded hosts when sufficient memory headroom remains.

## 0.2.5

- Improve strict directory scan throughput and align file-type, path, symbolic-link, and live verbose output behavior with Gitleaks.

## 0.2.4

- Match Gitleaks handling of Git diagnostics and elapsed-time summaries.

## 0.2.3

- Stream Git-history findings during scans, align commit and byte accounting with Gitleaks, and reduce runtime through bounded parallel matching.

## 0.2.2

- Let `picket tui` reuse its scanner executable and let standalone `picket-tui` resolve Windows global-tool shims.

## 0.2.1

- Preserve Unicode banner glyphs in attached Windows consoles while keeping redirected output BOM-free UTF-8.

## 0.2.0

- Scan staged, unstaged, and untracked Git changes, UTF-16 input, and composite decoded evidence.
- Add Hugging Face repositories plus GitLab issue, comment, release, and release-asset sources.
- Add bounded coding-agent guards, direct secret verification, GitLab revocation, and live-validation request budgets.
- Expand native provider rules, contextual predicates, false-positive handling, and randomness scoring.

## 0.1.13

- Add Gitleaks-compatible banners, verbose finding output, log-level filtering, and scan summaries.
- Make Windows portable releases pass WinGet executable validation.

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
