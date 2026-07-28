# Git Changes

Use the native Git changes source to scan the content currently being developed without scanning the complete checkout:

```powershell
picket scan --git-changes . --report-format jsonl --report-path picket-results/git-changes.jsonl --redact=100
```

The path can select a Git working tree, a directory inside it, or one changed file. Report paths remain relative to the repository root.

## Selected Content

One invocation scans:

- staged file snapshots from the Git index,
- unstaged tracked-file snapshots from the working tree,
- untracked files that are not ignored by Git.

Unchanged and deleted files have no changed content to scan and are excluded. Renames, copies, type changes, and unmerged files are included when they have a readable snapshot. Symbolic links are scanned as link text without following their targets.

Untracked files follow Git's standard ignore sources. Pass `--no-ignore` to include Git-ignored untracked files and disable native ignore-file handling. Native rule path allowlists, `.picketignore`, and explicit `--ignore-path` files otherwise apply normally.

## Snapshot Provenance

A file can have different staged and working-tree content. Picket scans both snapshots and records their origin in native reports:

| Provenance | Meaning |
| --- | --- |
| `git-index` | The finding exists only in the staged index snapshot. |
| `git-worktree` | The finding exists only in the unstaged working-tree snapshot. |
| `git-untracked` | The finding comes from an untracked file. |
| `git-index+worktree` | The same stable finding exists in both staged and working-tree snapshots. |

Shared findings are paired by occurrence, so repeated copies of the same secret remain distinct. A paired finding uses the current working-tree coordinates and the combined provenance value. Findings unique to either snapshot remain separate.

Archives use the same depth, entry, decompressed-byte, compression-ratio, target-size, timeout, and cancellation limits as other native sources. `--checkpoint` can resume an interrupted Git changes scan after Picket verifies the complete ordered path, provenance, and content manifest.

## Hooks

Git hooks do not use this aggregate mode. Pre-commit hooks remain staged-only because they must inspect exactly what the commit will contain. Use `picket scan --git-changes .` for an interactive review of all pending work.
