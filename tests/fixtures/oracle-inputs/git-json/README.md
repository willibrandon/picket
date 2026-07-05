# Git JSON Oracle Input

This fixture exercises strict Gitleaks-compatible git-history scanning with a
synthetic rule and a fully redacted report.

The oracle repository is created from `source.txt` with this deterministic
metadata:

- author and committer: `Picket Oracle <picket@example.com>`
- author and committer date: `1704067200 +0000`
- commit message: `add git oracle secret`
