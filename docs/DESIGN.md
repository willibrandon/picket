# Picket — Design Document

**A best-in-class secrets scanner for .NET, built on the Scout library stack — a drop-in gitleaks replacement that goes far beyond it.**

- **Status:** Implementation design (v0.1 — full scope)
- **Date:** 2026-07-04
- **Target runtime:** `picket` CLI on .NET 10 Native AOT (`net10.0`); reusable libraries target `net9.0` and `net10.0`
- **Binary name:** `picket`
- **Root namespace:** `Picket`
- **Built on:** `Scout.Text.Regex`, `Scout.IO.Globbing`, `Scout.IO.Ignore` (this repository)
- **License:** MIT (deliberately — see §2.3)

---

## 1. Name

**Chosen name: `Picket`.**

A *picket* is a sentry posted ahead of the main body to keep watch and raise the alarm; a *picket line* is a guarded perimeter. That is exactly this tool: it stands watch over a codebase and warns when a secret crosses the line. It also rhymes thematically with **Scout** — reconnaissance and sentry duty are the same discipline — so the two products read as a family.

**Collision due diligence.** The package ID `Picket` is unused on NuGet (verified: zero packages). GitHub prior art is JBoss **PicketLink**/**PicketBox**, an archived Java identity framework (double-digit stars, dormant for years), and unrelated hobby repos (a Python geofencing toy, a strike-notifier browser extension). None is a secrets scanner or a .NET security tool, so confusion in this niche is negligible. If a hard conflict ever surfaces, the rename is mechanical (namespaces, assembly/binary name, package IDs).

**Command name:** the only installed command is `picket`. No short alias (avoids shadowing system tools, mirroring Scout's `sc`/`sc.exe` decision).

---

## 2. Mission & Positioning

### 2.1 Mission

A **feature-complete, byte-compatible gitleaks replacement** for .NET that is also the **best-in-class** open-source secrets scanner overall: it matches gitleaks flag-for-flag and config-for-config so existing users switch with zero migration, then adds the capabilities the whole field is missing — live and offline **verification**, **credential-privilege analysis**, **incremental blob-dedup scanning**, a **rule test harness**, portable **wildcard/relative ignores**, **simultaneous multi-format output**, and a genuinely **free, permissively-licensed CI action**.

### 2.2 Strategic timing (why now)

Gitleaks is **officially feature-frozen.** Its README states future releases are *security patches only* and the maintainer has moved to a separate successor project; the v9 wishlist issue was closed as "not working on v9." The most popular OSS secrets scanner has stopped accepting features while its GitHub Action is **proprietary and requires a paid license key for organizations** (with well-documented delivery failures: gitleaks-action #1624, #1753, #1561). TruffleHog — the other leader — is **AGPL-3.0**, a recurring enterprise-adoption blocker, and *still lacks an ignore file* (its single most-reacted open issue, #2687, 30 reactions). The lane for a **fast, MIT-licensed, drop-in-compatible, verification-capable** scanner — with a first-class .NET-native story that no incumbent has — is wide open.

### 2.3 Non-negotiables (inherited from Scout's engineering culture)

- **MIT license, no open-core, no paid tier for the scanner or its CI action.** This is a positioning weapon against both gitleaks-action (proprietary/paid-for-orgs) and TruffleHog (AGPL). It is a hard constraint, not a default.
- **Native AOT, single self-contained binary**, fast cold start (a pre-commit hook and CI step must feel instant). No JIT, no runtime reflection on hot paths.
- **Byte-oriented end to end.** Secrets live in `.env` files, PEM blobs, minified bundles, and files of unknown/broken encoding. Picket matches over `ReadOnlySpan<byte>` via `Scout.Text.Regex` and never round-trips through a lossy UTF-16 decode. This is the core reason to build on Scout and not the BCL `Regex`.
- **Behavioral compatibility is a tested contract**, in Scout's tradition: a differential suite runs Picket and the pinned real `gitleaks` binary over a corpus and asserts matching findings, fingerprints, and report bytes (after documented identity normalization). Any intentional deviation is recorded in a `PARITY.md`-style ledger with a guarding test.
- **One type per file; zero warning suppressions; every public API documented** — enforced by the same MSBuild/analyzer regime this repo already ships (`Scout.SourceGen` analyzers, `Directory.Build.targets` gates).
- **No feature is stubbed or `NotImplementedException`-ed.** Full scope is delivered; internal milestones (§12) are integration gates, not shippable subsets.

### 2.4 Non-goals

- Not a SaaS. No mandatory account, no phone-home, no telemetry. Verification (which necessarily contacts provider APIs) is **opt-in** and there is an enforced **offline mode** default posture for privacy-sensitive users (§6.2).
- Not bug-for-bug bound to gitleaks defects. Where gitleaks has an acknowledged flaw (unstable fingerprints, silent git-error exit-0), Picket offers a **compatible mode** that reproduces it and a **fixed mode** that corrects it, both documented.

---

## 3. Architecture Overview

Picket is a layered stack mirroring Scout's own crate-per-project discipline. Every project is `net9.0;net10.0` and `IsAotCompatible` except the CLI app (`net10.0`, `PublishAot`).

```
Picket.Cli (picket binary; Native AOT static lib + C entry, reuses Scout's launcher shape)
  └── Picket.Engine        — scan orchestration, finding model, fingerprints, redaction
        ├── Picket.Rules    — rule + allowlist model, TOML config loader, gitleaks compat, RE2 translation
        ├── Picket.Sources  — scan sources: filesystem, git history, stdin, archives, remote (GitHub/GitLab/…)
        ├── Picket.Decoding — base64/hex/percent/unicode recursive decoder with offset remapping
        ├── Picket.Entropy  — Shannon entropy + p(random) probabilistic scoring
        ├── Picket.Verify   — live provider verification + offline checksum validation + analyze
        ├── Picket.Report   — json / csv / junit / sarif / template / toon / html writers (byte-exact)
        └── Picket.Store    — content-addressed blob datastore for dedup + incremental scans
Consumes: Scout.Text.Regex (ByteRegex/ByteRegexSet), Scout.IO.Globbing (GlobSet), Scout.IO.Ignore (FileWalker)
```

**How the three Scout libraries carry the load:**

| Scout library | Role in Picket |
|---|---|
| **`Scout.Text.Regex`** | The detection engine. Every rule regex compiles to a `ByteRegex`; the keyword prefilter and multi-rule scan compile to a single `ByteRegexSet` so N rules run in **one linear pass** over each blob (not N passes). Byte offsets returned map directly into the source buffer for match/line extraction. Linear-time guarantee means an untrusted community ruleset cannot ReDoS the scanner. |
| **`Scout.IO.Ignore`** | The filesystem source. `FileWalker` provides gitignore-exact, parallel, symlink-aware traversal — and directly answers the field's most-requested feature (gitleaks #1195: "use .gitignore as an allowlist") for free, because that is FileWalker's native behavior. `--no-git`-style toggles map onto `FileWalkerOptions`. |
| **`Scout.IO.Globbing`** | Path allowlists/denylists and rule `path` scoping. `GlobSet` matches a finding's path against many patterns at once; wildcard ignore fingerprints (gitleaks #1870) are implemented as globs. |

**Native AOT + argument bytes.** Picket reuses Scout's proven native-entry shape: `Picket.Cli` publishes as an AOT static library exporting an `[UnmanagedCallersOnly]` entry, driven by the same C launcher (`scout_main.c` sibling) so raw non-UTF-8 argv/paths round-trip. This is a solved problem in this repo; Picket inherits it rather than reinventing it.

---

## 4. Gitleaks Compatibility Surface (drop-in)

The compatibility contract is: **an existing gitleaks user points Picket at the same repo with the same `.gitleaks.toml`, `.gitleaksignore`, and flags, and gets the same findings, fingerprints, exit codes, and report bytes.** Everything in this section is in scope for v1.

### 4.1 Commands

| Command | Behavior | Notes |
|---|---|---|
| `picket git [repo]` | Scan git history. Reimplements gitleaks' `git log -p -U0 --full-history --all --diff-filter=tuxdb` pipeline; scans **additions only**. | `--log-opts`, `--staged`, `--pre-commit`, `--platform {github\|gitlab\|azuredevops\|gitea\|bitbucket\|none\|auto}` |
| `picket dir [path]` | Filesystem scan (aliases `file`, `directory`). Built on `FileWalker`. | `--follow-symlinks` |
| `picket stdin` | Scan piped input. | |
| `picket detect` | **Deprecated/hidden**, functional. Maps `detect`→`git`, `detect --no-git`→`dir`, `detect --no-git --pipe`→`stdin`. | Compatibility shim |
| `picket protect` | **Deprecated/hidden**, functional. Maps `protect`→`git --pre-commit`, `--staged`→`+--staged`. | Compatibility shim |
| `picket version`, `picket completion`, `picket help` | Standard. | Completions for bash/zsh/fish/PowerShell via `Scout.SourceGen`-style generation. |

**Picket-native additions** (§6): `picket verify`, `picket analyze`, `picket rules check`, `picket rules test`, `picket scan github|gitlab|s3|docker` (remote sources), `picket baseline`.

### 4.2 Global flags (gitleaks-exact)

`-c/--config`, `--exit-code` (default 1), `-r/--report-path` (`-`=stdout, extension-inferred format), `-f/--report-format {json,csv,junit,sarif,template}`, `--report-template`, `-b/--baseline-path`, `-l/--log-level`, `-v/--verbose`, `--no-color`, `--no-banner`, `--max-target-megabytes` (decimal MB, `len/1_000_000`), `--ignore-gitleaks-allow`, `--redact[=0..100]` (NoOptDefVal 100), `--enable-rule` (repeatable), `-i/--gitleaks-ignore-path` (default `.`; plus auto-load `{source}/.gitleaksignore`), `--max-decode-depth` (default **5**), `--max-archive-depth` (default 0), `--timeout`, `--diagnostics`, `--diagnostics-dir`.

**Config precedence (exact):** `--config` → `GITLEAKS_CONFIG` (path) → `GITLEAKS_CONFIG_TOML` (content) → `{target}/.gitleaks.toml` → embedded default. Picket adds `PICKET_CONFIG*` as primary with the `GITLEAKS_*` names as compatibility fallbacks (the Scout `SCOUT_CONFIG_PATH`/`RIPGREP_CONFIG_PATH` pattern).

**Exit codes (exact):** `0` no leaks; `--exit-code` value (default 1) leaks found; `1` scan error/partial; `126` unknown flag. A report is still written on partial scans.

### 4.3 Config TOML schema (complete)

Full parse of the gitleaks schema, validated against the same rules gitleaks enforces:

- **`[extend]`**: `useDefault`, `path` (mutually exclusive with `useDefault`, fatal if both), `disabledRules`. **Chain depth capped at 2.** Merge semantics reproduced exactly: child rule overrides `description`/`entropy`/`secretGroup`/`regex`/`path` when non-zero, **appends** `tags`/`keywords`/`allowlists`; new rules added; global allowlists appended; rules re-sorted alphabetically after extend. `extend.url` is **parsed but a no-op** (matches gitleaks, whose `extendURL()` is an empty TODO) — Picket logs a clear "extend.url is not implemented" warning rather than silently ignoring. `minVersion` honored (warn if running older; Picket maps this to its own version line).
- **`[[rules]]`**: `id` (unique, required), `description`, `regex`, `path`, `secretGroup` (0 ⇒ first non-empty capture group; validated ≤ NumSubexp), `entropy` (Shannon, strict `>`), `keywords` (lowercased, Aho-Corasick prefilter), `tags`, `skipReport`, `[[rules.allowlists]]` (plural, v8.21+; deprecated singular `[rules.allowlist]` accepted but cannot mix — error), `[[rules.required]]` **composite rules** (`id` referencing an existing rule, `withinLines`, `withinColumns`; primary reported only if every required rule has a finding in proximity).
- **Allowlists** (`[[rules.allowlists]]` and global `[[allowlists]]`): `description`, `condition` (`OR`/`||` default, `AND`/`&&`), `commits` (case-insensitive SHA), `paths` (regex), `regexTarget` (`secret` default / `match` / `line`), `regexes`, `stopwords` (case-insensitive substring of secret, Aho-Corasick), and global-only `targetRules` (v8.25+, validated post-extend). Empty allowlist = config error. Deprecated singular `[allowlist]` cannot coexist with plural.
- **Embedded default config**: Picket ships the **gitleaks default ruleset** (222 rules at the pin) transcribed and pinned, plus its default global allowlist (~28 path regexes, ~13 regexes, 2 stopwords). Provenance and version recorded in an `UPSTREAM.md`, advanced only via a documented sync policy (Scout's model). Picket layers **its own additional rules** on top under a distinct namespace so the gitleaks-compatible core stays byte-identical while Picket's expanded coverage (§6.5) is additive and toggleable.

### 4.4 The RE2 → Scout translation layer (the critical compatibility risk)

Gitleaks regexes are **Go `regexp` (RE2 syntax)**. Scout's `ByteRegex` is a port of **Rust `regex-automata`** — also RE2-lineage, also linear-time, also no backreferences/lookaround. This is a **strong match** (both reject the same catastrophic constructs), but the two dialects are not identical. `Picket.Rules` includes an explicit **RE2-dialect compatibility layer** that:

1. Translates Go-specific syntax to Scout/Rust equivalents where they differ (e.g. Go `(?P<name>)` named groups — Rust accepts both `(?P<name>)` and `(?<name>)`; flag placement; `\z`/`\A` anchor spellings; Go's `(?s)`/`(?m)` semantics; POSIX class handling; Go's default-Unicode `.` vs byte mode).
2. Compiles each rule to a `ByteRegex` with options set to mirror gitleaks' engine defaults (gitleaks runs Go `regexp` in **non-Unicode-`.`, line-oriented** mode per fragment; Picket sets `ByteRegexOptions` to match).
3. **Reports, never silently drops.** A rule using a construct Scout cannot represent is surfaced as a hard, itemized error (rule id + reason), the same way Scout treats parity deviations. There is no quiet mismatch.
4. Is covered by a **rule-corpus differential** (§8): every rule in the gitleaks default config, plus a corpus of community configs, is compiled and run against fixtures under both real gitleaks and Picket, and the finding sets are diffed.

This layer is where the majority of compatibility engineering lives, and it is the one place a naive port would fail. It gets its own conformance suite.

### 4.5 Entropy (exact)

Shannon entropy over the Secret's bytes, compared with **strict `>`** against the rule threshold (gitleaks semantics). Reimplemented and pinned by unit tests against gitleaks' computed values for a fixture set.

### 4.6 Fingerprints, ignores, baseline (exact, plus fixes)

- **Fingerprint formats** (exact): git scan `{commit}:{file}:{rule-id}:{startLine}`; dir/stdin `{file}:{rule-id}:{startLine}`. Paths use `/`; backslashes normalized (gitleaks #1622); archive inner paths join with `!`.
- **`.gitleaksignore`**: one fingerprint per line, `#` comments, blank lines; 3-part (`file:rule:line`) and 4-part (`commit:file:rule:line`) entries path-normalized. Loaded from `--gitleaks-ignore-path` **and** `{source}/.gitleaksignore`. Matching checks the **commit-less form first** even for git findings, then the commit-qualified form. Also `.picketignore` (Picket-native, read after `.gitleaksignore` so Picket rules win).
- **Inline `gitleaks:allow`** substring suppression (any comment syntax); disabled by `--ignore-gitleaks-allow`. Picket also honors `picket:allow`.
- **Baseline** (`--baseline-path`): a prior JSON report; a finding is suppressed on full-field match (RuleID, Description, line/column bounds, Match+Secret [skipped when redacted], File, Commit, Author, Email, Date, Message, Entropy). Fingerprint deliberately not compared — reproduced exactly.

**Documented fixes (opt-in `--stable-fingerprints`, §6.1):** portable relative-path fingerprints (#1059), wildcard ignore entries (#1870), and git-vs-dir fingerprint consistency (#2107). Default mode stays byte-compatible; the fixed mode is a clearly-labeled superset.

### 4.7 Report formats (byte-exact)

Hand-written byte writers (Scout's JSON discipline — no `System.Text.Json` on the output path, because byte-identical escaping and field order matter for differential testing):

- **json**: array, **one-space indent**, exact PascalCase key order (`RuleID`, `Description`, `StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Match`, `Secret`, `File`, `SymlinkFile`, `Commit`, `Link` [omitempty], `Entropy`, `Author`, `Email`, `Date`, `Message`, `Tags`, `Fingerprint`), `Line` omitted, empty ⇒ `[]`.
- **csv**: exact header incl. conditional `Link`; Tags space-joined.
- **junit**: exact `<testsuites>/<testsuite>/<testcase>/<failure>` shape with indented-JSON body.
- **sarif**: schema 2.1.0, `tool.driver.name = picket`, results with `partialFingerprints` (commitSha, email, author, date, commitMessage), physicalLocation regions, `snippet.text`. (gitleaks hardcodes `semanticVersion: v8.0.0`; Picket emits its own version but keeps a documented `gitleaks-compat` sarif mode if a consumer pins that string.)
- **template**: Go `text/template`-compatible execution. This needs a **Go-template-compatible evaluator** (sprig-subset function map, minus `env`/`expandenv`/`getHostByName` as gitleaks removed them) so existing `.tmpl` files run unchanged. This is a scoped sub-project; templates are pinned by differential fixtures.

### 4.8 Decoding & archive & binary handling (exact)

- **Recursive decoder** (`Picket.Decoding`, `--max-decode-depth` default 5): `percent`, `unicode` (`U+XXXX`/`\uXXXX`), `hex` (≥32 hex chars), `base64` (≥16 chars, std+url alphabets), recursive with segment tracking; adds `decoded:<kind>` / `decode-depth:<n>` tags; **remaps match bounds back to the encoded original** (the fiddly part — pinned by tests).
- **Archive scanning** (`--max-archive-depth`, default 0/off): zip/tar/gz/bz2/xz/zstd/… via a managed archive layer, `!` inner-path separator, full nested provenance (answers TruffleHog #1549).
- **Binary/large-file**: dir scans chunked (100 KB with blank-line peek), MIME-sniff skip for `application/*`, empty-file skip, `--max-target-megabytes` cap. Reproduced, with an opt-in "skip binary in git scans by default" (#1118).

---

## 5. Scan Sources

| Source | v1 scope | Backed by |
|---|---|---|
| Filesystem (`dir`) | Full | `Scout.IO.Ignore` `FileWalker` (gitignore-aware, parallel, symlink policy) |
| Git history (`git`) | Full | Native git-log/diff pipeline reimplementation; additions-only; merge-commit handling (fixes #1028) |
| Stdin | Full | Direct |
| Staged / pre-commit diff | Full | `git diff -U0 --no-ext-diff [--staged]`; `--no-ext-diff` handling (fixes #1206) |
| Archives | Full | `Picket.Decoding` archive layer |
| **Remote GitHub** (org/repo/PR/issue/gist) | Full | GitHub API enumeration → blob stream |
| **Remote GitLab / Bitbucket / Azure Repos / Gitea** | Full | Provider enumeration → blob stream |
| **S3 / GCS / Azure Blob** | Full | Object enumeration |
| **Docker images / filesystem** | Full | Layer enumeration |

Remote and cloud sources put Picket at parity with TruffleHog's breadth (a capability gitleaks entirely lacks) while every source funnels into the **same blob-dedup datastore** (§7), so history and org scans scan each unique blob **once**.

---

## 6. Beyond Gitleaks — Best-in-Class Features

These are the differentiators, prioritized by the demand signal from the competitive research (reaction counts, comparison articles, declined-feature openings). **All are in scope.**

### 6.1 Stable, portable ignores (the loudest demand cluster)

The single most-reacted pain across gitleaks and TruffleHog is ignore ergonomics. Picket ships:
- **Wildcard/glob ignore entries** (gitleaks #1870) via `Scout.IO.Globbing`.
- **Relative, CI-portable fingerprints** (#1059) — no absolute `/github/workspace/...` leakage.
- **Content-based ignore option**: suppress a specific secret regardless of file/line (survives rebases and codegen), keyed on rule+secret hash rather than line number.
- **`.gitignore`-as-allowlist** (#1195) — native FileWalker behavior, on by default in `dir` scans.
- **A first-class ignore file** for the whole tool — the thing TruffleHog #2687 (30 reactions) still doesn't have.
- **Report of suppressed/`:allow` findings** (#1246) and **stale-ignore-entry detection** (#2130) via `picket baseline --audit`.

### 6.2 Verification — live + offline (TruffleHog's killer feature, plus Kingfisher's)

`Picket.Verify` gives Picket the capability gitleaks was asked for in 2022 (#1013) and never built:
- **Live verification**: for common credential types, confirm the secret is active by calling the provider API. Results bucket as `verified` / `unverified` / `unknown` (error) with `--only-verified` and `--results` selectors (TruffleHog-compatible flag names). **Verification is opt-in and off by default** (privacy); an enforced `--offline` mode guarantees no network egress.
- **Verification caching** (TruffleHog #2262) — a secret is verified once per run, not per chunk.
- **Offline checksum validation** (Kingfisher's edge; gitleaks #1456): structurally validate self-checksummed tokens (modern GitHub PATs, Stripe keys, etc.) with **no network call** — a fast, private FP-killer.
- **Validator breadth including DB/SDK** (Kingfisher's advantage over TruffleHog): HTTP, cloud-SDK (AWS/GCP/Azure), and **database connection-string validators** (Postgres/MySQL/MongoDB/JDBC/JWT), plus a **webhook validator** (POST to a user endpoint, `200`⇒verified) for custom detectors.

### 6.3 Credential-privilege analysis (`picket analyze`)

Port of TruffleHog's `analyze` — currently **unmatched** in the field. Given a verified credential, enumerate its permissions and reachable resources (GitHub token scopes, AWS key policy surface, etc.) so responders know blast radius, not just existence. Ships for the most-leaked credential types.

### 6.4 Incremental, dedup-first performance (`Picket.Store`)

Nosey Parker / Kingfisher proved the model: **content-address every blob and scan each unique blob exactly once**, persisting findings + scan state in a datastore.
- **Blob dedup** collapses the same secret appearing across thousands of commits into one scan and grouped findings (answers gitleaks #1054 dedup).
- **Incremental re-scans**: a second run over a repo skips unchanged blobs — turning CI scans from full-history re-reads into deltas (TruffleHog #813 / #2878).
- Backed by the SIMD prefilters in `Scout.Text.Regex` (memchr/memmem/Teddy) and `ByteRegexSet` single-pass multi-rule matching, this targets Nosey-Parker-class throughput (GB/s) in a managed AOT binary — a claim no .NET tool can currently make.

### 6.5 False-positive reduction

The universal complaint. Picket layers several defenses:
- **p(random) probabilistic scoring** (ripsecrets' idea): model whether a string is machine-generated by character distribution, not just raw Shannon entropy — fewer placeholder/variable-name hits (gitleaks #1830, #1897, #1073).
- **Test-fixture / placeholder awareness**: built-in recognition of well-known dummy keys (AWS doc `AKIA...EXAMPLE`, `PublicKeyToken` .NET refs #1052, sealed-secrets #1728).
- **Expanded, data-driven default rules** including the Azure gaps users cite (#539) — additive over the gitleaks-compatible core.
- **Multi-line secret support** (gitleaks' structural gap, #283/#908/#914) — Picket's blob model scans whole blobs, so PEM keys, XML, and Jupyter secrets that span lines are matchable, not truncated at fragment boundaries.

### 6.6 Rule authoring & QA (`picket rules check` / `picket rules test`)

Nosey Parker's underrated feature, generalized:
- Rules may embed **positive and negative example strings**; `picket rules check` self-tests every rule against its examples and fails on regression — a built-in rule-QA harness (leveraging this repo's own testing culture).
- `picket rules test <rule> <input>` for interactive authoring.
- A **`--print-config`** that emits the fully-resolved config after `extend` merging (gitleaks #983).

### 6.7 Output & integration ergonomics

- **Simultaneous multiple outputs** (gitleaks #1048, TruffleHog #1880): `-f json -f sarif` in one run, each to its own path or stdout.
- **Spec-compliant JSON** stream option (TruffleHog #2164) alongside the gitleaks-exact array.
- **SARIF, TOON, HTML** report formats (Kingfisher parity) plus **GitLab code-quality** format (#2068).
- **Config in `pyproject.toml` / other host files** (`[tool.picket]`, gitleaks #2066) and flags expressible in the TOML (#1732).
- **Findings context**: surrounding-line snippets for triage (gitleaks #1074/#1766), off by default.

### 6.8 The free CI action & hooks (the licensing wedge)

- **`picket-action`** — a genuinely **MIT-licensed, no-key, free-for-organizations** GitHub Action, the direct answer to gitleaks-action's proprietary/paid model and its broken license delivery (#1624/#1753/#1561). This is a headline adoption lever.
- **pre-commit, pre-push, and pre-receive** hooks (ggshield is the only OSS tool with documented pre-receive — Picket matches it, locally and free).
- **Docker images**, Homebrew/Scoop/winget, and `dotnet tool` distribution — reusing Scout's release machinery wholesale.

### 6.9 Embeddable library (`Picket.Engine` as a NuGet package)

Kingfisher #189 and secretlint's model show the demand for scanner-as-library. Because Picket is already a layered library stack, shipping `Picket.Engine` + `Picket.Rules` as NuGet packages (AOT-safe, `net9.0;net10.0`) lets .NET apps, analyzers, and MSBuild tasks embed secret scanning directly — a capability no competitor offers to the .NET ecosystem.

### 6.10 Honeytokens (stretch, ggshield parity)

`picket honeytoken create` to mint tripwire credentials. Unlike ggshield this need not be SaaS-bound: Picket can generate provider-native canaries (e.g. AWS keys in a user-controlled trap account) and a local sighting-detector. Marked stretch because it depends on external account setup, but in scope.

---

## 7. Data Model & Core Types

- **`Finding`** — the byte-exact gitleaks finding (§4.7 fields) plus Picket extensions (`VerificationStatus`, `RandomnessScore`, `BlobId`, `DecodePath`, `Validators[]`) that are **omitted in gitleaks-compat output** and present only in Picket-native formats.
- **`Rule`** / **`Allowlist`** / **`RequiredRule`** — the config model (§4.3), immutable after load.
- **`Fingerprint`** — value type with `git`/`dir` renderers and the compat/stable variants.
- **`Blob`** — content-addressed unit `{Sha256, Bytes, Provenance[]}`; provenance is a list because dedup means one blob has many locations.
- **`ScanRequest`** / **`ScanResult`** — orchestration inputs/outputs; results stream to reporters.

Hot paths are `ReadOnlySpan<byte>`-first, pooled buffers, `ref struct` iterators, no LINQ, no allocation in the match loop — the Scout playbook, enforced by allocation tests.

---

## 8. Testing Strategy

Mirrors Scout's differential-oracle discipline. Layers:

1. **Unit tests** — config parsing, entropy, fingerprints, decoder offset remapping, RE2 translation, report writers.
2. **Gitleaks differential suite (mandatory)** — a **pinned real `gitleaks` binary** (committed per-RID, SHA-256-verified before use, exactly like Scout's `rg` oracle) is run alongside Picket over a corpus of repos × configs × flag combinations. Assert matching findings, fingerprints, exit codes, and **byte-identical report output** after documented identity normalization (banner/version/tool-name fields). Any diff is fixed or recorded in `PARITY.md`.
3. **Rule-corpus conformance** — the gitleaks default ruleset plus gathered community configs, each rule compiled through the RE2 translation layer and run against fixtures under both tools; finding sets diffed. This gates the compatibility layer independently.
4. **Verification tests** — recorded/mocked provider responses; live tests behind an opt-in flag with test credentials.
5. **Fuzzing** — via `SharpFuzz` (Scout's harness): config TOML parser, RE2 translator, decoder, git-diff parser.
6. **Performance gates** — hyperfine against gitleaks and (where fair) TruffleHog/Nosey Parker on pinned corpora (a large monorepo, a deep-history repo), with hard ratio thresholds blocking release. Picket must be **at least competitive with gitleaks** on cold scans and **faster on incremental** scans (its structural advantage).

Framework: **xUnit v3**, all six RIDs, **zero skipped tests** (enforced by `Scout.SourceGen`'s `NoSkippedTestsAnalyzer`).

---

## 9. Compatibility Ledger (`PARITY.md`)

Like Scout, Picket keeps an explicit ledger. **Identity surfaces** intentionally differ (tool name `picket`, banners, homepage, SARIF `tool.driver.name`, config env var names) and are pinned by golden tests. **Behavioral compatibility** with gitleaks is the contract for the gitleaks-compat core; every intentional deviation (e.g. the fixed-fingerprint mode) is a documented, opt-in, test-guarded entry. Picket-native features live outside the compat contract by definition and are pinned by their own golden tests.

---

## 10. Distribution & Packaging

Reuses this repository's release engineering end to end:
- **`dotnet tool install -g Picket`** (RID packages + pointer package, hand-built like Scout's tool packages because they wrap native AOT binaries).
- **NuGet libraries**: `Picket.Engine`, `Picket.Rules` (embeddable scanner, §6.9).
- **Homebrew tap, Scoop bucket, winget, MSI (WiX)** — same automated release workflow.
- **Docker images** (`ghcr.io`), **`picket-action`** (MIT), **pre-commit hook** manifest.
- Deterministic, reproducible builds; SDK/runtime pinned; snapshot-pinned CI — inherited from Scout's `Directory.Build.*` and workflow set.

---

## 11. Competitive Position (summary)

| Capability | gitleaks | TruffleHog | Nosey Parker | Kingfisher | **Picket** |
|---|:--:|:--:|:--:|:--:|:--:|
| License | MIT (frozen) | AGPL-3.0 | Apache | Apache | **MIT** |
| Free org CI action | ✗ (paid) | ✓ | — | — | **✓** |
| Drop-in gitleaks config/CLI | — | ✗ | ✗ | ✗ | **✓** |
| Live verification | ✗ | ✓ | ✗ | ✓ | **✓** |
| Offline checksum validation | ✗ | ✗ | ✗ | ✓ | **✓** |
| Credential privilege analysis | ✗ | ✓ | ✗ | ✗ | **✓** |
| Blob dedup / incremental | ✗ | ✗ | ✓ | ✓ | **✓** |
| First-class ignore file + wildcards | ◐ | ✗ | ✗ | ◐ | **✓** |
| Rule self-test harness | ✗ | ✗ | ✓ | ◐ | **✓** |
| Simultaneous multi-format output | ✗ | ✗ | ✗ | ✗ | **✓** |
| SARIF | ✓ | ✗ | ◐ | ✓ | **✓** |
| Native .NET / embeddable library | ✗ | ✗ | ✗ | ✗ | **✓** |
| Pre-receive hook (local, free) | ◐ | ✗ | ✗ | ✗ | **✓** |

Picket is the only entry that is simultaneously **MIT**, **drop-in gitleaks-compatible**, **verification-capable**, **dedup-incremental**, and **.NET-native/embeddable**. That intersection is the product.

---

## 12. Milestones (internal integration gates — full scope ships at v1)

Following Scout's philosophy, no milestone before full parity+differentiation is described as shippable; these are integration checkpoints, not scope cuts.

- **M0 — Foundation.** Repo, pins, Native AOT entry (reuse Scout launcher), finding model, config TOML loader, `FileWalker`/`GlobSet`/`ByteRegexSet` wiring, RE2 translation skeleton + conformance harness. Gate: dir scan of a fixture matches gitleaks on a rule subset.
- **M1 — Gitleaks compat core.** All commands/flags, full TOML schema (extend, composite rules, allowlists), entropy, fingerprints, ignores, baseline, all five report formats, decoding, archives, git-history pipeline. Gate: full gitleaks differential suite green on the default ruleset + community configs.
- **M2 — Performance & dedup.** `Picket.Store` blob dedup + incremental scans; SIMD prefilter tuning. Gate: cold-scan competitive with gitleaks, incremental scan materially faster; hyperfine gates green.
- **M3 — Verification & analyze.** `Picket.Verify` live + offline validators (HTTP/SDK/DB/webhook), caching, `--only-verified`; `picket analyze`. Gate: verification conformance vs recorded provider responses.
- **M4 — Remote & cloud sources.** GitHub/GitLab/Bitbucket/Azure/Gitea, S3/GCS/Azure Blob, Docker. Gate: org-scan enumeration + dedup correctness.
- **M5 — FP reduction, rule QA, ergonomics.** p(random) scoring, fixture awareness, expanded rules, `rules check/test`, `--print-config`, simultaneous outputs, TOON/HTML/gitlab-code-quality, stable-fingerprint mode, suppressed-finding reporting.
- **M6 — Distribution.** `dotnet tool`, NuGet libraries, Homebrew/Scoop/winget/MSI, Docker, **MIT `picket-action`**, pre-commit/pre-push/pre-receive hooks.
- **M7 — Stretch.** Honeytokens; leak-database (HasMySecretLeaked-style) check.

**v1 ships when every gitleaks differential case, every conformance suite, and every performance gate is green** — and the free MIT action is live.

---

## Appendix A — Key open issues Picket resolves (traceability)

Ignore/portability: gitleaks #1870, #1195, #1059, #1328, #1325, #1052, #1246, #2130; TruffleHog #2687. Verification/validation: gitleaks #1013, #1456; TruffleHog #2262. Analysis: TruffleHog `analyze`. Dedup/incremental: gitleaks #1054; TruffleHog #813, #2878. Output: gitleaks #1048, #983, #2066, #1732, #1074, #1312, #2068; TruffleHog #1880, #2164, #1549. Multiline/coverage: gitleaks #283, #908, #914, #539, #1118. FP: gitleaks #1830, #1897, #1073, #1728. Licensing wedge: gitleaks-action #1624, #1753, #1561, #2063. Git correctness: gitleaks #1028, #1206, #2129. Privacy: TruffleHog #1239.
