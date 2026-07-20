# Picket Release-Readiness Review — 2026-07-19

Multi-agent review: 17 dimensions, 121 agents, every finding adversarially verified (blockers by a 3-lens refutation panel). 77 findings confirmed, 30 candidates refuted during verification.

Original test suite: 1268 tests, all passing after rebuilding the stale CLI binary (8 Unix-only skips on Windows).

## Resolution status — 2026-07-19

All 77 confirmed review entries have a final disposition. Seventy-six are resolved in implementation, tests, packaging, or documentation. The remaining code-signing entry is an external release-channel limitation: public artifacts are explicitly documented as unsigned and unnotarized, provenance attestations are not represented as platform signatures, and no workflow bypasses operating-system security checks.

| Review area | Status | Resolution |
| --- | --- | --- |
| engine-match | Resolved | Strict matching now covers trailing-newline trimming, multiline line targets, Gitleaks max-target rounding, nonparticipating captures, Unicode keyword folding, and condition-aware path allowlists. |
| compat-surface | Resolved | Bare `dir`, baseline failure behavior, report emission, usage exit codes, redaction forms, compatibility shims, baseline links, and strict redaction semantics are pinned to oracle fixtures. |
| report-writers | Resolved | JUnit counting and XML controls, template failures, report selection, CSV escaping, and percentage redaction have regression coverage. |
| security-network | Resolved | Endpoint ranges, proxy userinfo and address checks, and revocation authorization handling fail closed. |
| security-input | Resolved | Local reads, archive streams, and source limits are bounded and cancellation-aware. |
| sources-git | Resolved | Git execution cleanup and a raw byte-preserving patch parser cover CRLF and trailing terminators. |
| aot-packaging | Resolved | MSI payloads include zstandard and notices, package notices are complete, and publish-profile behavior matches the documented contract. |
| cli-ux | Resolved | Native operational failures use exit code 2, strict compatibility keeps oracle exit behavior, errors are actionable, and stdin scanning is bounded and streaming. |
| store-baseline | Resolved | Baseline parsing, ignore fingerprints, and cache replacement behavior are hardened and tested. |
| rules-corpus | Resolved | Generic matching uses Scout byte regex, rule metadata merges correctly, structured Codex examples are rejected, and regex edge syntax is covered. |
| test-quality | Resolved | CLI binary selection fails closed, oracle coverage is broader, process tests are cancellation-aware, and cache concurrency tests exercise contention. |
| docs-gates | Resolved | Security, compatibility, hook units, release profiles, and generated public references match implemented behavior. |
| ci-release-pipeline | Resolved with external signing limitation | Native architecture builds avoid emulation, irreversible publication follows release assembly, action SDK resolution is isolated, and symbol-free profiles are artifact-gated. Authenticode signing and Apple notarization require identities that are not configured. |
| verify-internals | Resolved | Validation cache writes tolerate contention, live validation semantics are documented, and cache commands avoid exposing raw secrets. |
| tui-hooks-local-surface | Resolved | Hook installation rejects unsafe repositories, editor fallback cannot shell-execute findings, and TUI scanner resolution fails clearly. |
| distribution-channels | Resolved | MSI and Homebrew retain native dependencies, Marketplace versioning is monotonic at 0.1.4 with the existing publisher identity, images are digest-pinned, and CI wrappers distinguish operational failures from findings. |
| licensing-provenance | Resolved | Gitleaks and all distributed managed/native dependencies are attributed, and notices propagate through NuGet, archives, containers, and MSI payloads. |

Final local validation: Release build completed with zero warnings; 1320 tests completed with 1312 passing and 8 expected Unix-only skips on Windows; formatting, workflow lint, Azure task tests, GitHub Action file-app build, VSIX creation, and the 37-page documentation build passed. Fresh `win-x64` Native AOT CLI and TUI publishes contained no public symbol sidecars, both executables passed version smoke tests, the AOT CLI passed all 10 compatibility-oracle fixtures, zstandard scanning produced the expected finding, and both RID-specific tool packages contained no symbol files or symbol packages.


## engine-match

**Readiness:** The engine is a carefully engineered, mostly faithful port of the pinned Gitleaks detector: entropy math (including the rune-count-over-byte-length quirk), byte-based column arithmetic, secretGroup=0 first-non-empty-group selection, keywordless rules, AND/OR allowlist conditions, stop-word/commit normalization, generic-rule precedence, required-rule proximity, and both fingerprint formats all verifiably match the oracle source. However, it misses a handful of Gitleaks post-processing quirks, and one of them — the trailing-newline trim of the match (detect.go:454/475) — breaks byte-exact Match/EndColumn parity on extremely common inputs (unquoted secrets at end of line via the stock generic-api-key rule), which violates the strict compat contract and must be fixed before any public release; the checked-in oracle fixture corpus (7 synthetic, quoted-token cases) is too thin to have caught it. The remaining divergences (first-line-only gitleaks:allow/line-target evaluation, condition-blind global path file filtering, the max-target megabyte-division window) are narrower but all produce deterministic report or exit-code mismatches against the oracle and should be fixed or consciously waived before release.


### [BLOCKER] `src/Picket.Engine/SecretScanner.cs:1186` (verifier severity: blocker,blocker,blocker)

Picket never replicates Gitleaks' trailing-newline trim of the regex match (detect.go:454+475), so Match text, EndColumn, and EndLine diverge from the oracle for every match whose regex consumes a trailing \n, including the stock generic-api-key rule.


*Failure scenario:* Scan a file containing `PASSWORD=hunter2abcdef\n` with the stock gitleaks config: gitleaks reports Match="PASSWORD=hunter2abcdef", EndColumn=22; picket reports Match="PASSWORD=hunter2abcdef\n" and EndColumn=23, breaking byte-exact JSON/CSV/SARIF parity with the pinned oracle on any unquoted assignment at end of line (ubiquitous in .env/properties/YAML files).


*Evidence:* Gitleaks detect.go:454 does `secret := strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n")` and detect.go:475 shrinks matchIndex[1] to the trimmed length before computing location, so Match/EndColumn/EndLine never include a trailing newline. Picket has no equivalent: SecretScanner.cs ScanRule uses raw match.Start/match.End for matchBytes (line 1186) and end position (line 1185), and GenericApiKeyMatcher.TryConsumeTerminator (GenericApiKeyMatcher.cs:252-256) returns matchEnd = position+1 when the terminator byte is '\n' (IsWhitespace includes \n and \r, line 508-511). The generic-api-key regex terminator `(?:[\x60'"\s;]|\\[nr]|$)` consumes the newline whenever an unquoted secret sits at end of line. Additionally gitleaks re-derives capture groups from the trimmed secret (detect.go:523), so patterns containing a trailing \n keep the full trimmed match as Secret, while Picket extracts the group from the original captures.


### [MAJOR] `src/Picket.Engine/SecretScanner.cs:1657` (verifier severity: blocker)

gitleaks:allow and regexTarget="line" allowlists are evaluated against only the first line of a match, but Gitleaks evaluates the full multi-line Line span, so END-line allow comments on multi-line secrets (e.g. private keys) are ignored.


*Failure scenario:* A multi-line private key whose last line is `-----END OPENSSH PRIVATE KEY----- # gitleaks:allow` is suppressed by gitleaks (the comment is inside finding.Line) but reported by picket, flipping the exit code from 0 to 1 and diverging from the oracle report; likewise an allowlist with regexTarget="line" whose pattern only occurs on a later line of the match suppresses in gitleaks but not in picket.


*Evidence:* Gitleaks builds finding.Line = fragment.Raw[loc.startLineIndex:loc.endLineIndex] which spans from the start of the match's first line through the end of the match's LAST line (location.go:40-52, extended at detect.go:484-486), and both the gitleaks:allow check (detect.go:510) and regexTarget="line" allowlists (detect.go:836, currentLine) evaluate that whole span. Picket's ExtractLine (SecretScanner.cs:1657-1672) starts at the match start offset and stops at the first \n or \r in both directions, so ContainsGitleaksAllow (line 1189) and the Line allowlist target (line 1188, 1481) only ever see the first line of a multi-line match. ExtractLine also treats lone \r as a line boundary while gitleaks only splits on \n.


### [MAJOR] `src/Picket.Engine/SecretScanner.cs:1574` (verifier severity: major)

Max-target size gating uses a strict byte comparison while Gitleaks uses integer megabyte division, so fragments up to ~1 MB above the configured limit are scanned by Gitleaks but silently skipped by Picket in git/stdin fragment paths.


*Failure scenario:* `picket git --max-target-megabytes 1` on a commit adding a 1.4 MB file: gitleaks scans the fragment (1_400_000/1_000_000 = 1, not > 1) and reports its secrets; picket skips it (1_400_000 > 1_000_000) and reports nothing — any fragment sized in (N*1e6, (N+1)*1e6) diverges from the oracle.


*Evidence:* Gitleaks gates fragment scanning with integer megabyte division: `rawLength := len(currentRaw) / 1_000_000; if rawLength > d.MaxTargetMegaBytes { skip }` (detect.go:431-440), so a fragment is scanned as long as len < (N+1)*1_000_000. Picket converts the flag to bytes (Program.CommandLine.cs:76 `megabytes * 1_000_000`) and skips with a strict byte comparison IsTooLargeForContentScan `inputLength > maxTargetBytes` (SecretScanner.cs:1574-1577, used at 63, 99, 239, 383). Directory scans are gated identically at the source level in both tools, but git-diff fragments have no source-level size gate in gitleaks, so the engine check is the deciding one.


### [MINOR] `src/Picket.Engine/SecretScanner.cs:1621` (verifier severity: minor)

When secretGroup points at a valid but non-participating capture group, Picket falls back to the full match while Gitleaks yields an empty secret (typically dropping the finding via the entropy gate).


*Failure scenario:* A custom rule like `regex = '(?:token=(\w{10,})|key=[A-Z]{20})'` with secretGroup=1 matching `key=ABCDEFGHIJKLMNOPQRST`: gitleaks produces Secret="" (dropped if entropy is set, otherwise reported with empty Secret), while picket reports Secret equal to the whole match — divergent Secret field and finding set vs the oracle.


*Evidence:* Gitleaks sets finding.Secret = groups[r.SecretGroup] (detect.go:525-530); Go's FindStringSubmatch returns "" for a capture group that did not participate in the match, yielding an empty Secret which is then usually dropped by the entropy check (entropy("")=0 <= threshold). Picket's ResolveSecret (SecretScanner.cs:1617-1623) does `group ?? captures.Match`, falling back to the FULL match when the configured group did not participate.


### [MINOR] `src/Picket.Engine/KeywordPrefilter.cs:102` (verifier severity: minor)

Keyword prefiltering is ASCII-only case-insensitive while Gitleaks uses Unicode ToLower, so rules with non-ASCII keywords can silently never run.


*Failure scenario:* A custom rule with keyword "café" scanning content containing "CAFÉ_SECRET=...": gitleaks runs the rule (lowercased content contains "café") and reports the secret; picket's prefilter never fires ('É' is not ASCII-folded), so the rule is skipped and the finding is missing.


*Evidence:* Gitleaks lowercases both the fragment and keywords with Unicode-aware strings.ToLower before prefilter matching (detect.go:321-341). KeywordPrefilter folds only ASCII A-Z (KeywordPrefilter.cs:102-107), so keywords containing non-ASCII letters never match case-insensitively.


**Refuted during verification:** src/Picket.Engine/CompiledRuleSet.cs:47 — Global path allowlists are applied as an unconditional file-enumeration filter, ignoring condition="AND" semantics, so f


## compat-surface

**Readiness:** The strict Gitleaks compatibility core is in strong shape for 0.1.0: config precedence (including GITLEAKS_CONFIG_TOML-as-content and file-target fallback), PICKET_CONFIG* isolation, the --platform set with autodetect-on-empty and 'auto' rejection, baseline field comparison, .gitleaksignore 3/4-part semantics, extend depth/conflict/url handling, --enable-rule fatal behavior, and native-feature gating behind --profile picket all match the pinned oracle (sibling clone verified at the pinned commit 4c232b5). The remaining gaps are edge and error-path divergences rather than detection or report-body defects: 'dir' lacking Gitleaks' default-to-cwd, hard-fail on unloadable baselines, the always-write-JSON-to-stdout default, and a family of usage-error exit-code (126 vs 1) and shim/flag-form permissiveness differences. None corrupts data, but the three majors should either be fixed or explicitly recorded in docs/PARITY.md with tests before a public release, since AGENTS.md requires every compatibility deviation to be ledgered.


### [MAJOR] `src/Picket.Cli/Program.CommandTree.cs:293` (verifier severity: major)

picket dir (and aliases file/directory) requires a path argument, while pinned Gitleaks dir defaults to scanning the current directory.


*Failure scenario:* CI drop-in 'cd repo && picket dir' exits nonzero with an argument error instead of scanning the working tree; on a clean tree gitleaks exits 0 and picket reports an error, breaking migrated pipelines.


*Evidence:* CreateDirectoryCommand calls AddRequiredArgument (ExactlyOne arity), and RunDirectory is invoked with defaultRoot=null so a missing path hits 'dir requires a path' (src/Picket.Cli/Program.Directory.cs:433-438). Gitleaks cmd/directory.go:26-32 defaults source to "." when no arg is given (Use: "dir [flags] [path]"); it also maps an empty-string arg to ".", while Program.Directory.cs:430 keeps root="" as-is. Not recorded in docs/PARITY.md; no test covers bare 'picket dir'.


### [MAJOR] `src/Picket.Cli/Program.Git.cs:368` (verifier severity: major)

A missing or malformed --baseline-path file aborts the scan with exit 1, while pinned Gitleaks logs the error and continues scanning without baseline filtering.


*Failure scenario:* First CI run with '--baseline-path baseline.json' before the baseline exists: gitleaks scans and exits 0 on a clean tree with a report; picket exits 1, produces no report, and the pipeline fails.


*Evidence:* TryLoadBaseline (src/Picket.Cli/Program.Reports.cs:12-34) returns false on IOException/InvalidDataException and RunGit/RunDirectory/RunStdinAsync immediately return CompleteRun(1) without scanning or writing a report. Gitleaks cmd/root.go:324-330 calls detector.AddBaseline and on error only logging.Error("Could not load baseline...") then proceeds; the scan runs unfiltered, the report is written, and exit code follows findings.


### [MAJOR] `src/Picket.Cli/Program.Reports.cs:241` (verifier severity: major)

Strict compat commands write the full JSON findings report to stdout when no --report-path is given, while pinned Gitleaks writes no report at all in that case; the deviation is documented in REPORTS.md but missing from the PARITY.md ledger.


*Failure scenario:* A migrated script 'picket git . > build.log' captures unredacted secrets JSON into a CI log where gitleaks previously emitted nothing on stdout; stdout-parsing wrappers also see unexpected content.


*Evidence:* TryWriteTextReport writes the report to Console.Out when reportPath is null/'-' and RunGit/RunDirectory/RunStdinAsync call TryWriteReport unconditionally (Program.Git.cs:415). Gitleaks cmd/root.go:348-406 only builds a Reporter when report-path is non-empty, and findingSummaryAndExit (root.go:464-491) writes nothing otherwise. docs/REPORTS.md:90 documents 'When no path or format is supplied, JSON is written to standard output', but docs/PARITY.md (which AGENTS.md says must record every compatibility deviation) has no entry, and the oracle capture commands in docs/UPSTREAM.md always pass --report-path so the harness never exercises this path.


### [MINOR] `src/Picket.Cli/Program.Git.cs:353` (verifier severity: major)

Usage errors other than unknown flags exit with 126, while pinned Gitleaks reserves 126 for 'unknown flag' and exits 1 for invalid flag values, invalid --platform, and extra positional arguments.


*Failure scenario:* 'picket git --platform=bogus .' exits 126 where 'gitleaks git --platform=bogus .' exits 1; wrappers classifying exit 1 as scan/config error misreport the failure class.


*Evidence:* Invalid --platform returns UnknownFlagExitCode=126 (Program.Git.cs:353-356, enshrined by CliCompatibilityTests.cs:4639); the same 126 is returned for bad --exit-code/--max-target-megabytes/--redact values and 'unexpected argument'. Gitleaks cmd/root.go:224-232 only exits 126 when err contains 'unknown flag'; cobra invalid-argument errors, scm.PlatformFromString failures (cmd/git.go:74-76), and 'accepts at most 1 arg' all go through logging.Fatal → exit 1. DESIGN.md:454 itself documents 126 as 'unknown flag' only.


### [MINOR] `src/Picket.Cli/Program.CommandLine.cs:1083` (verifier severity: minor)

Space-separated '--redact N' consumes the next token as a redaction percentage, while Gitleaks' cobra NoOptDefVal flag never consumes a separate token (only '--redact=N' sets a percentage).


*Failure scenario:* 'picket detect --redact 20' produces a 20%-masked report while the pinned oracle produces a fully 'REDACTED' report for the identical command line, breaking byte parity; a directory literally named '20' is also scanned by gitleaks but consumed as a percentage by picket.


*Evidence:* TryReadRedactionPercent (Program.CommandLine.cs:1078-1099) parses args[index+1] as the percent when it is an integer. Gitleaks defines redact as Uint with NoOptDefVal="100" (cmd/root.go:86-87), so 'gitleaks detect --redact 20' redacts 100% and treats '20' as an ignored positional, and 'gitleaks git --redact 20' errors with 'accepts at most 1 arg' when a repo is also given.


### [MINOR] `src/Picket.Cli/Program.CompatShims.cs:84` (verifier severity: minor)

The hidden detect/protect shims forward unrecognized flags to picket git, accepting flags the pinned Gitleaks shims reject with exit 126 (e.g. 'detect --staged', 'protect --platform').


*Failure scenario:* 'picket detect --staged' silently runs a staged diff scan and exits by findings where 'gitleaks detect --staged' exits 126, so scripts relying on the oracle's rejection behave differently.


*Evidence:* RunDetectAsync/RunProtect collect any unmatched arg into forwardedArgs and pass them to RunGit, which accepts --staged/--pre-commit/--platform/--gitleaks-ignore-path etc. Gitleaks detect only defines no-git, pipe, follow-symlinks, source, log-opts, platform (cmd/detect.go:33-41) and protect only staged, log-opts, source (cmd/protect.go:15-20); any other flag is 'unknown flag' → exit 126 via cmd/root.go:226-229.


### [MINOR] `src/Picket.Cli/Program.Reports.cs:326` (verifier severity: minor)

--report-template without --report-format silently resolves the format to 'template' and succeeds, while pinned Gitleaks fatals (either 'Unknown report format' from extension inference or 'Report format must be template...').


*Failure scenario:* 'picket git -r out.json --report-template t.tmpl .' writes template-rendered bytes into out.json and exits by findings; the identical gitleaks command exits 1 without scanning, so oracle exit codes and report bytes diverge.


*Evidence:* TryResolveReportFormat sets resolvedReportFormat="template" when only reportTemplatePath is set (Program.Reports.cs:324-328). Gitleaks root.go:360-402 infers the format from the report-path extension when -f is empty and then fatals via the sanity check 'Report format must be 'template' if --report-template is specified'; there is no implicit template resolution in code despite the help text.


### [MINOR] `src/Picket.Report/GitleaksFindingRedactor.cs:214` (verifier severity: minor)

Partial redaction masks by UTF-16 char count while Gitleaks masks by byte count, producing different redacted report bytes for multibyte (non-ASCII) secrets.


*Failure scenario:* A secret containing non-ASCII characters redacted with '--redact=50' yields a different visible prefix (and no split-sequence U+FFFD artifact) than the pinned oracle's report, breaking byte-exact comparison.


*Evidence:* MaskSecret uses secret.Length (UTF-16 units) and AsSpan char slicing (GitleaksFindingRedactor.cs:207-222). Gitleaks maskSecret (report/finding.go) computes lth from len(secret) (bytes) and slices secret[:lth], which can split a UTF-8 sequence and emit replacement characters after JSON encoding. Rounding (RoundToEven) matches; only the unit differs.


## report-writers

**Readiness:** Report generation is in strong shape for a 0.1.0: all compat writers (JSON/CSV/JUnit/SARIF/template) are handwritten byte-oriented StringBuilder code with no reflection serialization, native and compat formats are strictly separated at format resolution (compat mode rejects jsonl/html/toon/gitlab), and I verified byte parity against the pinned oracle's source and fixtures for empty-report shapes, field ordering, Go HTML-escape behavior, float32 entropy in JSON/JUnit, indentation, and the CSV Link-column quirk; the native HTML report is correctly escaped and CSP-locked. One compat-contract violation should be fixed before release: the JUnit writer drops the Link field from its embedded finding JSON (reachable on default git scans with recognized remotes), with template Entropy formatting and Windows stdout encoding as the next-most-important byte-fidelity gaps. Note also one deliberate, documented divergence worth a release-notes callout: Picket writes a JSON report to stdout when no --report-path is given, whereas gitleaks writes no report at all.


### [BLOCKER] `src/Picket.Report/GitleaksJunitReportWriter.cs:89` (verifier severity: blocker,blocker,blocker)

Compat JUnit writer omits the Link field from the embedded per-finding JSON, so JUnit reports byte-diverge from the Gitleaks oracle whenever SCM links are generated.


*Failure scenario:* picket git on a clone with a recognized GitHub remote (link auto-generation on) with --report-format junit --report-path out.xml: every <failure> body lacks the "Link": line that the pinned gitleaks binary emits, breaking the byte-exact report contract on a supported compat format.


*Evidence:* WriteJsonFinding (lines 75-99) writes Commit then Entropy and never emits Link, while the JSON/CSV compat writers do handle Link. Oracle: gitleaks report/junit.go getData() runs json.MarshalIndent over the full Finding struct, and report/finding.go:35 declares Link with `json:",omitempty"` positioned between Commit and Entropy, so gitleaks emits "Link": "..." per finding whenever non-empty. Picket populates Link via src/Picket.Cli/Program.GitLinks.cs (CreateScmLink for github/gitlab/azuredevops/gitea/bitbucket with auto platform detection), so the field is reachable on default git scans. tests/Picket.Tests/GitleaksJunitReportWriterTests.cs has no Link coverage (grep: no matches), and the oracle fixture junit_simple.xml only covers empty Link.


### [MAJOR] `src/Picket.Report/GitleaksTemplateReportWriter.cs:552` (verifier severity: blocker)

Template writer renders Entropy with double G17 formatting instead of Gitleaks' float32 shortest representation, diverging from the oracle for any template that prints {{ .Entropy }}.


*Failure scenario:* picket git --report-format template --report-template jsonextra.tmpl on any finding with nonzero entropy emits "Entropy": 3.681880802803402 where the pinned gitleaks emits "Entropy": 3.6818807 — template output no longer matches the oracle.


*Evidence:* FormatTemplateValue: `double number => number.ToString("G17", ...)`; ResolveFindingField line 480 returns finding.Entropy which is double (src/Picket.Engine/Finding.cs:129). Go text/template prints float32 via %v = strconv shortest-float32 (e.g. "3.6818807"), while G17 of the double yields "3.681880802803402". Gitleaks' own reference template D:/SRC/gitleaks/testdata/report/jsonextra.tmpl contains `"Entropy": {{ .Entropy }}`; the repo's ReportNumberFormatter.FormatGitleaksFloat (src/Picket.Report/ReportNumberFormatter.cs:12) implements the correct narrowing but is unused here. The existing oracle fixture only exercises Entropy 0, masking the bug.


### [MAJOR] `src/Picket.Cli/Program.Reports.cs:243` (verifier severity: major)

Reports written to stdout use Console.Out with no forced UTF-8 OutputEncoding, so on Windows consoles with legacy codepages non-ASCII report bytes are transcoded or lost, breaking byte-exactness and corrupting data.


*Failure scenario:* On a Windows cmd console (codepage 437), `picket git . > report.json` for a repo containing a finding in a path or line with é/中 produces CP437-transcoded or '?' bytes in the redirected report, differing from the gitleaks oracle's UTF-8 output and losing secret/match evidence characters.


*Evidence:* TryWriteTextReport does Console.Out.Write(report); grep across src/ finds no Console.OutputEncoding assignment anywhere (only GitSource.cs sets StandardOutputEncoding for reading git). Stdout is the DEFAULT report destination: TryResolveReportFormat lines 330-334 resolve null report path to "json", and docs/REPORTS.md states "When no path or format is supplied, JSON is written to standard output." .NET encodes Console.Out using the console output codepage (e.g. CP437), whereas gitleaks writes raw UTF-8 bytes to os.Stdout (cmd/root.go:470-471). File-path reports are unaffected (File.WriteAllText UTF-8 no BOM at line 254).


### [MINOR] `src/Picket.Report/GitleaksJunitReportWriter.cs:318` (verifier severity: major)

Invalid-XML-character replacement emits the character reference &#xFFFD; where Go's encoding/xml emits literal U+FFFD bytes, and 0xFFFE/0xFFFF are passed through instead of replaced.


*Failure scenario:* A finding whose Match or commit Message contains a control character such as \x1b (ANSI escape in a log file) rendered via --report-format junit produces &#xFFFD; where the pinned gitleaks emits the 3-byte U+FFFD sequence — a byte-level mismatch.


*Evidence:* AppendXmlRune appends "&#xFFFD;" for invalid characters; Go xml escapeText uses escFFFD = []byte("�") (literal EF BF BD bytes). IsInvalidXmlCharacter (lines 325-330) checks `value < 0x20 || (> 0xD7FF and < 0xE000) || > 0x10FFFF`, but Go's isInCharacterRange ends the BMP valid range at 0xFFFD, so U+FFFE/U+FFFF are escaped by Go and passed through literally by Picket. The divergent behavior is codified by test WriteReplacesInvalidXmlControlCharacters (tests/Picket.Tests/GitleaksJunitReportWriterTests.cs:73-84 asserts &#xFFFD;).


### [MINOR] `src/Picket.Report/GitleaksCsvReportWriter.cs:128` (verifier severity: minor)

CSV quoting predicate is narrower than Go's csv.Writer: fields equal to \. or starting with non-ASCII/other Unicode whitespace are left unquoted, diverging from the oracle.


*Failure scenario:* A Match or Message field beginning with a non-breaking space (U+00A0) — e.g. a secret matched on a line pasted from a web page — is written unquoted by Picket but quoted by gitleaks, producing byte-different CSV.


*Evidence:* NeedsQuotes only treats a leading ' ' or '\t' (lines 135-138) plus embedded , " \r \n as quote triggers. Go's encoding/csv fieldNeedsQuotes also quotes when the field is exactly `\.` (Postgres guard) and when the first rune satisfies unicode.IsSpace — including \v, \f, U+0085, U+00A0, U+2000-200A, U+2028/2029, U+3000. Gitleaks CsvReporter (report/csv.go) uses csv.NewWriter defaults, so these fields are quoted by the oracle.


### [MINOR] `src/Picket.Report/GitleaksFindingRedactor.cs:214` (verifier severity: minor)

Redaction masking diverges from gitleaks for non-ASCII secrets (UTF-16 char slicing vs UTF-8 byte slicing) and for empty-secret path-only findings (gitleaks' ReplaceAll-with-empty-old interleaving is not replicated).


*Failure scenario:* picket dir --redact with a custom config containing a path-only rule: gitleaks emits Match like "REDACTEDfREDACTEDiREDACTED..." (interleaved) while Picket emits the original "file detected: ..." text; likewise a secret containing multibyte characters masks at a different boundary than the oracle at partial redaction percentages.


*Evidence:* MaskSecret computes visibleLength from secret.Length (UTF-16 code units) and slices with AsSpan(0, visibleLength); gitleaks maskSecret (report/finding.go:88-100) uses len(secret) bytes and secret[:lth] byte slicing, which for multibyte secrets keeps different amounts of text and can split a UTF-8 sequence (later JSON-marshaled as U+FFFD). Additionally, for Secret == "" Picket returns the finding unchanged (lines 72-80), while gitleaks Redact (finding.go:78-86) runs strings.ReplaceAll(Line/Match, "", secret), which interleaves the mask between every rune of Line and Match for path-only rule findings.


## security-network

**Readiness:** The network and verification surface is release-ready. Live verification and revocation are strictly opt-in (--live/--verify flags, --confirm-revocation plus env-var-only credentials), the compat surface performs no outbound requests, and the SSRF guard is enforced both at preflight and at socket connect time against the actually-connected addresses with redirects disabled, HTTPS-only defaults, metadata-host blocking, rate limiting, and 64KB response truncation. Secrets never reach logs, exceptions, or disk: the validation cache persists only SHA-256/HMAC-protected non-secret metadata in owner-only files, the revocation payload buffer is zeroed, and the crash handler withholds exception details; the compatibility diagnostics HTTP server is loopback-only with a random constant-time-compared token and exposes only process counters. The three findings are hardening polish (two rare blocklist gaps reachable only with explicit --live plus a hostile endpoint, one input-hygiene inconsistency, one error-clarity nit) and none blocks a 0.1.0 release.


### [MINOR] `src/Picket.Security/EndpointGuard.cs:150` (verifier severity: minor)

The non-public address classifier misses 192.88.99.0/24 (6to4 relay anycast, RFC 7526) in IsNonPublicIPv4 and the RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48 in IsNat64NonPublicAddress (which only matches 64:ff9b::/96 with zero middle bytes).


*Failure scenario:* A user opts into --live with a copy-pasted --github-api-endpoint whose attacker-controlled DNS resolves to 64:ff9b:1::a00:1 on a NAT64 network; both the preflight and connect-time guards classify it public, and the Bearer-token verification request is routed to internal 10.0.0.1 despite the SSRF guard. Requires explicit --live plus a hostile endpoint/DNS, so defense-in-depth only.


*Evidence:* IsNonPublicIPv4 (lines 148-167) enumerates 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, >=224 — no 192.88.99/24 arm. IsNat64NonPublicAddress (lines 218-237) requires bytes 4-11 to be zero, so 64:ff9b:1::/48 addresses embedding private IPv4s pass as public.


### [MINOR] `src/Picket.Verify/GitHubSecretLiveValidatorOptions.cs:50` (verifier severity: minor)

UserEndpoint accepts URIs containing userinfo (user:password@host) while the parallel GitHubCredentialRevokerOptions.CredentialEndpoint setter rejects them, an inconsistent hygiene gate on config-supplied URLs.


*Failure scenario:* A user pastes an endpoint URL with embedded credentials; verify silently accepts it and the userinfo is never sent (Authorization is overwritten with the finding secret), masking the misconfiguration that revoke would loudly reject. No secret leak — evidence and cache normalization strip userinfo (SchemeAndServer|Path components) — purely a consistency/hygiene gap.


*Evidence:* UserEndpoint setter (lines 39-57) validates only IsAbsoluteUri and absence of Query/Fragment; GitHubCredentialRevokerOptions.CredentialEndpoint (GitHubCredentialRevokerOptions.cs lines 42-47) additionally rejects UserInfo. CLI TryReadUriFlag (Program.CommandLine.cs:158-173) passes any absolute URI through, so `picket verify --live --github-api-endpoint https://user:pass@host/user` is accepted.


### [MINOR] `src/Picket.Cli/Program.Revoke.cs:45` (verifier severity: minor)

The revoke path sets the proxy endpoint without the CLI-side EndpointGuard preflight that the live-verification path performs, so a guarded (non-public) proxy surfaces as an 'indeterminate' outcome with exit code 2 instead of a clear blocked error.


*Failure scenario:* User runs `picket revoke github --github-api-proxy https://10.0.0.5/ --confirm-revocation ...`; instead of a preflight 'blocked proxy' message and exit 1, they get 'revocation outcome is indeterminate ... the provider outcome is unknown' and exit 2, suggesting a transient provider failure rather than a policy block. Security enforcement is unaffected.


*Evidence:* Program.LiveVerification.cs lines 38-45 call EndpointGuard.Evaluate on the proxy and print 'blocked GitHub API proxy endpoint' before use; Program.Revoke.cs lines 40-51 assign options.ProxyEndpoint with only the setter's HTTPS/userinfo checks. The connect-time guard (EndpointGuardHttpConnector.cs:31-37) still blocks the connection, but the resulting HttpRequestException is mapped to CredentialRevocationState.Indeterminate ('request failed; the provider outcome is unknown', GitHubCredentialRevoker.cs:71-77).


## security-input

**Readiness:** Untrusted-input handling in this codebase is unusually disciplined for a 0.1.0: in-memory archive extraction with no zip-slip surface, normalized entry paths, native-mode bomb caps (depth/entries/bytes/ratio plus zstd window caps), symlink containment, git argument allowlisting, a DNS-pinning SSRF guard covering metadata hosts and all private/mapped IPv6 ranges, owner-only state files with atomic temp-file writes, HMAC-authenticated hash-only caches, and a crash handler that withholds exception details so secrets cannot leak into diagnostics. The release risks are concentrated in the gitleaks-compat profile: archive traversal there runs with every bomb cap disabled while buffering all decompressed content in memory (a real DoS on untrusted repos once the user passes the Gitleaks-documented --max-archive-depth flag), and Picket's content-based archive identification diverges structurally from the pinned oracle's filename-based identification, which can silently change the scanned file set in default compat runs. I recommend fixing both compat-profile items (apply native caps or streaming in compat archive mode, and align archive identification with the oracle) before a public release; the UTF-8 replacement divergence is an edge case that mainly needs oracle fixture coverage.


### [MAJOR] `src/Picket.Cli/Program.Directory.cs:59` (verifier severity: major)

In the gitleaks-compat profile, --max-archive-depth enables archive extraction with every archive-bomb cap disabled and full in-memory buffering, allowing memory-exhaustion DoS from untrusted archives.


*Failure scenario:* User runs 'picket dir --max-archive-depth 2 untrusted-repo/' (a Gitleaks-documented flag) against a repo containing a crafted zip whose entries each decompress near 2GB, or a 10KB gzip/zstd bomb: Picket decompresses and retains every entry in memory with no entry, byte, or ratio cap, driving multi-GB RSS until the process or CI host is OOM-killed and the scan fails.


*Evidence:* Program.Directory.cs:58-61 and Program.Git.cs:40-43 set maxArchiveEntries=0, maxArchiveBytes=null, maxArchiveCompressionRatio=0 unless nativeMode; the --max-archive-depth flag is accepted in compat mode (Program.Directory.cs:338-346, Program.Git.cs:257) while --max-archive-entries/--max-archive-megabytes/--max-archive-ratio are nativeMode-gated (Program.Directory.cs:348-376). ArchiveReadBudget.TryConsumeBytesCore (ArchiveReadBudget.cs:128) treats MaxBytes==0 as unlimited and MaxEntries==0 as unlimited (line 50); maxEntryBytes=maxTargetBytes is also null by default. ArchiveReader.TryReadStreamBytes (ArchiveReader.cs:405-464) buffers each fully decompressed entry into a MemoryStream and retains every entry's byte[] in the entries list, so cumulative memory across entries is unbounded (per-entry bounded only by MemoryStream's ~2GB ceiling). The pinned Gitleaks streams archive fragments in ~10KB chunks (gitleaks sources/file.go decompressorFragments, common.go maxPeekSize), so its memory stays bounded where Picket's does not. DESIGN.md:565 documents archive-bomb caps as native-mode-only, but AGENTS.md lists archive-bomb caps as a security requirement.


### [MAJOR] `src/Picket.Sources/DirectorySource.cs:138` (verifier severity: major)

Compat-mode archive identification is content-header based while the pinned Gitleaks identifies archives by filename only, silently changing which files are scanned versus skipped even at the default --max-archive-depth 0.


*Failure scenario:* Default compat scan of a repo containing (a) a .jar/.docx/.nupkg or any zip-magic file without a .zip name: Gitleaks scans its raw bytes (and can report secrets in stored/uncompressed regions) while Picket silently skips it — missing findings; or (b) a plaintext file named secrets.zip: Gitleaks skips it as an archive while Picket scans it and reports extra findings. Either direction breaks byte-exact report parity with the pinned oracle.


*Evidence:* DirectorySource.AddSourceFile calls ArchiveReader.IsArchiveFile(fullPath) (DirectorySource.cs:138), which sniffs the first 512 bytes for zip/gzip/zstd/ustar magic (ArchiveReader.cs:17-30, 492-551); when MaxArchiveDepth==0 the method returns without adding the file (lines 140-163), so any file whose content matches archive magic is dropped from the scan regardless of name. Gitleaks calls archives.Identify(ctx, s.Path, nil) with a nil stream (gitleaks sources/file.go:53), i.e. filename-extension matching only, and at MaxArchiveDepth 0 skips filename-identified archives (file.go:59-76) while raw-scanning archive-content files with non-archive names via fileFragments (file.go:86).


### [MINOR] `src/Picket.Sources/GitSource.cs:62` (verifier severity: major)

Compat git scanning decodes git patch output as UTF-8 with replacement-character fallback before matching, while Gitleaks scans raw patch bytes, producing divergent secret text and column offsets for histories containing invalid UTF-8.


*Failure scenario:* A git history contains a Latin-1 or binary-ish text file diff with a secret adjacent to invalid UTF-8 bytes (e.g. truncated multi-byte sequence on the same line): Picket's Match/Secret/Line text and StartColumn/EndColumn differ from the Gitleaks oracle's byte-exact report, failing the compat contract for that repo.


*Evidence:* GitSource.CreateGitProcess sets StandardOutputEncoding = Encoding.UTF8 (GitSource.cs:62) so invalid byte sequences become U+FFFD during ReadLine, and FlushFragment re-encodes with Encoding.UTF8.GetBytes (GitSource.cs:320-322), permanently replacing original bytes with EF BF BD before regex matching. .NET's decoder emits one U+FFFD per maximal invalid subsequence (e.g. truncated F0 9F 92 -> one U+FFFD) while Go emits one replacement rune per invalid byte at JSON-encoding time (three U+FFFD for the same input), and Gitleaks' regex matching runs over the original raw bytes.


## sources-git

**Readiness:** The git patch source model is largely faithful to the Gitleaks oracle: command construction (`git log -p -U0 --full-history --all --diff-filter=tuxdb`, additions-only, `git diff -U0 --no-ext-diff [--staged] .`), hunk-based line remapping, binary/archive handling, staged vs pre-commit blob reads, and argument-injection hardening (all values passed via ArgumentList, revision/log-opt allowlisting) are correct, and the source-host clients route auth through headers without logging tokens. Two fidelity gaps remain that break strict byte-exact parity for a subset of repos: git-quoted/non-ASCII file paths are not unquoted (major — corrupts the File field and perturbs global path-allowlist matching), and CRLF added lines lose their `\\r` and trailing newline (minor). Recommend fixing the path-unquoting before a public release since byte-exact reporting is the core compat promise; the CRLF issue is lower priority. No security vulnerabilities, data loss, or packaging breakage were found in this area."}


### [MAJOR] `src/Picket.Sources/GitSource.cs:519` (verifier severity: blocker)

The git-compat patch parser never unquotes git-quoted file paths, so findings in files with non-ASCII or special-character names get a corrupted File path and break byte-exact parity with the Gitleaks oracle.


*Failure scenario:* A repo has a secret in a file named café.txt (or any name needing quoting: high-byte chars, tabs, backslashes, quotes). With git's default core.quotepath=true, `git log -p -U0` emits `+++ "b/caf\303\251.txt"`. ParseNewFilePath only strips a literal `b/` prefix; since the line starts with `"` it returns the whole literal `"b/caf\303\251.txt"` (quotes + octal escapes) as FilePath. Gitleaks (go-gitdiff parseQuotedName) reports `café.txt`. The finding's File field is wrong/unusable, the report is not byte-exact with the oracle, and because the global allowlist `paths` regexes (e.g. the default image/font/`.png$` excludes) are matched against this corrupted path with its trailing quote, they no longer match — changing which findings are emitted.


*Evidence:* GitSource.cs ParseNewFilePath (line 519) and ParseDiffNewFilePath (line 530) return the raw string with no dequoting. Confirmed by running `git log -p -U0 --full-history --all --diff-filter=tuxdb` on a test repo: output was `diff --git "a/caf\303\251.txt" "b/caf\303\251.txt"` and `+++ "b/caf\303\251.txt"`. go-gitdiff@v0.9.1 file_header.go parseQuotedName (used by gitleaks) unquotes these. No `core.quotepath=false` / `-c` override is set in CreateGitProcess (lines 53-97).


### [MINOR] `src/Picket.Sources/GitSource.cs:205` (verifier severity: major)

Patch parsing via TextReader.ReadLine strips the CR from CRLF-terminated added lines and drops the trailing newline, so fragment bytes are not identical to the Gitleaks/go-gitdiff fragment on CRLF repos.


*Failure scenario:* For a CRLF-encoded file, `git log -p -U0` emits added lines as `+secret\r` (verified: `+AKIAIOSFODNN7EXAMPLE^M`). Parse() reads lines with reader.ReadLine() (line 205), which consumes `\r\n` as the terminator and discards the `\r`; added lines are then re-joined with `\n` and no trailing newline (FlushFragment, line 320). The gitleaks fragment (go-gitdiff Line/Raw(OpAdd)) preserves each `\r\n`. The resulting fragment content differs byte-for-byte, which can shift reported EndColumn/Match bytes for rules whose trailing boundary consumes line-terminator context and breaks strict byte-exact report parity on CRLF-line-ending repositories.


*Evidence:* GitSource.cs line 205 uses reader.ReadLine() (strips \r and \n); line 305 stores line[1..] and line 320 joins with "\n" without a trailing terminator. go-gitdiff gitdiff.go Raw(OpAdd) (line 63) concatenates l.Line which retains the original `\r\n`. Verified with `cat -A` on git output showing `+AKIAIOSFODNN7EXAMPLE^M`.


## aot-packaging

**Readiness:** Native AOT and package readiness is strong overall: all five shipped libraries are IsAotCompatible with trim/AOT/single-file analyzers enabled, the CLI has zero reflection-based serialization (handwritten Utf8JsonWriter/JsonDocument only, no JsonSerializer, no Reflection.Emit/Activator/plugin loading), the three publish profiles byte-match docs/RELEASE.md and are enforced by convention tests, NuGet metadata (authors, MIT expression, packed root README, icon, repo URL, snupkg symbols) is complete across all seven packages, and ZstdNet 1.5.7 native assets genuinely cover every claimed non-musl RID with a heavily gated musl path. The one release-gating defect is the Windows MSI: it installs only picket.exe/picket-tui.exe/LICENSE from a ZIP payload that also carries libzstd.dll and THIRD-PARTY-NOTICES.txt, so MSI-installed scanners abort entire scans on any zstd-compressed input — fix the WiX component list (or gate MSI payload completeness the way musl artifacts are gated) before the first stable tag builds MSIs. Remaining items (incomplete third-party notices, blanket IL3058 NoWarn scope, framework-dev doc drift) are polish that can land in 0.1.x.


### [BLOCKER] `packaging/msi/Picket.wxs:26` (verifier severity: blocker,blocker,blocker)

The Windows MSI installs only picket.exe, picket-tui.exe, and LICENSE, omitting the libzstd.dll native library that the win-x64/win-arm64 publish output (and release ZIP) contains, so zstandard decompression hard-fails on MSI installs.


*Failure scenario:* User installs picket-v0.1.0-win-x64.msi from the GitHub release, runs `picket scan .` on a tree containing any zstd-compressed file (magic 28 B5 2F FD, e.g. a .zst artifact or exported container layer) -> ZSTD_createDCtx P/Invoke throws DllNotFoundException, the entire scan aborts with an error instead of reporting findings, while the identical release ZIP install succeeds on the same input.


*Evidence:* Picket.wxs components (lines 26-53) install exactly three files; release.yml:545 validates only those three files in the payload. src/Picket.Sources/Picket.Sources.csproj:14 references ZstdNet with IncludeAssets="native" (verified: ZstdNet 1.5.7 ships runtimes/win-x64/native/libzstd.dll and runtimes/win-arm64/native/libzstd.dll, which RID publish copies beside the exe and the ZIP payload includes via release.yml:235). src/Picket.Sources/ZstandardNativeMethods.cs:11-13 loads "libzstd" dynamically at runtime. ArchiveReader detects zstd by magic bytes (ArchiveReader.cs:17-24,506) and constructs ZstandardDecompressionStream at ArchiveReader.cs:330; the surrounding catch filters (lines 71, 108) only catch IOException/InvalidDataException/UnauthorizedAccessException, so DllNotFoundException escapes and aborts the scan. docs/RELEASE.md:45-49 makes 'missing library, unloadable runtime, or nonfunctional decompressor fails before packaging' an explicit release invariant for the musl channel, but the MSI channel has no equivalent gate. The MSI also drops THIRD-PARTY-NOTICES.txt, which the ZIP payload carries.


### [MINOR] `THIRD-PARTY-NOTICES.txt:1` (verifier severity: minor)

THIRD-PARTY-NOTICES.txt covers only ZstdNet and Zstandard, omitting MIT notices for third-party managed code statically compiled into the shipped Native AOT binaries (SharpYaml/Alexandre Mutel, System.CommandLine/Microsoft, Hex1b/Mitch Denny), and the Picket.Tui.Cli tool package ships no notices file at all.


*Failure scenario:* First public release distributes AOT binaries and the standalone Picket.Tui.Cli tool package embedding third-party MIT code without the required copyright/permission notices; an enterprise license audit of a security tool flags the distribution as non-compliant with the MIT notice-preservation clause.


*Evidence:* THIRD-PARTY-NOTICES.txt is 67 lines with exactly two entries (ZstdNet, Zstandard). NuGet nuspecs confirm SharpYaml 3.13.0 (Alexandre Mutel, MIT), System.CommandLine 2.0.9 (Microsoft, MIT), and Hex1b 0.165.0 (Mitch Denny, MIT) — all AOT-compiled into picket/picket-tui, and MIT requires the copyright and permission notice in copies or substantial portions. Only src/Picket.Cli/Picket.Cli.csproj:40 packs the notices file; src/Picket.Tui.Cli/Picket.Tui.Cli.csproj has no equivalent, and the MSI omits the file entirely (packaging/msi/Picket.wxs). Scout.* packages are the repo author's own (willibrandon) and need no notice.


### [MINOR] `AGENTS.md:75` (verifier severity: minor)

AGENTS.md and docs/DESIGN.md list `framework-dev` as a named release profile, but no framework-dev publish profile exists (only release-speed/release-minsize/release-diagnostics pubxml files) and docs/RELEASE.md omits it.


*Failure scenario:* A contributor follows the design docs and runs `dotnet publish -p:PublishProfile=framework-dev`, which fails because the profile file does not exist, or assumes a defined dev profile pins JIT/diagnostics settings that are actually just SDK defaults.


*Evidence:* AGENTS.md:75 and docs/DESIGN.md:179 enumerate four profiles including `framework-dev`; the only pubxml files under src/Picket.Cli/Properties/PublishProfiles/ and src/Picket.Tui.Cli/Properties/PublishProfiles/ are release-speed, release-minsize, release-diagnostics; docs/RELEASE.md documents exactly those three. DESIGN.md describes framework-dev as a framework-dependent dev build ('Not the shipped CLI'), which plain `dotnet build` provides, so nothing is functionally broken.


**Refuted during verification:** src/Picket.Cli/Picket.Cli.csproj:27 — The IL3058 suppression (commit 3128912) is a project-wide blanket NoWarn in Picket.Cli, Picket.Tui, and Picket.Tui.Cli, 


## cli-ux

**Readiness:** The CLI/TUI surface is largely disciplined: exit-code handling is consistent within each command (126 parse rejections, 1 runtime errors, 0/exit-code for clean/leaks), error messages are actionable without leaking secrets (crash output deliberately withholds exception detail in Picket.Security/CrashDiagnosticWriter.cs), `picket view` and the TUI handle missing/corrupt/summary-only reports gracefully, generated hooks are correctly shell-quoted, and no dev-machine paths are hardcoded in src/. However, one blocker must be fixed before any public release: the picket-tui scan executor's development fallback will execute `dotnet run` against a Picket.Cli.csproj found by walking up from the current directory, which is arbitrary code execution when triaging an untrusted tree in non-side-by-side installs (a layout RELEASE.md explicitly ships via dotnet tools). Two majors also deserve a decision before 0.1.0: the strict-compat commands print full unredacted reports to stdout by default where the pinned Gitleaks prints nothing (documented in REPORTS.md but absent from PARITY.md, and a secret-exposure surprise for drop-in CI migrations), and `picket dir` without a path errors instead of scanning \".\" as both Gitleaks and DESIGN.md specify. The remaining findings are polish-level (no-op verbose/banner flags, 126-vs-1 edge semantics, a silent 126 path, duplicated/missing help rows, unbounded stdin buffering).


### [BLOCKER] `src/Picket.Tui/PicketTuiProcessScanExecutor.cs:142` (verifier severity: blocker,blocker,blocker)

The release TUI scan executor falls back to executing `dotnet run --project` on a Picket.Cli.csproj discovered by walking UP from the current working directory, allowing arbitrary code execution from an untrusted scanned tree.


*Failure scenario:* User installs picket and picket-tui as dotnet tools (or any non-adjacent layout), cd's into an untrusted repository that contains a planted src/Picket.Cli/Picket.Cli.csproj (e.g. a malicious fork mimicking Picket's layout with hostile MSBuild targets), runs `picket-tui` and starts a scan from the workspace. The TUI executes `dotnet run --project <attacker csproj>`, and MSBuild evaluation/build runs the attacker's code with the user's privileges. Scanning untrusted trees is the product's core use case.


*Evidence:* ResolvePicketPath (lines 132-151): if picket.exe is not beside picket-tui, it calls FindDevelopmentPicketProject(Directory.GetCurrentDirectory()) which walks parent directories looking for src/Picket.Cli/Picket.Cli.csproj, then returns "dotnet" with prefix args ["run", "--project", <found csproj>, "--"]. This dev fallback has no #if DEBUG guard and takes precedence over PATH resolution. Every PicketTuiState constructs this executor (PicketTuiState.cs:59). docs/RELEASE.md:43 ships Picket.Tui.Cli as a dotnet tool (ToolCommandName=picket-tui), an install layout where picket.exe is NOT beside picket-tui, making the fallback reachable in production.


### [MAJOR] `src/Picket.Cli/Program.Reports.cs:241` (verifier severity: blocker)

Strict Gitleaks-compatible commands (git/dir/stdin/detect/protect) write the full unredacted JSON report to stdout whenever no --report-path is given, whereas the pinned Gitleaks binary writes no report at all unless -r is supplied.


*Failure scenario:* A team drops picket in as a gitleaks replacement in CI: `picket git . -c .gitleaks.toml`. Where gitleaks printed nothing to stdout, picket now dumps every finding including the raw Secret/Match/Line values into the CI log by default (redaction defaults to 0), permanently exposing live credentials in build logs and violating the drop-in behavioral contract.


*Evidence:* TryWriteTextReport (lines 239-244) treats a null/empty reportPath as stdout, and every compat command path (e.g. Program.Git.cs:415, Program.Stdin.cs:331) calls TryWriteReport with reportPath possibly null. The pinned oracle only builds a reporter when report-path is non-empty (..\gitleaks\cmd\root.go:348-357) and prints only log lines to stderr by default. The behavior is deliberate (docs/REPORTS.md:90 "When no path or format is supplied, JSON is written to standard output"; tests/Picket.Tests/CliCompatibilityTests.cs:40 asserts stdout contains the raw secret), but the divergence is recorded nowhere in docs/PARITY.md or docs/UPSTREAM.md, and the oracle capture commands always pass --report-path so the compare never exercises it.


### [MAJOR] `src/Picket.Cli/Program.CommandTree.cs:293` (verifier severity: blocker)

`picket dir` with no path argument errors out instead of scanning the current directory, diverging from both the pinned Gitleaks binary and Picket's own DESIGN.md contract.


*Failure scenario:* A script or pre-commit config that runs `gitleaks dir` from the repo root is migrated to `picket dir`; instead of scanning the current directory and returning 0/1 based on findings, picket fails with a usage error (System.CommandLine missing-argument error or "dir requires a path"/126), breaking the pipeline and skipping the secret scan entirely.


*Evidence:* CreateDirectoryCommand calls AddRequiredArgument(command, "picket dir", "path") (ExactlyOne arity), and the manual parser prints "dir requires a path" and returns 126 when root is null with a null defaultRoot (Program.Directory.cs:433-439; the dir command never passes defaultRoot). Gitleaks defaults the source to "." when no arg is given (..\gitleaks\cmd\directory.go:26-31), and docs/DESIGN.md section 7.1 documents the command as `picket dir [path]` (optional). No test pins the no-argument behavior, suggesting an oversight rather than a decision.


### [MINOR] `src/Picket.Cli/Program.CommandLine.cs:1044` (verifier severity: minor)

-v/--verbose, -l/--log-level, --no-color, and --no-banner are accepted on compatibility commands but are complete no-ops, while help text claims '-v Enable verbose logging' and Gitleaks actually changes output for these flags.


*Failure scenario:* A user runs `picket git . -v` expecting the gitleaks-style per-finding console output or debug logs and gets no change whatsoever; help output actively promises behavior ("Enable verbose logging") that the binary does not implement.


*Evidence:* TryHandleCommonCompatibilityFlag (lines 1044-1070) parses and discards all four flags. In the pinned Gitleaks, -v prints each finding (detect/detect.go:745), --log-level changes stderr logging, and a startup banner is written to stderr unless --no-banner (cmd/root.go:88, 133-140); Picket never prints a banner or any leaks-found/no-leaks-found summary lines. CliOptionMetadata.cs:53 and 230 still describe --verbose as "Enable verbose logging."


### [MINOR] `src/Picket.Cli/Program.CommandTree.cs:22` (verifier severity: minor)

Exit code 126 is returned for unknown commands and for invalid flag values, but the pinned Gitleaks reserves 126 strictly for 'unknown flag' errors (everything else exits 1), and the unknown-command message can name the wrong token.


*Failure scenario:* A CI wrapper that follows gitleaks semantics (treat 126 as 'bad flag, fix invocation', treat 1 as 'leaks or scan error') misclassifies `picket dri .` (typo'd command) or `picket git --timeout=abc .` runs, and a user typing `picket help bogus` is told the unknown command is 'help'.


*Evidence:* RunCommandLineAsync returns UnknownFlagExitCode (126) for unrecognized root commands (lines 20-24), and every TryRead*Flag value-parse failure in the compat parsers returns 126 (e.g. Program.Git.cs:299-302 for `--timeout abc`). Gitleaks' Execute() only exits 126 when err.Error() contains "unknown flag" (..\gitleaks\cmd\root.go:226-231); cobra invalid-argument and unknown-command errors fall through to logging.Fatal → exit 1. docs/DESIGN.md:454 likewise documents 126 as "unknown flag" only. Additionally the message interpolates args[0], so `picket help bogus` prints "unknown command: help" instead of "unknown command: bogus".


### [MINOR] `src/Picket.Cli/Program.VerifyAnalyze.cs:41` (verifier severity: minor)

`picket verify --offline=false` and `picket analyze --offline=false` exit 126 with no error message at all.


*Failure scenario:* A user scripting `picket verify --offline=$FLAG .` with FLAG=false gets exit code 126 and empty stderr, with no indication of which argument was rejected or why.


*Evidence:* Both RunVerify (line 41) and RunAnalyze (line 199) use `if (!TryReadBooleanFlag(arg, "--offline", out bool offline) || !offline) { return UnknownFlagExitCode; }`. TryReadBooleanFlag succeeds for "--offline=false" (offline=false) without printing anything, so the `!offline` branch returns 126 silently — unlike every other rejected input in the CLI, which writes an actionable line to stderr.


### [MINOR] `src/Picket.Cli/Program.CommandTree.cs:312` (verifier severity: minor)

`picket stdin --help` lists --max-archive-depth twice, and `picket scan --help` omits several flags the runtime accepts (--exit-code, --gitleaks-ignore-path, --ignore-gitleaks-allow, --follow-symlinks, --max-decode-depth, --report-template).


*Failure scenario:* A user reading `picket stdin --help` sees the duplicated --max-archive-depth row and doubts the help's accuracy; a user of `picket scan` cannot discover working flags like --exit-code or --max-decode-depth from help or shell completion because they are undeclared on the command tree.


*Evidence:* CreateStdinCommand calls AddScanLimitOptions (which unconditionally adds --max-archive-depth at line 733) and then adds a second --max-archive-depth option at line 312. CreateScanCommand builds help from AddNativeScanOptions/AddScanLimitOptions(includeMaxDecodeDepth: false) but RunScan forwards unmatched args to RunDirectory, which accepts --exit-code (Program.Directory.cs:156), --gitleaks-ignore-path (:277), --ignore-gitleaks-allow (:288), --follow-symlinks (:298), --max-decode-depth (:328), and --report-template (:202) — none of which appear in `picket scan --help`.


### [MINOR] `src/Picket.Cli/Program.Stdin.cs:267` (verifier severity: minor)

`picket stdin` buffers the entire standard input into a single in-memory MemoryStream/byte[] before scanning, with no size cap, unlike Gitleaks' streaming stdin source.


*Failure scenario:* Piping a very large stream (e.g. `git cat-file --batch --all | picket stdin`, tens of GB) allocates the entire input in memory (with a second copy from ToArray), driving the process to OutOfMemory/LOH thrash where gitleaks completes with bounded memory.


*Evidence:* RunStdinAsync copies Console.OpenStandardInput() fully into a MemoryStream and materializes stream.ToArray() (lines 266-268) before any scanning; --max-target-megabytes is only applied later inside SecretScanner.Scan. The pinned Gitleaks scans stdin as streamed fragments (sources package) and never requires the whole pipe in memory.


## store-baseline

**Readiness:** The persistence/baseline/cache area is in strong shape for a 0.1.0: the scan cache and checkpoint stores are carefully engineered (per-user HMAC authentication, AES-GCM-sealed secret hashes, entry-name/content cross-validation, bounded imports, FileShare.None locking with graceful contention handling, corrupt data degrading to cache misses or clear errors), docs/CACHE.md accurately reflects the implementation, native-only features (--cache-dir, --baseline-mode, --checkpoint) are correctly fenced out of strict compat mode, and fingerprints/baselines are path-separator stable across Windows and Linux. The one release-relevant gap is a compat divergence on the baseline error path: picket fails closed (exit 1, no report) where the pinned Gitleaks continues without the baseline, which can turn oracle-passing CI runs into failures; it cannot hide findings, but it should either be fixed to match the oracle or explicitly documented as intentional before release. Remaining findings are edge-case parsing divergences and one export robustness nit.


### [MAJOR] `src/Picket.Cli/Program.Reports.cs:28` (verifier severity: major)

A missing or malformed --baseline-path aborts the scan with exit 1 and no report, while pinned Gitleaks logs an error and continues scanning without baseline suppression, producing divergent exit codes and report output.


*Failure scenario:* CI runs `picket dir --baseline-path stale.json .` on a clean tree after the baseline file was deleted: gitleaks exits 0 and writes an empty report; picket exits 1 and writes no report, breaking a pipeline that passed under the oracle. With findings present, gitleaks reports all findings while picket produces no report at all.


*Evidence:* TryLoadBaseline catches IOException/InvalidDataException and returns false; every strict-compat call site returns CompleteRun(1) without scanning (Program.Git.cs:368-371, Program.Directory.cs:598-601, Program.Stdin.cs:274-277). Gitleaks cmd/root.go (pinned clone ../gitleaks, lines ~324-330) does `logging.Error().Msgf("Could not load baseline...")` and continues; detect/baseline.go LoadBaseline errors are non-fatal, so gitleaks scans, writes the report, and exits by findings count.


### [MINOR] `src/Picket.Compat/GitleaksBaseline.cs:168` (verifier severity: minor)

Baseline JSON parsing is stricter than Gitleaks: property lookups are case-sensitive and a JSON null root is rejected, whereas Go's json.Unmarshal matches field names case-insensitively and unmarshals null into an empty baseline.


*Failure scenario:* A baseline file containing `null`, or one produced by a tool emitting `"ruleID"`/`"file"` casing, loads in gitleaks (fields matched or baseline empty, scan proceeds) but makes picket print "the format of the file ... is not supported" / silently read empty fields, changing which findings are suppressed relative to the oracle.


*Evidence:* GetString/GetInt32 use TryGetProperty with exact names ("RuleID", "StartLine", ...) at lines 168-196; ReadFindings throws InvalidDataException for any non-array root at lines 119-123. Gitleaks detect/baseline.go uses json.Unmarshal into []report.Finding, which is case-insensitive on keys and accepts `null` without error.


### [MINOR] `src/Picket.Compat/GitleaksIgnore.cs:162` (verifier severity: minor)

Picket normalizes backslashes in the finding's own file path and fingerprint at ignore-lookup time, while Gitleaks only normalizes .gitleaksignore entries, so findings in files whose names contain a literal backslash are suppressed by picket but reported by gitleaks.


*Failure scenario:* On Linux, a file literally named `a\b.txt` produces a finding with fingerprint `a\b.txt:rule:5`; a .gitleaksignore entry `a\b.txt:rule:5` is normalized to `a/b.txt:rule:5` by both tools, so gitleaks fails to match and reports the leak while picket normalizes the finding side too and suppresses it (exit 0 vs 1).


*Evidence:* CreateGlobalFingerprint calls NormalizePath(finding.File) (lines 162-170) and IsIgnored normalizes finding.Fingerprint via NormalizeFingerprint (line 119). Gitleaks detect.go AddFinding builds globalFingerprint from finding.File verbatim (line 712) and looks it up unmodified; only ignore entries are run through the backslash replacer in AddGitleaksIgnore.


### [MINOR] `src/Picket.Store/PicketScanCache.cs:218` (verifier severity: minor)

Cache export fails entirely if any single entry file has a last-write timestamp outside the zip DOS range (before 1980 or after 2107), because ZipArchiveEntry.LastWriteTime's ArgumentOutOfRangeException is not in the per-entry catch list.


*Failure scenario:* A cache entry restored by a backup/sync tool with a zeroed (1601/1970) timestamp makes `picket cache export --cache-dir ... --output ...` fail with a generic message for the entire archive, even though all entries are valid and authenticated; pruning by age (PruneOlderThan) would also immediately consider such entries expired.


*Evidence:* Export's per-entry try (lines 213-228) catches only IOException and UnauthorizedAccessException; `archiveEntry.LastWriteTime = new DateTimeOffset(lastWriteTimeUtc, TimeSpan.Zero)` at line 218 throws ArgumentOutOfRangeException for out-of-range dates, escaping the loop. Program.Cache.cs:189 catches it as ArgumentException, so the whole export returns exit 1 ("failed to export cache") rather than skipping the one entry the way corrupt entries are skipped (ExportSkipsCorruptEntries covers content corruption only).


## rules-corpus

**Readiness:** The rule system is largely in strong shape: the embedded Gitleaks default config is byte-identical to the pinned 4c232b5 upstream snapshot, native rule packs (picket-default/strict/experimental) are correctly opt-in and cannot leak into strict compat (detectors, randomness scoring, and --rule-pack are all gated on --profile picket across git/dir/stdin/rules), the keyword prefilter is case-fold-correct on both sides, and extend/disabledRules/generic-precedence semantics were verified against the pinned Gitleaks source. However, the hand-written GenericApiKeyMatcher that replaces Scout regex evaluation for the compat generic-api-key rule has two Go-verified behavioral divergences from the pinned regex (uppercase 'API' keyword island and case-sensitive base64 alternative) that miss real secrets Gitleaks reports on common inputs - these are release blockers for the byte-exact compatibility contract and should be fixed or the matcher reverted to Scout regex before any public release. The remaining findings (extend-merge skipReport/required divergence, Codex refresh-token FP breadth) are survivable for 0.1.0 but worth addressing early.


### [BLOCKER] `src/Picket.Engine/GenericApiKeyMatcher.cs:448` (verifier severity: blocker,blocker,blocker)

The hand-written generic-api-key matcher's `(?-i:[Aa]pi|API)` emulation only accepts a lowercase 'p' (and any-case 'i'), so it misses uppercase 'API' matches the pinned Gitleaks regex finds and accepts 'apI'/'ApI' forms Gitleaks rejects.


*Failure scenario:* Strict-compat scan (`picket dir`/`git`/`stdin`, no --profile picket) of a file containing `API = "Zq7Rw9Xt2Kp5"` -> pinned Gitleaks reports a generic-api-key finding, Picket reports nothing (missed secret, report/exit-code mismatch vs oracle). Conversely `myApI = "Zq7Rw9Xt2Kp5"` -> Picket reports a finding Gitleaks does not (extra finding). Both violate the byte-exact Gitleaks-compatibility contract on the highest-traffic default rule.


*Evidence:* GenericApiKeyMatcher.CanHandle (line 11-16) replaces Scout regex evaluation for the stock pinned generic-api-key pattern (byte-identical to ../gitleaks config/gitleaks.toml line 640), and SecretScanner.cs line 447-451 routes the compat rule through it unconditionally (strict compat included). StartsWithApiKeyword (lines 448-454) requires input[1]=='p' (lowercase only) while allowing input[2] in {'i','I'}. Verified against Go stdlib regexp with the exact pinned pattern: `API = "abcdefgh1234"` MATCHES in Go, `apI = ...`/`ApI = ...` do NOT. The rule's keyword prefilter includes case-insensitive "api", so the fragment reaches the rule in both engines.


### [BLOCKER] `src/Picket.Engine/GenericApiKeyMatcher.cs:494` (verifier severity: blocker,blocker,blocker)

The matcher's base64 secret alternative (`[a-z0-9][a-z0-9+/]{11,}={0,3}`) is implemented lowercase-only, but the pinned pattern has a global `(?i)` flag so Gitleaks case-folds that class; mixed/upper-case base64 secrets containing '+' or '/' are missed.


*Failure scenario:* Strict-compat scan of `secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (AWS-style 40-char mixed-case base64 secret) -> pinned Gitleaks reports a generic-api-key finding via the case-folded base64 alternative; Picket reports nothing. Missed real secrets plus oracle report divergence in strict compatibility mode.


*Evidence:* IsAsciiLowerDigit (lines 494-498) and IsLowerBase64Byte (lines 489-492) accept only a-z, 0-9, '+', '/'. Verified with Go stdlib regexp using the exact pinned pattern: `key = AB+cd/ef0123;` and `key = aB+cd/ef0123;` both MATCH in Go (case-insensitive class under (?i)), but the Picket matcher fails them (word alternative dies at '+', base64 alternative dies at the first uppercase letter). The word-secret alternative cannot rescue values whose first 10 chars include '+' or '/'.


### [MAJOR] `src/Picket.Compat/GitleaksRuleDefinition.cs:125` (verifier severity: major)

Extend-merge semantics diverge from pinned Gitleaks for skipReport and required rules: Picket ORs the overriding rule's skipReport and prefers its [[rules.required]], while Gitleaks' Config.extend() keeps only the base rule's SkipReport/RequiredRules and discards the override's.


*Failure scenario:* A user .gitleaks.toml with `[extend] useDefault = true` plus `[[rules]] id = "aws-access-token" skipReport = true` (or a [[rules.required]] block): pinned Gitleaks ignores the override and still reports aws-access-token findings; Picket suppresses them (or applies required-rule proximity gating Gitleaks would not). Reports and exit codes diverge from the oracle for extend+override configs in strict compat mode.


*Evidence:* MergeWithBase lines 125-126: `SkipReport || baseRule.SkipReport` and `RequiredRules.Count != 0 ? RequiredRules : baseRule.RequiredRules`. Pinned gitleaks config/config.go extend() (lines ~450-480 at commit 4c232b5) copies only Description/Entropy/SecretGroup/Regex/Path overrides and appends Tags/Keywords/Allowlists; `c.Rules[ruleID] = baseRule` keeps baseRule.SkipReport and baseRule.RequiredRules, dropping the extending config's values. Both loaders are used by strict-compat commands (GitleaksConfigLoader.ResolveExtends line 736-739 calls MergeWithBase).


### [MAJOR] `src/Picket.Engine/NativeJsonCredentialDetector.cs:294` (verifier severity: major)

The picket-openai-codex-refresh-token detector flags any `refresh_token` assignment whose value is >=32 printable chars containing '_' (or >=48 chars) as a critical/high-confidence Codex credential, with no rt_ prefix, entropy, or randomness gate, so obvious placeholders and other providers' docs fire.


*Failure scenario:* Native scan (`picket scan` or `--profile picket`) of documentation containing `refresh_token = "insert_your_refresh_token_here_now"` -> critical 'Detected a Codex OAuth refresh token' finding marked structurally valid; similar hits on any OAuth sample/tutorial in any language. Embarrassing default-profile false positives misattributed to OpenAI Codex.


*Evidence:* IsPlausibleCodexToken (lines 286-296): refresh branch is `value.Contains('_') || value.Length >= 48` after a length>=32 printable check. AddCodexAssignments (lines 168-212) runs on ANY native-mode input (not only JSON) for every occurrence of the `refresh_token` label followed by '='/':'. The rule (EmbeddedPicketConfig.cs lines 257-271) is severity critical / confidence high with no randomnessThreshold, and its own example uses an `rt_` prefix that the detector never requires. OfflineSecretValidator.ValidateCodexRefreshToken (OfflineSecretValidator.cs lines 279-289) is equally permissive, so the finding is annotated "structurally valid". Native picket-* rules also bypass Gitleaks global stopword allowlists by design (CompiledRuleSet.cs line 131).


### [MINOR] `src/Picket.Engine/GitleaksRegexCompiler.cs:92` (verifier severity: minor)

TranslatePattern's character-class tracking treats a `]` immediately after `[` (or `[^`) as the class terminator, but Go/RE2 treats a leading `]` as a literal class member, so perl escapes later in such a class are mistranslated into nested bracket expressions.


*Failure scenario:* A custom strict-compat .gitleaks.toml rule using a Go-valid class like `[]\d]` or `[^]\s]` silently matches different text in Picket than in Gitleaks (e.g. requires a trailing ']' after the digit), producing divergent findings with no load-time error.


*Evidence:* Lines 77-95: on `[` inClass=true, and the very next `]` sets inClass=false with no first-character exception. Verified with Go stdlib regexp: `[]a]` and `[]\d]` compile, and `[]\d]` matches "5" and "]" but not "x" (leading ] is literal, \d is in-class). Picket would translate `[]\d]` to `[][0-9]]` (class of ']','[',0-9 followed by a required literal ']'), changing semantics. No pattern in the pinned gitleaks.toml uses this form (grep '\[\]' returns nothing), so only custom user configs are affected.


**Refuted during verification:** src/Picket.Compat/GitleaksConfigLoader.cs:731 — Unknown [extend].disabledRules entries are silently ignored, whereas pinned Gitleaks logs a 'Disabled rule doesn't exist; src/Picket.Engine/CompiledRuleSet.cs:71 — CompiledRuleSet.CompileDeferredRegexes is never called from any code path, so deferred (regexesPrevalidated) rule and al


## test-quality

**Readiness:** Test quality in this repo is well above 0.1.0 norms: ~45k lines of MSTest/MTP tests that all run unconditionally in CI (the differential comparisons use committed, hash-manifested Gitleaks oracles, so nothing is skipped when the oracle binary is absent), security boundaries are genuinely well covered (connect-time SSRF guard with DNS-rebinding coverage, three-tier archive-bomb caps for dir/git/zstd sources, cache path-traversal and poisoning rejection, 111 redaction assertions, owner-only file permissions asserted on both Windows ACLs and Unix modes), live provider tests use loopback fixture servers and fakes exclusively, and env-mutating tests are correctly serialized. The release-blocking risk is concentrated in what the suite does NOT execute: the shipped Native AOT binaries never run the compat suite (one musl smoke test is the only AOT execution before release), the real-gitleaks differential corpus is 7 scenarios that no CI job ever re-validates against the pinned binary, and the 222 Gitleaks default rules have no per-rule corpus or even a compile-all test. I would not ship a public release claiming byte-exact Gitleaks compatibility until at least the oracle fixture suite (or a representative subset) is run against the published AOT binaries in the release pipeline and a rules-check/compile pass over the full default rule set exists.


### [MAJOR] `tests/Picket.Tests/CliExecutablePath.cs:10` (verifier severity: major)

The entire compat/differential test suite runs only the framework (JIT) CLI build; the published Native AOT binaries that will actually ship are never exercised by any test except a single Linux musl zstd smoke scan.


*Failure scenario:* An AOT/trim-specific behavior difference (globalization-invariant mode, trimmed converter, single-file path resolution, regex compilation differences under release-speed profile) changes report bytes or exit codes only in the shipped binary; all 5,893 lines of CliCompatibilityTests and the oracle byte comparisons pass green in CI while the released Windows/macOS binary violates the byte-exact Gitleaks contract on day one.


*Evidence:* CliExecutablePath.Resolve looks only under src/Picket.Cli/bin/{config}/net10.0 (lines 9-37), never at publish output. .github/workflows/ci.yml runs 'dotnet test' (line 83) BEFORE 'Publish Native AOT binaries' (lines 88-93), and the only AOT execution is the musl smoke test (lines 104-136) on Linux RIDs. release.yml likewise only smoke-tests musl (lines 190-218); win-x64/win-arm64/osx AOT binaries are attested and released with zero executions.


### [MAJOR] `tests/Picket.Tests/CompatibilityOracleFixtureTests.cs:12` (verifier severity: major)

Real-Gitleaks differential coverage is only 7 committed oracle scenarios (csv/junit/sarif have exactly one each, template format has none, git history is a single-commit repo), and no CI job ever re-runs the pinned gitleaks binary, so most compat behavior is asserted only by hand-written expectations that can encode the same misreading as the implementation.


*Failure scenario:* A divergence from gitleaks v8.30.0-23-g4c232b5 in an area with no oracle (e.g. template rendering whitespace, multi-commit/rename patch attribution, csv quoting of an edge value, empty-report bytes for a format other than json) ships unnoticed because both the implementation and its test were written from the same (wrong) reading of upstream, and nothing ever compares against the real binary again.


*Evidence:* tests/fixtures/oracles contains 7 fixtures; only basic-dir-json covers csv/junit/sarif (s_compatibilityReportFormats used in one test); all other oracles are json-only. rg over .github/workflows finds zero references to gitleaks or the Capture/Promote scripts — captures are manual (scripts/Capture-GitleaksOracle.cs). docs/DESIGN.md line 1197 claims the differential suite covers staged diffs, archives, decoders, binary files, symlinks, Windows paths, invalid UTF-8, templates, empty reports, and partial errors — none of those have a promoted oracle; they are covered only by self-referential CliCompatibilityTests assertions.


### [MINOR] `tests/Picket.Tests/GitSourceTests.cs:259` (verifier severity: minor)

Malformed git patch handling — a DESIGN.md §10.4 security-test requirement — is covered by exactly one reflection-based private-method test (hunk-header integer overflow); no end-to-end test feeds GitSource corrupted patch streams.


*Failure scenario:* A repository containing a commit crafted to emit an unexpected git-log patch shape (e.g. hunk header the parser mis-splits, or metadata line resembling a diff header) causes GitSource to misattribute lines, skip a file silently, or throw and abort the scan — none of which any current test would detect; the reflection test also breaks silently into a test failure if the private method is ever renamed.


*Evidence:* ParseNewStartLineTreatsOverflowAsInvalidHunk uses BindingFlags.NonPublic reflection into GitSource.ParseNewStartLine (lines 261-267). rg for malformed/corrupt/truncated across GitSourceTests and CliCompatibilityTests finds no test covering truncated diffs, garbage bytes, invalid UTF-8 inside a patch, or hostile commit metadata against the 567-line parser in src/Picket.Sources/GitSource.cs. DESIGN.md line 1219 lists 'malformed git patches' as a required security test area.


### [MINOR] `tests/Picket.Tests/Picket.Tests.csproj:22` (verifier severity: minor)

The test project declares a build-ordering ProjectReference for Picket.Tui.Cli (ReferenceOutputAssembly=false) but none for Picket.Cli, even though ~15 test classes execute the picket binary from src/Picket.Cli/bin.


*Failure scenario:* A developer runs 'dotnet test tests/Picket.Tests' (or an IDE per-project test run) after editing Picket.Cli source; the suite silently executes the stale CLI binary and passes, masking a regression that only full-solution CI later catches — or fails with FileNotFoundException on a clean checkout, an order-dependence AGENTS.md's own conventions try to avoid.


*Evidence:* Picket.Tests.csproj lines 12-25 list every src project except Picket.Cli; line 22 shows the Tui.Cli pattern that Picket.Cli lacks. CliExecutablePath.cs throws FileNotFoundException (line 39) or, worse, resolves a stale previously-built picket.exe when only the test project is rebuilt.


### [MINOR] `tests/Picket.Tests/PicketScanCacheTests.cs:466` (verifier severity: minor)

WriteTreatsLockContentionAsNonFatal contains no assertions — it only verifies Write does not throw while the lock file is held, without checking whether the entry was written, skipped, or corrupted.


*Failure scenario:* A regression that makes contended writes silently corrupt or truncate the existing cache entry (rather than skip it) still passes this test, since post-contention cache state is never read back or asserted.


*Evidence:* Lines 466-476: the method creates a cache, holds the lock file with FileShare.None, calls cache.Write a second time, and ends; a heuristic scan of all 95 test files found this as the only assertion-free test method in the suite.


**Refuted during verification:** docs/DESIGN.md:1205 — No rule-corpus test exists for the 222 embedded Gitleaks-compat default rules: nothing compiles every dialect-translated; tests/Picket.Tests/SecretScannerTests.cs:650 — No direct unit tests exist for GitleaksShannonEntropy.Calculate or ShannonEntropy.Calculate (AGENTS.md line 128 requires


## docs-gates

**Readiness:** Documentation is in strong release shape. Both required v1 gates are present and current: UPSTREAM.md records pinned upstream commits (the sibling Gitleaks clone HEAD matches the pinned oracle commit) plus a working sync process, and PARITY.md records each deviation with named regression tests that exist (one stale test-name citation aside). VALIDATION.md's privacy/egress model was cross-checked claim-by-claim against src/Picket.Verify and the CLI and is accurate; EMBEDDING.md examples match the real public API; README package IDs, RELEASE.md workflows/profiles/scripts, ACTION.md inputs, and the generated docs-site (CI-checked, current for Scout 0.4.7) all match the implementation. The four findings are polish-level doc inaccuracies, none blocking a 0.1.0 release.


### [MINOR] `docs/VALIDATION.md:110` (verifier severity: minor)

The revocation "accepted families" list omits ghs_ installation tokens, which the implementation accepts and submits to GitHub's irreversible revocation endpoint.


*Failure scenario:* An operator reading VALIDATION.md expects a ghs_ installation token passed via --credential-env to be rejected locally; instead picket revoke github submits it to https://api.github.com/credentials/revoke and GitHub irreversibly revokes it.


*Evidence:* docs/VALIDATION.md:110 lists accepted families as ghp_, github_pat_, gho_, ghu_, ghr_. src/Picket.Verify/GitHubCredentialSyntax.cs:74-77 (IsRevocable) accepts any IsAppToken shape, and IsAppToken (lines 24-52) accepts 40-char ghs_ tokens and stateless ghs_<id>_<jwt> tokens; UPSTREAM.md issue #2192 confirms both installation formats are supported for revocation.


### [MINOR] `README.md:25` (verifier severity: minor)

README's embeddable-library list omits Picket.Compat, which is a packed public package listed in RELEASE.md and EMBEDDING.md.


*Failure scenario:* A user reading only the README misses the package that provides GitleaksConfigLoader/PicketConfigLoader (the built-in rule sets), concluding Picket has no embeddable config/rule-loading package and abandoning an embedding evaluation.


*Evidence:* README.md:23-28 lists only Picket.Rules, Picket.Engine, Picket.Report, Picket.Security. src/Picket.Compat/Picket.Compat.csproj:4-5 sets IsPackable=true / PackageId=Picket.Compat; docs/RELEASE.md:34-38 and docs/EMBEDDING.md:6 both list five packages including Picket.Compat, and release.yml packs/pushes it.


### [MINOR] `docs/PARITY.md:171` (verifier severity: minor)

PARITY.md cites regression test "LoadFileRejectsOversizedConfig", which does not exist; the actual test is LoadFileRejectsOversizedExtendedConfig.


*Failure scenario:* A release auditor verifying the 'Local extend.path Resolution' deviation searches for the cited test name, finds no match, and cannot confirm the deviation is test-guarded without manually hunting for the renamed test.


*Evidence:* grep for LoadFileRejectsOversizedConfig across tests/ finds nothing; tests/Picket.Tests/GitleaksConfigLoaderTests.cs:1024 defines LoadFileRejectsOversizedExtendedConfig. PARITY.md's own preamble (lines 3-5) requires each entry to name its oracle/regression test.


### [MINOR] `docs/HOOKS.md:32` (verifier severity: minor)

HOOKS.md documents --max-target-megabytes as "MiB" but the implementation and other docs use decimal megabytes (n * 1,000,000 bytes).


*Failure scenario:* A hook author sizing the cap from HOOKS.md expects a 10 "MiB" (10,485,760-byte) threshold but files between 10,000,000 and 10,485,760 bytes are skipped, silently excluding files they believed were scanned in pre-commit/pre-receive enforcement.


*Evidence:* src/Picket.Cli/Program.CommandLine.cs:76 converts with `megabytes * 1_000_000`; docs/ACTION.md:52 documents the same limit as "decimal MB"; docs/HOOKS.md:32 says "Maximum file size in MiB".


## ci-release-pipeline

**Readiness:** CI genuinely gates what AGENTS.md requires: formatting, Release build+tests, AOT publish on all 8 RIDs (including a finished, well-hardened musl/Alpine path with pinned digests, ELF-interpreter validation, and container smoke scans), plus VSIX packaging and a self-scan — and the tag-to-release pipeline (archives, checksums, attestations, MSI, VSIX, NuGet, GHCR image, package-manager manifests, GitHub Release, marketplace promotion with dry-run) is remarkably complete for a 0.1.0. Input handling in the GitHub Action and Azure DevOps task is exemplary (env-carried inputs, argv arrays, no shell interpolation, escaped log commands, redact=100 and verify=false defaults), secrets are never echoed, and the Dockerfile is locked-restore, minimal-base, and non-root. The main release risk is that the end-to-end release workflow has never run: the multi-arch container publish will likely fail (no QEMU/binfmt setup, Native AOT under emulation) after NuGet packages are irreversibly pushed, and nothing is code-signed. I found no compat-contract, injection, or secret-leak issues in this area; fixing the container job (cross-compile or native arm64 runner) and doing a dry-run prerelease tag before v0.1.0 would make this area release-ready.


### [MAJOR] `.github/workflows/release.yml:731` (verifier severity: major)

The multi-arch container publish builds linux/arm64 Native AOT under QEMU emulation with no qemu/binfmt setup step, on a never-exercised release path.


*Failure scenario:* First v0.1.0 tag push: build-binaries/build-packages/publish-nuget succeed, then publish-container's arm64 stage fails at the first RUN (exec format error) or hangs/crashes in emulated ILC; publish-release never runs, so no GitHub Release or checksums are published while the immutable NuGet 0.1.0 packages are already pushed.


*Evidence:* publish-container runs `docker buildx build --platform linux/amd64,linux/arm64` (release.yml lines 723-743) on ubuntu-latest with only `docker buildx create --use`; there is no docker/setup-qemu-action or binfmt registration anywhere in the repo (grep for qemu/binfmt/setup-qemu returns nothing). Dockerfile line 5 uses `FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION}-noble` without --platform=$BUILDPLATFORM, so the arm64 stage runs the full .NET SDK, clang, and ILC emulated. Running the .NET SDK under qemu-user is unsupported upstream and extremely slow even when binfmt is present. The repo has no releases yet, so this job has never run.


### [MINOR] `.github/workflows/release.yml:676` (verifier severity: minor)

Irreversible publishes (NuGet push, GHCR image including mutable :latest) are sequenced before the rest of the release is proven, so a downstream failure leaves a half-published release.


*Failure scenario:* build-msi or the manifest generator fails after publish-nuget and publish-container complete: NuGet.org permanently holds the version, ghcr.io/willibrandon/picket:latest points at a build that has no corresponding GitHub Release, and the generated Homebrew/Scoop/winget manifests' release-download URLs 404 until a manual re-run.


*Evidence:* publish-container has `needs: validate` only (lines 674-677) and pushes version tags plus `:latest` for stable tags (lines 707-714); publish-nuget needs only build-binaries and build-packages (lines 393-397) and pushes immediately, while publish-release (lines 745-753) is the job that assembles archives, checksums, manifests, and the GitHub Release. gh release upload --clobber and --skip-duplicate make re-runs safe, but they cannot un-burn NuGet versions or retract a wrongly advanced latest tag.


### [MINOR] `.github/workflows/release.yml:555` (verifier severity: minor)

No code signing anywhere in the release path: Windows binaries/MSIs are not Authenticode-signed and macOS binaries are not codesigned or notarized.


*Failure scenario:* A user downloads picket-v0.1.0-win-x64.msi or the osx tar.gz: SmartScreen shows an unknown-publisher warning and Gatekeeper blocks the unquarantined binary unless installed via Homebrew — high-friction and reputationally awkward for a security tool, though survivable at 0.1.0.


*Evidence:* build-msi builds the MSI with WiX (line 555) and immediately hashes it; the archive packaging step (lines 223-250) produces only SHA-256 sidecars; the only integrity mechanisms are checksums and GitHub artifact attestations (actions/attest@v4). There is no signtool, codesign, notarytool, or GPG step in any workflow or script.


### [MINOR] `src/Picket.Cli/Properties/PublishProfiles/release-speed.pubxml:11` (verifier severity: minor)

Windows release zips (and therefore winget/scoop installs) ship native PDB files because symbol suppression is only configured for macOS RIDs and packaging copies the entire publish output.


*Failure scenario:* win-x64 release archive is tens of MB larger than intended and every winget/scoop install extracts large .pdb files into the portable install directory; the MSI is unaffected since it cherry-picks picket.exe/picket-tui.exe/LICENSE.


*Evidence:* release-speed.pubxml disables DebugSymbols/DebugType/NativeDebugSymbols only for osx-arm64/osx-x64 (lines 9-13); StripSymbols has no effect on Windows Native AOT, which always emits a native picket.pdb beside picket.exe. release.yml line 235 packages with `Copy-Item -Path (Join-Path $publishOutput '*') -Recurse`, so picket.pdb and picket-tui.pdb land in picket-<tag>-win-*.zip, which is also the winget InstallerUrl and scoop URL emitted by scripts/Generate-PackageManagerManifests.cs.


### [MINOR] `action.yml:135` (verifier severity: major)

The composite action runs dotnet from the consumer's workspace, so a consumer repo's global.json overrides SDK resolution and breaks the action's net10.0 build even though the action installed 10.0.301.


*Failure scenario:* A consumer repository pinning `{ "sdk": { "version": "8.0.100" } }` uses willibrandon/picket@v0: setup-dotnet installs 10.0.301, but restore/build of the action's solution resolves SDK 8 (or errors that 8.0.100 is not installed) and the action fails with an SDK/TargetFramework mismatch unrelated to the consumer's code.


*Evidence:* The Restore step runs `dotnet restore "$env:GITHUB_ACTION_PATH/Picket.slnx" --locked-mode` (line 135) and the Run step invokes `dotnet build`/`dotnet run` (lines 173-175) with the default working directory (GITHUB_WORKSPACE). dotnet resolves global.json by walking up from the current working directory, not the project path, so the consumer's global.json (not the action's pin at global.json with rollForward: disable) governs SDK selection.


**Refuted during verification:** .github/workflows/marketplace-release.yml:218 — The Azure DevOps Marketplace PAT is passed to tfx as a command-line argument instead of being kept in the environment.


## verify-internals

**Readiness:** The revocation and live-verification contracts hold up well under review: RevokeAsync is reachable only from the explicit `picket revoke github` command with a doubly-enforced --confirm-revocation, live validators are constructed only behind explicit --live/--verify flags, the TLS mode can only tighten (never bypass) certificate validation, and ambiguous HTTP/network outcomes map to error/indeterminate rather than inactive/revoked. The validation cache stores only one-way hashes and HMAC-authenticated non-secret metadata with owner-only permissions on both platforms, fails closed on tamper and expiry, and leaves no secret-bearing temp files. The one release-relevant defect is robustness, not contract violation: an unguarded cache write with a no-retry exclusive lock can abort a whole run under cache-dir contention or disk errors, which is embarrassing in shared CI but survivable for 0.1.0. Remaining items are documentation drift and cache housekeeping polish; nothing in this dimension blocks a public release.


### [MAJOR] `src/Picket.Verify/SecretLiveVerifier.cs:97` (verifier severity: major)

An optional persistent validation-cache write is unguarded and can abort an entire verify/analyze/scan run: SecretLiveVerifier.VerifyAsync calls _cache.Write with no exception handling, and SecretValidationCache.Write acquires its lock file with FileShare.None and zero retries.


*Failure scenario:* Two CI jobs share --cache-dir and both live-verify the same leaked token: both compute the same key fingerprint, the second process's OpenLock throws IOException immediately (lock held with FileShare.None), the exception propagates uncaught through VerifyAsync and TryApplyLiveValidation to the outer crash boundary, and the whole scan fails with a generic error instead of degrading to an uncached verification. Disk-full or an AV file lock during Write produces the same fatal outcome.


*Evidence:* SecretLiveVerifier.cs:97 calls _cache.Write(cacheKey, auditedResult, now + duration) outside any try/catch. SecretValidationCache.cs:118-124 opens the lock via OpenLock -> OwnerOnlyFileSystem.OpenFile(FileMode.OpenOrCreate, FileShare.None) with no retry loop (contrast PicketStateProtectionKey.OpenLock, which retries 200 times), and File.Move(overwrite: true) can also throw if a concurrent reader holds the entry open. TryApplyLiveValidation (Program.LiveVerification.cs:124-141) catches only OperationCanceledException; reads are guarded (SecretValidationCache.TryRead catches IOException) but writes are not.


### [MINOR] `docs/VALIDATION.md:61` (verifier severity: minor)

docs/VALIDATION.md says transient provider failures "can be request-cached for the current verifier run", but the code never request-caches them, and the documented ErrorResultCacheDuration option is dead for the built-in GitHub validator.


*Failure scenario:* A repository containing the same unreachable GitHub token in 50 files runs `picket verify --live` while api.github.com is erroring: every duplicate finding re-contacts the provider (bounded only by pacing/retries) even though the doc leads the user to expect in-run and 5-minute error caching, inflating run time and provider request volume beyond what is documented.


*Evidence:* SecretLiveVerifier.cs:92-99 writes the in-run request cache only inside `if (auditedResult.IsPersistentCacheable)`; GitHubSecretLiveValidator.CreateTransientErrorResult (lines 195-202) and CreateHttpResult for Error states (line 192, `isPersistentCacheable: state != SecretValidationState.Error`) both set IsPersistentCacheable=false, so no Error result is ever request-cached or persistently cached. SecretLiveVerifierOptions.ErrorResultCacheDuration (SecretLiveVerifierOptions.cs:89-97, default 5 min) is therefore unreachable for the shipped validator.


### [MINOR] `src/Picket.Cli/Program.Cache.cs:8` (verifier severity: minor)

SecretValidationCache.PruneExpired is never invoked from any CLI path, so expired live-validation cache entries accumulate on disk indefinitely; `picket cache` subcommands manage only the native scan cache.


*Failure scenario:* A long-lived CI runner uses --cache-dir on every verify run for months: expired .cache entries (correctly ignored on read via the expiry check) are never deleted, so the validation directory grows without bound and stale non-secret validation metadata (identity, scopes, evidence keyed to hashed secrets) is retained on disk far past its intended lifetime.


*Evidence:* Grep for PruneExpired across src/ shows only its definition (SecretValidationCache.cs:138); Program.Cache.cs stats/prune/export/import operate exclusively on PicketScanCache, and nothing in Program.LiveVerification.cs or elsewhere prunes the validation cache. Additionally, PruneExpired (SecretValidationCache.cs:372-379) requires a valid MAC to classify an entry as expired, so corrupt/tampered entries can never be deleted by it either.


### [MINOR] `docs/VALIDATION.md:110` (verifier severity: minor)

The revocation doc lists accepted credential families as ghp_, github_pat_, gho_, ghu_, and ghr_, but the code also accepts ghs_ GitHub App server/installation tokens.


*Failure scenario:* An operator with a leaked `ghs_` installation token reads docs/VALIDATION.md, concludes `picket revoke github` cannot handle it, and uses a slower manual path (or conversely is surprised when Picket submits a token family the doc says is unsupported), undermining trust in the documented contract for an irreversible operation.


*Evidence:* GitHubCredentialSyntax.IsRevocable (GitHubCredentialSyntax.cs:60-83) returns true for IsAppToken matches, and IsAppToken (lines 15-53) accepts 40-character `ghs_` tokens and long-form `ghs_<id>_<jwt-shaped>` installation tokens in addition to `ghu_`. docs/VALIDATION.md line 110 omits `ghs_` from the accepted-families list.


## tui-hooks-local-surface

**Readiness:** The git-hook and TUI generation code is mostly solid: QuoteShell applies correct POSIX single-quote escaping to every interpolated value (CommandPath, ConfigPath, BaselinePath, MaxTargetMegabytes, redact) so there is no command injection; option names are constants; ranges/SHAs flow through git's ArgumentList and a revision allowlist; pre-push/pre-receive use `set -eu`, handle the zero-SHA (delete/new-branch) cases, and fail closed via `|| status=$?`; TryWriteHook refuses to clobber unmanaged hooks without --force; the TUI keeps raw secrets out of state, redacts crash output, and yanks only metadata. However, the pre-commit hook is a release blocker: it omits `--staged`, so it scans the unstaged working tree and lets staged secrets slip through the canonical `git add`+`git commit` flow while blocking unrelated commits — the headline local-dev control does not actually guard commits. A one-line fix (append `--staged` in CreatePreCommitHookScript) resolves it. The TUI open-file ShellExecute fallback (arbitrary execution of report-supplied executable paths on Windows) should also be hardened before release. Not ready to ship until the pre-commit hook is corrected."}


### [BLOCKER] `src/Picket.Cli/Program.Hooks.cs:303` (verifier severity: blocker,blocker,blocker)

The generated pre-commit hook runs `picket protect --source` WITHOUT `--staged`, so it scans the unstaged working tree instead of the staged index and fails to detect secrets that are about to be committed.


*Failure scenario:* Developer adds a secret: `git add config.cs` (secret now in the index, working tree == index), then `git commit`. The installed pre-commit hook executes `picket protect --source "$repo_root" --redact=100`. RunProtect (Program.CompatShims.cs:167-171) forwards `--pre-commit` but never `--staged`, so GitSource.CreateProcess (Picket.Sources/GitSource.cs:67-77) runs `git diff -U0 --no-ext-diff .` (working tree vs index), which is EMPTY. Picket finds nothing, exits 0, and the commit proceeds with the secret. Conversely, an unstaged edit that will NOT be committed IS scanned, blocking unrelated commits. Behavior is exactly inverted from a functional pre-commit guard, and it diverges from Gitleaks' own recommended pre-commit invocation (`.pre-commit-hooks.yaml`: `gitleaks git --pre-commit --redact --staged`). The hook must append `--staged` in CreatePreCommitHookScript.


*Evidence:* Program.Hooks.cs:295-307 CreatePreCommitHookScript appends only ` protect --source "$repo_root"` plus scan options; no `--staged`. RunProtect (Program.CompatShims.cs:127-174) only sets staged when the user passes `--staged`, which the hook does not. GitSource.cs:67-77 gates `--staged` solely on options.Staged. Sibling gitleaks .pre-commit-hooks.yaml entry uses `--staged`.


### [MAJOR] `src/Picket.Tui/PicketTuiProcessFileLauncher.cs:85` (verifier severity: major)

The TUI 'open file' fallback launches the finding's file path with UseShellExecute=true, which on Windows executes executable file types (.exe/.bat/.cmd/.ps1) taken from a potentially untrusted report.


*Failure scenario:* User loads a report describing an untrusted repository (or runs picket-tui with cwd inside one) that has a finding whose Path is `evil.exe` (an attacker can plant a file containing a token-shaped string so it appears as a finding). User presses the open-file key on that finding. RequestOpenFocusedFindingFile (PicketTuiState.cs:682) queues row.Path, and TryOpenPendingFile (PicketTuiState.cs:725) calls the launcher. When no PICKET_EDITOR/VISUAL/EDITOR is set and `code` is not on PATH, CreateStartInfo (lines 85-88) returns `new ProcessStartInfo(path){ UseShellExecute = true }`, and Process.Start ShellExecutes the resolved absolute path -> Windows runs the planted executable instead of opening it in an editor. The fallback should restrict to a known editor or refuse to shell-execute executable extensions.


*Evidence:* PicketTuiProcessFileLauncher.cs:69-89 CreateStartInfo falls through to UseShellExecute=true on the raw resolved path when no configured editor and no `code`. TryResolveLocalFile (105-143) only checks File.Exists, not extension/trust. Path originates from ReportFindingSummary.Path via PicketTuiState.cs:682-686 -> 717-725.


### [MINOR] `src/Picket.Tui/PicketTuiProcessScanExecutor.cs:142` (verifier severity: major)

ResolvePicketPath falls back to a cwd-derived dev project (`dotnet run --project <repo>/src/Picket.Cli`) or a bare `picket.exe` name, which permits binary/project planting from an untrusted current directory when picket is not co-located with picket-tui.


*Failure scenario:* If picket.exe is not beside picket-tui (broken install or dev run) and the user launches the scan workspace with cwd inside an attacker-crafted repo that contains `src/Picket.Cli/Picket.Cli.csproj`, FindDevelopmentPicketProject walks up from Directory.GetCurrentDirectory() and returns that path, so the executor runs `dotnet run --project <attacker>/src/Picket.Cli/Picket.Cli.csproj`, executing attacker-controlled MSBuild/csproj targets. The bare-name fallback (`picket.exe`) similarly lets Windows CreateProcess search cwd for a planted picket.exe. In a correct release archive picket.exe is always staged beside picket-tui so besideTui short-circuits this, making the risk dev/misconfiguration-only, but the cwd-relative resolution should be removed or restricted.


*Evidence:* PicketTuiProcessScanExecutor.cs:132-168: besideTui check first, then FindDevelopmentPicketProject(Directory.GetCurrentDirectory()) yielding `dotnet run --project ...`, then bare `executableName` fallback. RELEASE.md states picket and picket-tui ship in the same RID archive, so the fallback is normally dead.


## distribution-channels

**Readiness:** The distribution channels are unusually well-engineered for a 0.1.0: the GitHub Action builds from source at the action ref (no 404/unchecksummed-download risk), both CI wrappers default to full redaction, secret-hash-only caching, opt-in SARIF upload/live verification, and loud failure on scanner crashes; the release pipeline stamps every channel artifact from the tag with SHA-256 sidecars, attestations, and a VSIX validator; generated Homebrew/Scoop/WinGet manifests embed correct URLs and hashes for artifacts the pipeline actually produces; docs input tables match action.yml and task.json exactly. The release-blocking themes are (1) the bundled libzstd native library being dropped by the MSI and the generated Homebrew formula, which ships those two channels with zstandard scanning broken, and (2) the Azure DevOps Marketplace already holding private version 0.1.3 while the product is 0.1.0, so the first public tag cannot promote the extension unless it is >= v0.1.4 (and the manifest still lacks the Public gallery flag, which docs say must be added before the stable release is built). Fix the libzstd packaging in Picket.wxs and the Homebrew template and settle the first-tag version before cutting any public release; the remaining items are polish.


### [MAJOR] `packaging/msi/Picket.wxs:26` (verifier severity: major)

The MSI installs only picket.exe, picket-tui.exe, and LICENSE, omitting the bundled libzstd.dll (and THIRD-PARTY-NOTICES.txt) that ships in the Windows release ZIP, so MSI-installed picket cannot decompress any zstandard content.


*Failure scenario:* User installs picket via the released MSI, then runs `picket scan file.zst` or scans a docker/OCI archive with zstd-compressed layers (docs/CONTAINERS.md:19) -> DllNotFoundException for libzstd at decompression time; the same binary from the ZIP, Scoop, or WinGet works, making the MSI channel look uniquely broken. Separately, if libzstd.dll is added, shipping it without THIRD-PARTY-NOTICES.txt violates the BSD notice obligation.


*Evidence:* Picket.wxs lines 26-53 declare exactly three File components (picket.exe, picket-tui.exe, LICENSE). The MSI payload is the extracted win ZIP (release.yml:530-555), which contains libzstd.dll because ZstdNet 1.5.7 ships runtimes/win-x64|win-arm64/native/libzstd.dll (Picket.Sources.csproj:14 IncludeAssets="native") and release.yml:235 copies the whole publish dir into the archive. src/Picket.Sources/ZstandardNativeMethods.cs:11 declares LibraryImport("libzstd") with no custom DllImportResolver anywhere in src/, so resolution depends on the DLL sitting beside the exe; Windows has no system libzstd.dll. THIRD-PARTY-NOTICES.txt (BSD-3-Clause zstd notice, packed per Picket.Cli.csproj:40 and required per docs/RELEASE.md:49) is also dropped.


### [MAJOR] `scripts/Generate-PackageManagerManifests.cs:344` (verifier severity: major)

The generated Homebrew formula installs only the picket and picket-tui executables from the release tarball, discarding the bundled libzstd.dylib/libzstd.so, so brew-installed picket loses zstandard decompression on macOS and Linux.


*Failure scenario:* `brew install` from the generated formula, then `picket scan repo/` on a repo containing .zst files or `picket scan --docker-archive image.tar` with zstd layers -> DllNotFoundException; the formula's own `test do` block passes, so a tap CI run would not catch it. Fix: install the payload via libexec with exec wrappers, or bin.install the native library beside the executables.


*Evidence:* WriteHomebrewFormula emits `bin.install "picket"` and `bin.install "picket-tui"` (lines 344-345) and a test that only runs `picket version` (line 349), which never touches zstd. The osx/linux tarballs contain libzstd (ZstdNet 1.5.7 ships runtimes/osx-arm64|osx-x64/native/libzstd.dylib and linux natives; release.yml:235 archives the entire publish output; Dockerfile:44 proves the library lands in the publish root). LibraryImport("libzstd") (src/Picket.Sources/ZstandardNativeMethods.cs:11) probes AppContext.BaseDirectory first, then system paths; macOS ships no public libzstd.dylib and typical Linux installs only have libzstd.so.1 without the dev symlink, so nothing resolves once the library is left behind in Homebrew's temp staging.


### [MAJOR] `azure-devops/vss-extension.json:5` (verifier severity: major)

Extension version 0.1.3 is already published privately to the Azure DevOps Marketplace while the product is at 0.1.0, and no gate checks tag-vs-Marketplace monotonicity, so a first public release tagged v0.1.0 through v0.1.3 will fail (or be rejected) at the tfx publish step.


*Failure scenario:* Maintainer tags v0.1.0 (the declared product version): release workflow builds, checksums, and attests picket-v0.1.0-azure-devops.vsix successfully; marketplace-release.yml promotion then fails at tfx publish because 0.1.0 <= 0.1.3. Also the packaged CHANGELOG.md describes versions (0.1.1-0.1.3) above the published extension version. First stable tag must be >= v0.1.4 for the Azure channel, silently decoupling extension versioning from the v0.1.0 product plan.


*Evidence:* vss-extension.json:5 declares 0.1.3 and azure-devops/CHANGELOG.md documents shipped 0.1.1-0.1.3 versions; docs/MARKETPLACES.md:100 confirms 'the currently private extension' is shared with the willibrandon test org, i.e. these versions exist on the Marketplace. Directory.Build.props:14 sets VersionPrefix 0.1.0. Release automation stamps the VSIX from the tag (release.yml:635 `--override {version: <tag>}`), and scripts/Validate-MarketplaceRelease.cs:240-244 requires manifest version == tag version, but nothing anywhere compares the tag against the highest already-published Marketplace version — the Marketplace rejects non-increasing extension versions at `tfx extension publish`.


### [MINOR] `Dockerfile:5` (verifier severity: minor)

Build and runtime base images are pinned only to the floating tag 10.0-noble, not to a digest or exact patch tag, unlike the digest-pinned images used elsewhere in the release pipeline.


*Failure scenario:* The GHCR release image content changes between rebuilds of the same tag when MCR updates 10.0-noble, so the published multi-arch image is not reproducible from the tagged source, and a compromised or regressed base tag flows into a release without any pin to detect it.


*Evidence:* Dockerfile:3-5 uses `ARG DOTNET_VERSION=10.0` and `FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION}-noble`; line 27 same for runtime-deps. By contrast release.yml:198 uses runtime-deps@sha256:297e573... and docs/RELEASE.md:68 touts digest-pinned Alpine images for musl publishes.


### [MINOR] `azure-devops/tasks/PicketScanV1/index.js:344` (verifier severity: minor)

With failOn=errors, a partial-scan error that still emitted findings passes the task (and the GitHub action behaves the same), because exit code 1 with findings>0 is always classified as findings rather than error.


*Failure scenario:* A scan that errors partway (e.g. timeout after N files) but reported at least one finding exits 1 with findings>0; under failOn=errors the CI job succeeds even though the scan was incomplete, so a partially-scanned repo is reported green in the mode users pick precisely to catch scanner errors. Ambiguity is inherited from Gitleaks exit codes, but the docs (azure-devops/README.md:25 'Scanner execution errors still fail the task') overpromise for this case.


*Evidence:* docs/DESIGN.md:451-453 documents exit code 1 as both 'leaks found' and 'scan error or partial scan'. index.js:335-349 (`shouldFail` errors arm: `exitCode !== 0 && findings === 0`; `isScannerError` same condition) and .github/actions/run-picket.cs:428-435 (`"errors" when scannerExitCode != 0 && findingCount == 0`) both treat nonzero-exit-with-findings as a pure findings outcome.


## licensing-provenance

**Readiness:** Not release-ready on this dimension: two blockers stand. The embedded rule corpus is a verbatim 3,220-line copy of Gitleaks' MIT-licensed default config with zero attribution anywhere in the repo or artifacts, and THIRD-PARTY-NOTICES.txt covers only the zstd pair while omitting every other statically linked MIT dependency (Hex1b, SharpYaml, System.CommandLine, System.IO.FileSystem.AccessControl, .NET runtime). Both are cheap to fix — extend THIRD-PARTY-NOTICES.txt (and the convention test at tests/Picket.Tests/RepositoryConventionTests.cs:542-544), then propagate the file into the MSI and the non-Cli NuGet packages. Provenance hygiene is otherwise strong: the embedded config's pinned commit matches docs/UPSTREAM.md exactly, ZstdNet/ZstdSharp dual usage is intentional and documented, Docker and release archives already carry the notices file, the Azure DevOps VSIX bundles no third-party node modules, and no incompatible inbound license headers exist in src/.


### [BLOCKER] `src/Picket.Compat/EmbeddedGitleaksConfig.cs:9` (verifier severity: blocker,blocker,blocker)

The 3,220-line verbatim copy of Gitleaks' MIT-licensed default gitleaks.toml embedded in every shipped binary and in the packable Picket.Compat NuGet library carries no Gitleaks copyright notice anywhere in the repository or its distributions.


*Failure scenario:* Any public release (binaries, Docker image, MSI, NuGet packages) redistributes a substantial portion of the Gitleaks Software without the required MIT copyright/permission notice, violating the Gitleaks license from the first tag.


*Evidence:* EmbeddedGitleaksConfig.cs:9-13 embeds the upstream config verbatim including its auto-generation banner; wc -l shows 3,220 lines. The sibling oracle clone's LICENSE is 'MIT License / Copyright (c) 2019 Zachary Rice'; MIT requires the copyright and permission notice in all copies or substantial portions. rg for 'Zachary Rice' and 'zricethezav' across the repo returns zero hits; THIRD-PARTY-NOTICES.txt (lines 1-67) lists only ZstdNet and Zstandard; README.md and docs/RULES.md never attribute Gitleaks's license. Picket.Compat is IsPackable=true (src/Picket.Compat/Picket.Compat.csproj:4) and docs/RULES.md:13,23 confirm both the compat default and the native picket-default config (which 'extends the embedded Gitleaks compatibility rules') ship this corpus.


### [BLOCKER] `THIRD-PARTY-NOTICES.txt:1` (verifier severity: blocker,major,blocker)

THIRD-PARTY-NOTICES.txt omits every statically linked MIT dependency with a third-party copyright holder — Hex1b, SharpYaml, System.CommandLine, System.IO.FileSystem.AccessControl, and the AOT-compiled .NET runtime — listing only ZstdNet and Zstandard.


*Failure scenario:* Every release binary, archive, container image, and NuGet package redistributes MIT-licensed code from Mitch Denny, Alexandre Mutel, and Microsoft without reproducing their copyright and permission notices, a license violation present in all v0.1.0 artifacts.


*Evidence:* Notices file contains only ZstdNet (lines 3-33) and Zstandard (lines 35-67). Shipped PackageReferences: SharpYaml + Scout.Text.Regex (src/Picket.Engine/Picket.Engine.csproj:17-18), Scout.IO.Ignore (src/Picket.Sources/Picket.Sources.csproj:13), System.CommandLine (src/Picket.Cli/Picket.Cli.csproj:41, src/Picket.Tui.Cli/Picket.Tui.Cli.csproj:42), System.IO.FileSystem.AccessControl (src/Picket.Security/Picket.Security.csproj:16), Hex1b (src/Picket.Tui/Picket.Tui.csproj:25). Cached nuspecs confirm all are MIT with distinct holders: Hex1b 'Copyright (c) 2024 Mitch Denny', SharpYaml 'Alexandre Mutel', System.CommandLine and System.IO.FileSystem.AccessControl '© Microsoft Corporation'. Native AOT publish (PublishAot=true) compiles these plus the MIT .NET runtime into picket/picket-tui executables. tests/Picket.Tests/RepositoryConventionTests.cs:542-544 asserts only ZstdNet/Zstandard/Meta entries, locking in the gap. (Scout.* shares the repository author so self-attribution risk is low, but entries should still be added for completeness.) Hex1b's own package THIRD-PARTY-NOTICES.txt (OFL font, SkiaSharp, Svg.Skia) should also be reviewed for propagation into picket-tui distributions.


### [MAJOR] `packaging/msi/Picket.wxs:33` (verifier severity: major)

The MSI installs picket.exe, picket-tui.exe, and LICENSE but not THIRD-PARTY-NOTICES.txt, so even the existing ZstdNet/Zstandard notices never reach MSI users; it also omits the libzstd.dll native runtime asset that the archives ship.


*Failure scenario:* A user who installs via MSI receives statically linked third-party code with no third-party notices at all; additionally, .zst archive scanning fails from an MSI install because libzstd.dll is not installed.


*Evidence:* Picket.wxs:26-53 declares exactly four components: PicketExe, PicketTuiExe, PicketLicense (LICENSE only), and PicketPath — no notices file and no libzstd native library, even though the MSI payload is expanded from the Windows release archive which contains both (.github/workflows/release.yml:531-548 verifies only picket.exe, picket-tui.exe, LICENSE). docs/RELEASE.md:49 lists archives, tool packages, and the container image as carrying THIRD-PARTY-NOTICES.txt but is silent on the MSI.


### [MINOR] `Directory.Packages.props:9` (verifier severity: minor)

Scout.IO.Globbing 0.4.7 is centrally pinned and documented as a shipped Picket dependency, but no project references it and it is not even present in the local NuGet cache.


*Failure scenario:* Release documentation (release-profiles.md) tells users the shipped binaries contain Scout.IO.Globbing 0.4.7 when they do not, and either the docs or an intended dependency is wrong at tag time.


*Evidence:* Directory.Packages.props:9 pins it; rg for PackageReference across src/, tests/, benchmarks/ shows zero references; ~/.nuget/packages/scout.io.globbing does not exist. AGENTS.md:37, docs/DESIGN.md:11/85/99-101, and docs-site/src/content/docs/reference/release-profiles.md:65 all describe it as a used dependency at 0.4.7.


**Refuted during verification:** src/Picket.Tui.Cli/Picket.Tui.Cli.csproj:39 — Only the Picket.Cli project packs THIRD-PARTY-NOTICES.txt into its NuGet packages; the picket-tui tool package and the p
