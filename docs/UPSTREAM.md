# Upstream Pins

Picket compatibility work is pinned to upstream reference snapshots. Upgrade
these pins deliberately and update oracle fixtures in the same change.

Do not commit machine-specific clone paths. Developers can keep reference
repositories anywhere and point Picket tooling at them with environment
variables. When an environment variable is not set, local scripts try a sibling
clone next to this repository.

## Reference Clone Discovery

| Project | Environment variable | Default sibling clone | Role |
|---|---|---|---|
| Gitleaks | `PICKET_GITLEAKS_REPO` | `../gitleaks` | Primary compatibility oracle |
| Scout | `PICKET_SCOUT_REPO` | `../scout` | Read-only API/behavior reference. Picket consumes Scout through NuGet packages only. |
| TruffleHog | `PICKET_TRUFFLEHOG_REPO` | `../trufflehog` | Verification, sources, and analyze reference |
| Nosey Parker | `PICKET_NOSEYPARKER_REPO` | `../noseyparker` | Historical datastore/rule-QA/performance reference |
| Kingfisher | `PICKET_KINGFISHER_REPO` | `../kingfisher` | Validation breadth, revocation, access-map, and reporting reference |
| .NET Runtime | `PICKET_DOTNET_RUNTIME_REPO` | `../runtime` | Native AOT/runtime implementation reference |

## Current Pins

<!-- upstream-pins:start -->
| Project | Version | Commit | Remote |
|---|---:|---|---|
| Gitleaks | `v8.30.0-23-g4c232b5` | `4c232b5014f7618360bd992b4c489cb055881c6b` | `https://github.com/gitleaks/gitleaks.git` |
| Scout | `v0.4.1` | `706e5597e1ff65da239d61ba6288e92b8129b284` | `https://github.com/willibrandon/scout.git` |
| TruffleHog | `v3.95.8-1-gf2cd191b9` | `f2cd191b97098913a07522227d2b5e40e57252f4` | `https://github.com/trufflesecurity/trufflehog.git` |
| Nosey Parker | `v0.24.0-31-g2e6e7f36` | `2e6e7f36ce36619852532bbe698d8cb7a26d2da7` | `https://github.com/praetorian-inc/noseyparker.git` |
| Kingfisher | `v1.105.0` | `78904df5ea7354a7dc3700e3c41a124524d23083` | `https://github.com/mongodb/kingfisher.git` |
| .NET Runtime | `fe5e47348f8` | `fe5e47348f86013bbe8f3041e56f5208cd632e53` | `https://github.com/dotnet/runtime` |
<!-- upstream-pins:end -->

Refresh the table from local clones with:

```powershell
pwsh ./scripts/Capture-UpstreamPins.ps1 -Update
```

Print the captured table without editing docs with:

```powershell
pwsh ./scripts/Capture-UpstreamPins.ps1
```

## Gitleaks Compatibility

The embedded strict-compatibility default config in
`src/Picket.Compat/EmbeddedGitleaksConfig.cs` is generated from:

```text
<gitleaks clone>/config/gitleaks.toml
```

Resolve `<gitleaks clone>` with `PICKET_GITLEAKS_REPO` or the sibling
`../gitleaks` fallback.

Current Gitleaks code defaults are treated as authoritative when README text and
implementation disagree. For example, `--max-decode-depth` follows the pinned
code default of `5`.

Expected oracle command shapes:

```powershell
gitleaks git --source <repo> --config <config> --report-format json --report-path <out>
gitleaks dir <path> --config <config> --report-format json --report-path <out>
gitleaks stdin --config <config> --report-format json --report-path <out>
```

Picket compatibility tests should compare normalized reports, fingerprints,
config diagnostics, exit codes, and stderr text against this pinned version.
