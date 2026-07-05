# Upstream Pins

Picket compatibility work is pinned to local reference clones. Upgrade these
pins deliberately and update oracle fixtures in the same change.

| Project | Local path | Version | Commit |
|---|---|---:|---|
| Gitleaks | `D:\SRC\gitleaks` | `v8.30.0-23-g4c232b5` | `4c232b5014f7618360bd992b4c489cb055881c6b` |
| Scout | `D:\SRC\scout` | `v0.4.1` | `706e5597e1ff65da239d61ba6288e92b8129b284` |
| TruffleHog | `D:\SRC\trufflehog` | `v3.95.8-1-gf2cd191b9` | `f2cd191b97098913a07522227d2b5e40e57252f4` |
| Nosey Parker | `D:\SRC\noseyparker` | `v0.24.0-31-g2e6e7f36` | `2e6e7f36ce36619852532bbe698d8cb7a26d2da7` |
| Kingfisher | `D:\SRC\kingfisher` | `v1.105.0` | `78904df5ea7354a7dc3700e3c41a124524d23083` |
| .NET Runtime | `D:\SRC\runtime` | `fe5e47348f8` | `fe5e47348f86013bbe8f3041e56f5208cd632e53` |

## Gitleaks Compatibility

The embedded strict-compatibility default config in
`src/Picket.Compat/EmbeddedGitleaksConfig.cs` is generated from:

```text
D:\SRC\gitleaks\config\gitleaks.toml
```

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
