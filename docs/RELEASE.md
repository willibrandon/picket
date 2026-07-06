# Release Profiles

Picket publishes the CLI with named Native AOT profiles. Always pass an explicit runtime identifier with `-r` so the artifact is tied to the target platform.

```powershell
dotnet publish src/Picket.Cli/Picket.Cli.csproj -p:PublishProfile=release-speed -r win-x64
dotnet publish src/Picket.Cli/Picket.Cli.csproj -p:PublishProfile=release-minsize -r linux-x64
dotnet publish src/Picket.Cli/Picket.Cli.csproj -p:PublishProfile=release-diagnostics -r osx-arm64
```

## Profiles

| Profile | Purpose | Key settings |
| --- | --- | --- |
| `release-speed` | Default public CLI artifact. | Native AOT, self-contained, single-file publish, speed optimization, stripped symbols, diagnostics reduced. |
| `release-minsize` | Smallest supported artifact for package managers, containers, and constrained runners. | Native AOT, size optimization, stripped symbols, stack traces off, EventSource and metrics off, resource-key exception messages. |
| `release-diagnostics` | Support artifact for bug reports and performance investigations. | Native AOT, speed optimization, symbols kept, debugger support, EventSource, metrics, stack traces, and HTTP activity propagation enabled. |

All profiles keep unsafe BinaryFormatter serialization, UTF-7, metadata update support, XML resolver networking by default, and HTTP/3 disabled. These switches are explicit so size and diagnostics tradeoffs are visible in review.

`release-minsize` must not change scanner findings, rule behavior, reports, validation states, or exit-code classification. It may reduce diagnostic richness only.

## NuGet Package Validation

Every CI run packs the public embeddable packages after build and test:

- `Picket.Rules`
- `Picket.Engine`
- `Picket.Report`
- `Picket.Security`

The CI pack gate runs on Windows, Linux, and macOS so package metadata, embedded readmes, symbol packages, project-reference dependencies, and cross-platform MSBuild paths are validated before release automation consumes the same projects.

## Native AOT Publish Validation

Every CI run also publishes the CLI with `release-speed` for the runner's native RID:

- `linux-x64` on `ubuntu-latest`
- `win-x64` on `windows-latest`
- `osx-arm64` on `macos-26`

This is the analyzer gate for Native AOT, trimming, single-file compatibility, and RID-specific publish behavior. A normal `dotnet build` is not enough evidence that the shipped executable can be produced.

## GitHub Action Smoke Validation

CI runs the local composite action on `ubuntu-latest` against the sanitized GitHub secret-scanning fixture with cache, annotations, and SARIF upload disabled. The smoke step asserts that the action exits successfully, reports zero findings for the placeholder fixture, and writes both `picket.sarif` and `picket.jsonl`.

## Runtime Identifiers

Use the target RID in the publish command. Common release RIDs are:

| Platform | RID |
| --- | --- |
| Windows x64 | `win-x64` |
| Windows Arm64 | `win-arm64` |
| Linux x64 | `linux-x64` |
| Linux Arm64 | `linux-arm64` |
| macOS x64 | `osx-x64` |
| macOS Arm64 | `osx-arm64` |

Release automation should publish, sign, checksum, and archive each RID separately.
