# Scripts

Picket repository utilities are .NET file-based apps. They require the .NET 10
SDK selected by the repository `global.json`.

The implementation follows the Microsoft file-based app guidance:

https://learn.microsoft.com/en-us/dotnet/core/sdk/file-based-apps

Run a utility with:

```powershell
dotnet run --file ./scripts/Capture-UpstreamPins.cs -- -AllowMissing
```

For automation or repeated invocations, build first and run without rebuilding:

```powershell
dotnet build ./scripts/Capture-UpstreamPins.cs --nologo --verbosity quiet
dotnet run --file ./scripts/Capture-UpstreamPins.cs --no-build -- -AllowMissing
```

The build-first pattern avoids file-based app cache contention when multiple
processes might run the same utility at the same time.

If the SDK cache gets stale or contested, clear all file-based app cache output:

```powershell
dotnet clean file-based-apps
```

To force a clean build for one utility:

```powershell
dotnet clean ./scripts/Capture-UpstreamPins.cs
dotnet build ./scripts/Capture-UpstreamPins.cs
```

The executable utilities have a Unix shebang:

```text
#!/usr/bin/env -S dotnet --
```

The repository uses LF line endings through `.gitattributes`, which is required
for direct Unix execution. On Unix-like systems, executable files can also be run
directly after checkout when the executable bit is present:

```bash
./scripts/Capture-UpstreamPins.cs -AllowMissing
```

Keep file-based apps under `scripts/`, outside project directories. The local
`scripts/Directory.Build.props` intentionally isolates utility app settings from
package metadata and project settings used by the shipped Picket projects.

Repository tests build every executable utility app with `dotnet build` and run
stable fake-input coverage for the GitHub oracle capture and comparison apps.
When adding a utility, keep its top-level launcher thin and put behavior in a
documented app class so XML documentation and convention tests cover helpers.

Current utilities:

| App | Purpose |
| --- | --- |
| `Build-ZstandardMusl.cs` | Build the pinned decompression-only zstandard runtime used by musl release artifacts. |
| `Capture-UpstreamPins.cs` | Refresh or print upstream reference clone pins. |
| `Capture-GitleaksOracle.cs` | Capture pinned Gitleaks oracle reports. |
| `Capture-CompatibilityOracle.cs` | Capture side-by-side Gitleaks/Picket oracle bundles. |
| `Promote-CompatibilityOracle.cs` | Normalize reviewed oracle captures into committed fixtures. |
| `Capture-GitHubSecretScanningOracle.cs` | Capture sanitized hosted GitHub secret-scanning alert metadata. |
| `Compare-GitHubSecretScanningOracle.cs` | Compare hosted alert metadata to a Picket JSONL report. |
| `Generate-PackageManagerManifests.cs` | Generate Homebrew, Scoop, and WinGet manifests from release checksums. |

Do not store secrets in utility arguments, logs, or committed fixtures. Oracle
capture output remains under ignored `artifacts/` paths until it has been
reviewed and normalized.
