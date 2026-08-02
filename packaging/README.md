# Packaging

Release packaging is generated from built release artifacts, not maintained by hand.

`scripts/Generate-PackageManagerManifests.cs` reads `checksums.txt` from a release asset directory and writes:

- `homebrew/picket.rb`
- `scoop/picket.json`
- `winget/willibrandon.picket/<version>/willibrandon.picket.yaml`
- `winget/willibrandon.picket/<version>/willibrandon.picket.locale.en-US.yaml`
- `winget/willibrandon.picket/<version>/willibrandon.picket.installer.yaml`

Run it locally after release archives and checksums exist:

```powershell
dotnet run --file ./scripts/Generate-PackageManagerManifests.cs -- -ReleaseTag v0.2.8 -ChecksumsPath dist/checksums.txt -OutputDirectory artifacts/package-managers -Clean
```

The release workflow packages those files into `picket-<tag>-package-manager-manifests.zip`. Stable releases validate and commit the Homebrew and Scoop files to their package repositories and submit the WinGet set through a pull request. Prereleases publish the bundle without changing package repositories.

The WinGet manifests use the Windows ZIP portable installer path so `picket.exe` and `picket-tui.exe` remain the same Native AOT executables shipped in the Windows release archives.

Windows MSI installers are built for stable releases from the same `win-x64` and `win-arm64` release ZIP payloads with `packaging/msi/Picket.wxs`. The installer places `picket.exe`, `picket-tui.exe`, and `LICENSE` under `Program Files\Picket`, adds that folder to the machine PATH, and uses the same release version, SHA-256 sidecars, and artifact attestation flow as the other release assets. Prerelease tags skip MSI artifacts because Windows Installer `ProductVersion` does not support SemVer prerelease labels.
