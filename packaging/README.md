# Packaging

Release packaging is generated from built release artifacts, not maintained by hand.

`scripts/Generate-PackageManagerManifests.cs` reads `checksums.txt` from a release asset directory and writes:

- `homebrew/picket.rb`
- `scoop/picket.json`
- `winget/Willibrandon.Picket/<version>/Willibrandon.Picket.yaml`
- `winget/Willibrandon.Picket/<version>/Willibrandon.Picket.locale.en-US.yaml`
- `winget/Willibrandon.Picket/<version>/Willibrandon.Picket.installer.yaml`

Run it locally after release archives and checksums exist:

```powershell
dotnet run --file ./scripts/Generate-PackageManagerManifests.cs -- -ReleaseTag v0.4.2 -ChecksumsPath dist/checksums.txt -OutputDirectory artifacts/package-managers -Clean
```

The release workflow packages those files into `picket-<tag>-package-manager-manifests.zip`. Publish or submit the generated files from that bundle to the appropriate package-manager repository after validating the target repository policy.

The WinGet manifests use the Windows ZIP portable installer path so `picket.exe` and `picket-tui.exe` remain the same Native AOT executables shipped in the Windows release archives. MSI packaging is a separate Windows installer track and should use the same release binaries, version, checksum, and signing provenance when it is added.
