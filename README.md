# Picket

Picket is a MIT-licensed secrets scanner for .NET. It provides a Gitleaks-compatible command surface, a Picket-native scanning surface, Native AOT release binaries, dotnet tool packages, and embeddable AOT-safe libraries for rules, scanning, reporting, and endpoint safety.

## Tools

Install the command-line scanner:

```powershell
dotnet tool install --global Picket
```

Install the interactive terminal report triage companion:

```powershell
dotnet tool install --global Picket.Tui.Cli
```

The Native AOT release archives remain the recommended zero-runtime CLI distribution. The dotnet tool packages are framework-dependent NuGet tool packages for environments that already manage the .NET SDK or runtime.

## Libraries

Picket publishes these embeddable packages:

- `Picket.Rules`
- `Picket.Engine`
- `Picket.Report`
- `Picket.Security`

The public library surface is intentionally narrow and AOT-safe. See `docs/EMBEDDING.md` for examples and the package roles.

## Documentation

Project documentation is published at:

```text
https://willibrandon.github.io/picket/
```
