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

The release archives are direct Native AOT executable downloads. The dotnet tool packages are RID-specific Native AOT NuGet tool packages selected by the .NET CLI during install for Windows, Linux, and macOS x64/Arm64.

Scan staged, unstaged, and untracked non-ignored Git changes together:

```powershell
picket scan --git-changes . --report-format jsonl --redact=100
```

Scan a Hugging Face model, dataset, Space, or bucket with a read-only token stored in an environment variable:

```powershell
picket scan --huggingface-model owner/model --huggingface-token-env HF_TOKEN --report-format jsonl --redact=100
```

## CI Integrations

Use the [Picket Secret Scanner](https://github.com/marketplace/actions/picket-secret-scanner) GitHub Action:

```yaml
- uses: actions/checkout@v7.0.1
- uses: willibrandon/picket@v0
  with:
    upload-sarif: true
```

Azure Pipelines can install [Picket from the Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=willibrandon.picket) and use the `PicketScan@1` task:

```yaml
- task: PicketScan@1
  inputs:
    target: "$(Build.SourcesDirectory)"
    failOn: "findings"
```

See [GitHub Action](https://github.com/willibrandon/picket/blob/main/docs/ACTION.md) and [Azure DevOps](https://github.com/willibrandon/picket/blob/main/docs/AZURE_DEVOPS.md) for permissions, inputs, reports, and failure behavior.

## Libraries

Picket publishes these embeddable packages:

- `Picket.Rules`
- `Picket.Engine`
- `Picket.Compat`
- `Picket.Report`
- `Picket.Security`

The public library surface is intentionally narrow and AOT-safe. See `docs/EMBEDDING.md` for examples and the package roles.

## Documentation

Project documentation is published at:

```text
https://willibrandon.github.io/picket/
```
