# GitHub Action

The [Picket Secret Scanner](https://github.com/marketplace/actions/picket-secret-scanner) Action scans checked-out repositories, Docker archives, OCI archives, and registry images, writes native SARIF and JSONL reports, and can upload SARIF to GitHub code scanning. Its public inputs, outputs, permissions, source-selection rules, and failure modes are documented in [`docs/ACTION.md`](../../docs/ACTION.md).

Azure Pipelines users can install [Picket from the Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=willibrandon.picket) and run the `PicketScan@1` task documented in [`docs/AZURE_DEVOPS.md`](../../docs/AZURE_DEVOPS.md).

## Implementation

`run-picket.cs` is a .NET file-based app used by the local composite action in
`action.yml`. The action builds it first, then runs it with `--no-build`:

```powershell
dotnet build "$env:GITHUB_ACTION_PATH/.github/actions/run-picket.cs" --nologo --verbosity quiet
dotnet run --file "$env:GITHUB_ACTION_PATH/.github/actions/run-picket.cs" --no-build
```

The build-first pattern avoids file-based app cache contention on runners and
matches the repository script guidance in `scripts/README.md`.

Keep the top-level launcher thin. Put reusable behavior in documented helper
types such as `PicketActionFailurePolicy.cs` and `PicketActionScanSource.cs` and include them with `#:include`.
The test project compiles pure helpers directly so action policy is exercised by
the same tests as the scanner. The local `Directory.Build.props` isolates
action-helper settings from package metadata and project settings used by
shipped Picket projects.

The helper writes GitHub outputs through `GITHUB_OUTPUT`, optional job summary
content through `GITHUB_STEP_SUMMARY`, and safe workflow annotations from the
redacted JSONL report. It must not print raw `secret`, `match`, or `line`
payloads from findings.
