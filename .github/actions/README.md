# GitHub Action Helper

`run-picket.cs` is a .NET file-based app used by the local composite action in
`action.yml`. The action builds it first, then runs it with `--no-build`:

```powershell
dotnet build "$env:GITHUB_ACTION_PATH/.github/actions/run-picket.cs" --nologo --verbosity quiet
dotnet run --file "$env:GITHUB_ACTION_PATH/.github/actions/run-picket.cs" --no-build
```

The build-first pattern avoids file-based app cache contention on runners and
matches the repository script guidance in `scripts/README.md`.

Keep the top-level launcher thin. Put behavior in documented methods on the app
class so XML documentation and repository convention tests can cover helper
members. The local `Directory.Build.props` isolates action-helper settings from
package metadata and project settings used by shipped Picket projects.

The helper writes GitHub outputs through `GITHUB_OUTPUT`, optional job summary
content through `GITHUB_STEP_SUMMARY`, and safe workflow annotations from the
redacted JSONL report. It must not print raw `secret`, `match`, or `line`
payloads from findings.
