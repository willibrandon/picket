# Picket for Azure Pipelines

Run Picket secret scanning in Azure Pipelines with the `PicketScan@1` task.

The task wraps the Picket CLI instead of reimplementing scanner behavior. It builds a `picket scan` command from validated inputs, writes reports to a task-owned report directory, emits Azure DevOps output variables, and can publish SARIF, JSONL, and HTML reports as build artifacts.

Credential handling stays explicit. The task passes remote Azure DevOps credentials by environment variable name, so token values do not appear in command lines, logs, summaries, or task metadata.

## Example

```yaml
steps:
- task: PicketScan@1
  inputs:
    target: '$(Build.SourcesDirectory)'
    profile: 'picket'
    reportFormats: 'sarif,jsonl,html'
    failOn: 'findings'
    redact: '100'
```

Use `picketPath` when the executable is not named `picket` or is not available on `PATH`. Live verification and remote Azure DevOps enumeration are opt-in task inputs.
