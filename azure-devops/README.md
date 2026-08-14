# Picket for Azure Pipelines

Install [Picket from the Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=willibrandon.picket), then run secret scanning in Azure Pipelines with the `PicketScan@1` task.

The task builds a `picket scan` command from validated workspace, Docker archive, OCI archive, registry image, or Azure DevOps source inputs, writes reports to a task-owned report directory, emits Azure DevOps output variables, and can publish SARIF, JSONL, and HTML reports as build artifacts.

Credential handling stays explicit. The task passes remote Azure DevOps credentials by environment variable name, so token values do not appear in command lines, logs, summaries, or task metadata.

Container registry authentication follows the same rule: `registryTokenEnv`, `registryUsernameEnv`, and `registryPasswordEnv` contain environment variable names, never credential values.

## Example

```yaml
steps:
- task: PicketScan@1
  inputs:
    target: '$(Build.SourcesDirectory)'
    profile: 'picket'
    rulePacks: 'picket-strict'
    ignorePath: '$(Build.SourcesDirectory)/.picketignore'
    reportFormats: 'sarif,jsonl,html'
    failOn: 'findings'
    redact: '100'
```

Use `picketPath` when the executable is not named `picket` or is not available on `PATH`. Live verification and remote Azure DevOps enumeration are opt-in task inputs.

Use `dockerArchive`, `ociArchive`, or `registryImage` to scan a container image through the task. These inputs, `target`, and remote Azure DevOps enumeration are mutually exclusive. Omitting all source inputs retains the `$(Build.SourcesDirectory)` workspace default.

When `verify` is enabled, `liveMaxRequests` defaults to 100 outbound provider requests per scan and `liveMaxRequestsPerProvider` defaults to 25 for any one provider. Retries consume the budgets; cache hits do not.

`ignorePath` accepts complete `picket:v1:<sha256>` fingerprints copied from native reports and `sha256:<content-sha256>` content-hash entries.

Supplying `config` replaces Picket's embedded native default rule set. `[extend] useDefault = true` restores the Gitleaks default rules, not Picket's complete native default profile.

`failOn: never` suppresses finding-based failure only. Scanner execution errors still fail the task.

## Compatibility

The task requires Azure Pipelines agent `3.220.0` or newer and a Picket executable compatible with the agent operating system and architecture. Microsoft-hosted Windows, Linux, and macOS agents are supported. Self-hosted agents and Azure DevOps Server are supported when they meet the same agent and executable requirements.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the platform matrix and [the Picket Azure DevOps documentation](https://willibrandon.github.io/picket/generated/azure-devops/) for all inputs and source modes.

## Privacy

Picket does not collect telemetry. Local scans do not contact Picket services. Remote source enumeration and live verification run only when their inputs are explicitly enabled. Reports are redacted by default and are uploaded to the pipeline only for selected report formats.

See [PRIVACY.md](PRIVACY.md) for credential, report, cache, and network handling details. Support is available through the [Picket issue tracker](https://github.com/willibrandon/picket/issues).
