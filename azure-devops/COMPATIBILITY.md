# Compatibility

The `PicketScan@1` task requires Azure Pipelines agent `3.220.0` or newer and uses the agent's Node 20 task runner.

| Agent operating system | Architectures | Picket executable |
| --- | --- | --- |
| Windows | x64, ARM64 | `win-x64` or `win-arm64` |
| Linux using glibc | x64, ARM64 | `linux-x64` or `linux-arm64` |
| Linux using musl | x64, ARM64 | `linux-musl-x64` or `linux-musl-arm64` |
| macOS | x64, ARM64 | `osx-x64` or `osx-arm64` |

Microsoft-hosted Windows, Linux, and macOS agents are supported. Self-hosted agents are supported when a matching Picket executable is available through the `picketPath` input or `PATH`.

Azure DevOps Services is supported. Azure DevOps Server is supported when its connected agent meets the minimum version and Node 20 runner requirements. Features backed by service APIs depend on the selected server version exposing the corresponding REST API. Workspace scans do not depend on remote source APIs.

The task does not download or select a Picket executable. Release archives, RID-specific .NET tool packages, containers, and installation guidance are published with Picket releases.
