# Picket Azure DevOps Extension

This folder contains the Azure DevOps Marketplace packaging inputs for the `PicketScan@1` task.

The task is a distribution wrapper around the Picket CLI. It builds a `picket scan` command from validated task inputs, writes reports under a task-owned report directory, emits Azure DevOps output variables, and publishes selected report files as build artifacts. Scanner behavior stays in the CLI.

The task does not acquire credentials by value. Remote Azure DevOps enumeration passes token environment variable names to Picket so token values do not appear in command lines, logs, summaries, or task metadata.

Before publishing the extension, validate the VSIX package from this folder with `tfx extension create --manifest-globs vss-extension.json --output-path ../artifacts/azure-devops --rev-version false` and run task smoke tests on Windows, Linux, and macOS hosted agents.
