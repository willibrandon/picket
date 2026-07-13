# Privacy

The Picket Azure Pipelines task does not collect telemetry and does not send scan data to Picket or its maintainer.

Workspace scans run locally on the pipeline agent. Remote source enumeration and live credential verification are disabled unless the pipeline explicitly enables and configures them. When enabled, Picket contacts only the selected provider endpoints under its endpoint, redirect, TLS, proxy, response-size, retry, and rate-limit controls.

Provider credentials are read from pipeline environment variables. The task passes environment variable names to Picket rather than placing credential values in command-line arguments, summaries, annotations, task metadata, or reports.

Reports can contain sensitive source context when redaction is reduced. The task defaults to full redaction and secret-hash-only cache storage. Selected reports are uploaded to the Azure Pipelines run as build artifacts; Azure DevOps retention and access policies then apply. Pipeline authors are responsible for granting artifact access only to intended users and for choosing shorter retention when reports contain sensitive metadata.

Picket cache files remain on the agent or in the pipeline cache location selected by the pipeline. Raw cache mode is an explicit trusted-environment option. Secret-hash-only mode is the default.

Security concerns can be reported through the private vulnerability reporting instructions in the Picket repository. General support is available at https://github.com/willibrandon/picket/issues.
