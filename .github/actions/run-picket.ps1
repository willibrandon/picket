Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ActionInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Default = ''
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }

    return $value
}

function Resolve-WorkspacePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    $workspace = [Environment]::GetEnvironmentVariable('GITHUB_WORKSPACE')
    if ([string]::IsNullOrWhiteSpace($workspace)) {
        $workspace = (Get-Location).Path
    }

    return [IO.Path]::GetFullPath([IO.Path]::Combine($workspace, $Path))
}

function Add-ActionOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $outputPath = [Environment]::GetEnvironmentVariable('GITHUB_OUTPUT')
    if ([string]::IsNullOrWhiteSpace($outputPath)) {
        return
    }

    Add-Content -LiteralPath $outputPath -Value "$Name=$Value"
}

function Add-StepSummary {
    param(
        [AllowEmptyString()]
        [string[]]$Lines
    )

    $summaryPath = [Environment]::GetEnvironmentVariable('GITHUB_STEP_SUMMARY')
    if ([string]::IsNullOrWhiteSpace($summaryPath)) {
        return
    }

    Add-Content -LiteralPath $summaryPath -Value $Lines
}

$actionPath = [Environment]::GetEnvironmentVariable('GITHUB_ACTION_PATH')
if ([string]::IsNullOrWhiteSpace($actionPath)) {
    $actionPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

$scanPath = Resolve-WorkspacePath (Get-ActionInput -Name 'PICKET_PATH' -Default '.')
$configPath = Get-ActionInput -Name 'PICKET_CONFIG_PATH'
$baselinePath = Get-ActionInput -Name 'PICKET_BASELINE_PATH'
$cacheEnabled = Get-ActionInput -Name 'PICKET_CACHE_ENABLED' -Default 'true'
$cachePath = Get-ActionInput -Name 'PICKET_CACHE_PATH' -Default '.picket/cache'
$reportDirectory = Resolve-WorkspacePath (Get-ActionInput -Name 'PICKET_REPORT_DIRECTORY' -Default 'picket-results')
$failOn = (Get-ActionInput -Name 'PICKET_FAIL_ON' -Default 'findings').Trim().ToLowerInvariant()
$redact = Get-ActionInput -Name 'PICKET_REDACT' -Default '100'
$maxTargetMegabytes = Get-ActionInput -Name 'PICKET_MAX_TARGET_MEGABYTES'

if ($failOn -notin @('findings', 'errors', 'never')) {
    Write-Host '::error title=Invalid fail-on::fail-on must be findings, errors, or never.'
    exit 1
}

New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null

$sarifPath = Join-Path $reportDirectory 'picket.sarif'
$jsonlPath = Join-Path $reportDirectory 'picket.jsonl'
$projectPath = Join-Path $actionPath 'src/Picket.Cli/Picket.Cli.csproj'
$arguments = @(
    'run',
    '--project',
    $projectPath,
    '--configuration',
    'Release',
    '--no-restore',
    '--',
    'scan',
    $scanPath,
    '-r',
    $sarifPath,
    '-r',
    $jsonlPath,
    "--redact=$redact"
)

if (![string]::IsNullOrWhiteSpace($configPath)) {
    $arguments += @('-c', (Resolve-WorkspacePath $configPath))
}

if (![string]::IsNullOrWhiteSpace($baselinePath)) {
    $arguments += @('-b', (Resolve-WorkspacePath $baselinePath))
}

if ($cacheEnabled.Equals('true', [StringComparison]::OrdinalIgnoreCase)) {
    $resolvedCachePath = Resolve-WorkspacePath $cachePath
    New-Item -ItemType Directory -Force -Path $resolvedCachePath | Out-Null
    $arguments += @('--cache-dir', $resolvedCachePath)
}

if (![string]::IsNullOrWhiteSpace($maxTargetMegabytes)) {
    $arguments += @('--max-target-megabytes', $maxTargetMegabytes)
}

$scannerExitCode = 0
try {
    & dotnet @arguments
    $scannerExitCode = $LASTEXITCODE
}
catch {
    $message = $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' ')
    Write-Host "::error title=Picket process failed::$message"
    $scannerExitCode = 1
}

$findingCount = 0
if (Test-Path -LiteralPath $jsonlPath) {
    $findingCount = (Get-Content -LiteralPath $jsonlPath | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Measure-Object).Count
}

$shouldFail = $false
$failureCode = 0
switch ($failOn) {
    'findings' {
        if ($findingCount -gt 0) {
            $shouldFail = $true
            $failureCode = if ($scannerExitCode -ne 0) { $scannerExitCode } else { 1 }
        }
        elseif ($scannerExitCode -ne 0) {
            $shouldFail = $true
            $failureCode = $scannerExitCode
        }
    }
    'errors' {
        if ($scannerExitCode -ne 0 -and $findingCount -eq 0) {
            $shouldFail = $true
            $failureCode = $scannerExitCode
        }
    }
}

Add-ActionOutput -Name 'exit-code' -Value ([string]$scannerExitCode)
Add-ActionOutput -Name 'findings' -Value ([string]$findingCount)
Add-ActionOutput -Name 'sarif-path' -Value $sarifPath
Add-ActionOutput -Name 'jsonl-path' -Value $jsonlPath
Add-ActionOutput -Name 'should-fail' -Value $shouldFail.ToString().ToLowerInvariant()
Add-ActionOutput -Name 'failure-code' -Value ([string]$failureCode)

Add-StepSummary -Lines @(
    '# Picket scan',
    '',
    '| Field | Value |',
    '| --- | --- |',
    "| Scanner exit code | $scannerExitCode |",
    "| Findings | $findingCount |",
    "| Fail on | $failOn |",
    "| SARIF | $sarifPath |",
    "| JSONL | $jsonlPath |"
)

exit 0
