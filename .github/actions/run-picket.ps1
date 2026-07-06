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

function ConvertTo-GitHubCommandProperty {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return $Value.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A').Replace(':', '%3A').Replace(',', '%2C')
}

function ConvertTo-GitHubCommandMessage {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return $Value.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
}

function ConvertTo-MarkdownCell {
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return $Value.Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ').Trim()
}

function Get-JsonPropertyString {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ''
    }

    return [string]$property.Value
}

function Get-JsonPropertyInt {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$Default
    )

    $propertyValue = Get-JsonPropertyString -InputObject $InputObject -Name $Name
    [int]$parsed = 0
    if ([int]::TryParse($propertyValue, [ref]$parsed)) {
        return $parsed
    }

    return $Default
}

function ConvertTo-PositiveInt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    [int]$parsed = 0
    if ([int]::TryParse($Value, [ref]$parsed) -and $parsed -ge 0) {
        return $parsed
    }

    Write-Host "::error title=Invalid $Name::$Name must be a non-negative integer."
    exit 1
}

function Write-FindingAnnotations {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonlPath,

        [Parameter(Mandatory = $true)]
        [int]$Limit
    )

    if ($Limit -eq 0 -or !(Test-Path -LiteralPath $JsonlPath)) {
        return 0
    }

    $emitted = 0
    foreach ($line in Get-Content -LiteralPath $JsonlPath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        if ($emitted -ge $Limit) {
            break
        }

        try {
            $finding = $line | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Host '::warning title=Picket annotation skipped::Could not parse a JSONL finding for annotation output.'
            continue
        }

        $ruleId = Get-JsonPropertyString -InputObject $finding -Name 'ruleId'
        $file = Get-JsonPropertyString -InputObject $finding -Name 'file'
        if ([string]::IsNullOrWhiteSpace($file)) {
            continue
        }

        $lineNumber = Get-JsonPropertyInt -InputObject $finding -Name 'startLine' -Default 1
        $columnNumber = Get-JsonPropertyInt -InputObject $finding -Name 'startColumn' -Default 1
        if ($lineNumber -lt 1) {
            $lineNumber = 1
        }

        if ($columnNumber -lt 1) {
            $columnNumber = 1
        }

        $properties = "file=$(ConvertTo-GitHubCommandProperty $file),line=$lineNumber,col=$columnNumber,title=$(ConvertTo-GitHubCommandProperty "Picket secret: $ruleId")"
        $message = ConvertTo-GitHubCommandMessage "Picket detected rule $ruleId at $file`:$lineNumber`:$columnNumber."
        Write-Host "::warning $properties::$message"
        $emitted++
    }

    return $emitted
}

function Add-FindingSummaryCount {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Counts,

        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Default
    )

    $key = if ([string]::IsNullOrWhiteSpace($Value)) { $Default } else { $Value }
    if ($Counts.ContainsKey($key)) {
        $Counts[$key] = [int]$Counts[$key] + 1
        return
    }

    $Counts[$key] = 1
}

function Get-FindingBreakdownTableLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$ColumnName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Counts,

        [Parameter(Mandatory = $true)]
        [int]$Limit
    )

    if ($Counts.Count -eq 0) {
        return @()
    }

    $lines = @(
        '',
        "## $Title",
        '',
        "| $ColumnName | Count |",
        '| --- | ---: |'
    )

    $rows = $Counts.GetEnumerator() |
        Sort-Object @{ Expression = { -[int]$_.Value } }, @{ Expression = { [string]$_.Key } } |
        Select-Object -First $Limit

    foreach ($row in $rows) {
        $lines += "| $(ConvertTo-MarkdownCell ([string]$row.Key)) | $($row.Value) |"
    }

    if ($Counts.Count -gt $Limit) {
        $lines += ''
        $lines += "_Showing top $Limit of $($Counts.Count)._"
    }

    return $lines
}

function Get-FindingBreakdownSummaryLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonlPath,

        [Parameter(Mandatory = $true)]
        [int]$Limit
    )

    if ($Limit -eq 0 -or !(Test-Path -LiteralPath $JsonlPath)) {
        return @()
    }

    $ruleCounts = @{}
    $fileCounts = @{}
    foreach ($line in Get-Content -LiteralPath $JsonlPath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        try {
            $finding = $line | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Host '::warning title=Picket summary skipped::Could not parse a JSONL finding for summary output.'
            continue
        }

        Add-FindingSummaryCount -Counts $ruleCounts -Value (Get-JsonPropertyString -InputObject $finding -Name 'ruleId') -Default '(unknown rule)'
        Add-FindingSummaryCount -Counts $fileCounts -Value (Get-JsonPropertyString -InputObject $finding -Name 'file') -Default '(unknown file)'
    }

    $lines = @()
    $lines += Get-FindingBreakdownTableLines -Title 'Findings by rule' -ColumnName 'Rule' -Counts $ruleCounts -Limit $Limit
    $lines += Get-FindingBreakdownTableLines -Title 'Findings by file' -ColumnName 'File' -Counts $fileCounts -Limit $Limit
    return $lines
}

$actionPath = [Environment]::GetEnvironmentVariable('GITHUB_ACTION_PATH')
if ([string]::IsNullOrWhiteSpace($actionPath)) {
    $actionPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}

$scanPath = Resolve-WorkspacePath (Get-ActionInput -Name 'PICKET_PATH' -Default '.')
$configPath = Get-ActionInput -Name 'PICKET_CONFIG_PATH'
$baselinePath = Get-ActionInput -Name 'PICKET_BASELINE_PATH'
$cacheEnabled = Get-ActionInput -Name 'PICKET_CACHE_ENABLED' -Default 'true'
$cacheMode = (Get-ActionInput -Name 'PICKET_CACHE_MODE' -Default 'secret-hash-only').Trim().ToLowerInvariant()
$cachePath = Get-ActionInput -Name 'PICKET_CACHE_PATH' -Default '.picket/cache'
$reportDirectory = Resolve-WorkspacePath (Get-ActionInput -Name 'PICKET_REPORT_DIRECTORY' -Default 'picket-results')
$failOn = (Get-ActionInput -Name 'PICKET_FAIL_ON' -Default 'findings').Trim().ToLowerInvariant()
$summaryEnabled = (Get-ActionInput -Name 'PICKET_SUMMARY' -Default 'true').Trim().ToLowerInvariant()
$validationResults = Get-ActionInput -Name 'PICKET_RESULTS'
$onlyVerified = (Get-ActionInput -Name 'PICKET_ONLY_VERIFIED' -Default 'false').Trim().ToLowerInvariant()
$annotationsEnabled = Get-ActionInput -Name 'PICKET_ANNOTATIONS' -Default 'true'
$annotationLimit = ConvertTo-PositiveInt (Get-ActionInput -Name 'PICKET_ANNOTATION_LIMIT' -Default '50') 'annotation-limit'
$redact = Get-ActionInput -Name 'PICKET_REDACT' -Default '100'
$maxTargetMegabytes = Get-ActionInput -Name 'PICKET_MAX_TARGET_MEGABYTES'
$timeout = Get-ActionInput -Name 'PICKET_TIMEOUT'
$maxArchiveDepth = Get-ActionInput -Name 'PICKET_MAX_ARCHIVE_DEPTH'
$maxArchiveEntries = Get-ActionInput -Name 'PICKET_MAX_ARCHIVE_ENTRIES'
$maxArchiveMegabytes = Get-ActionInput -Name 'PICKET_MAX_ARCHIVE_MEGABYTES'
$maxArchiveRatio = Get-ActionInput -Name 'PICKET_MAX_ARCHIVE_RATIO'

if ($failOn -notin @('findings', 'errors', 'never')) {
    Write-Host '::error title=Invalid fail-on::fail-on must be findings, errors, or never.'
    exit 1
}

if ($cacheMode -notin @('secret-hash-only', 'raw')) {
    Write-Host '::error title=Invalid cache-mode::cache-mode must be secret-hash-only or raw.'
    exit 1
}

if ($summaryEnabled -notin @('true', 'false')) {
    Write-Host '::error title=Invalid summary::summary must be true or false.'
    exit 1
}

if ($onlyVerified -notin @('true', 'false')) {
    Write-Host '::error title=Invalid only-verified::only-verified must be true or false.'
    exit 1
}

if ($onlyVerified.Equals('true', [StringComparison]::OrdinalIgnoreCase) -and ![string]::IsNullOrWhiteSpace($validationResults)) {
    Write-Host '::error title=Invalid validation filter::results and only-verified cannot both be set.'
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
    $arguments += @('--cache-dir', $resolvedCachePath, '--cache-mode', $cacheMode)
}

if ($onlyVerified.Equals('true', [StringComparison]::OrdinalIgnoreCase)) {
    $arguments += '--only-verified'
}
elseif (![string]::IsNullOrWhiteSpace($validationResults)) {
    $arguments += @('--results', $validationResults)
}

if (![string]::IsNullOrWhiteSpace($maxTargetMegabytes)) {
    $arguments += @('--max-target-megabytes', $maxTargetMegabytes)
}

if (![string]::IsNullOrWhiteSpace($timeout)) {
    $arguments += @('--timeout', $timeout)
}

if (![string]::IsNullOrWhiteSpace($maxArchiveDepth)) {
    $arguments += @('--max-archive-depth', $maxArchiveDepth)
}

if (![string]::IsNullOrWhiteSpace($maxArchiveEntries)) {
    $arguments += @('--max-archive-entries', $maxArchiveEntries)
}

if (![string]::IsNullOrWhiteSpace($maxArchiveMegabytes)) {
    $arguments += @('--max-archive-megabytes', $maxArchiveMegabytes)
}

if (![string]::IsNullOrWhiteSpace($maxArchiveRatio)) {
    $arguments += @('--max-archive-ratio', $maxArchiveRatio)
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

$annotationCount = 0
if ($annotationsEnabled.Equals('true', [StringComparison]::OrdinalIgnoreCase)) {
    $annotationCount = Write-FindingAnnotations -JsonlPath $jsonlPath -Limit $annotationLimit
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
Add-ActionOutput -Name 'annotations' -Value ([string]$annotationCount)
Add-ActionOutput -Name 'should-fail' -Value $shouldFail.ToString().ToLowerInvariant()
Add-ActionOutput -Name 'failure-code' -Value ([string]$failureCode)

if ($summaryEnabled.Equals('true', [StringComparison]::OrdinalIgnoreCase)) {
    $resultFilterSummary = 'all'
    if ($onlyVerified.Equals('true', [StringComparison]::OrdinalIgnoreCase)) {
        $resultFilterSummary = 'only-verified'
    }
    elseif (![string]::IsNullOrWhiteSpace($validationResults)) {
        $resultFilterSummary = $validationResults
    }

    $summaryLines = @(
        '# Picket scan',
        '',
        '| Field | Value |',
        '| --- | --- |',
        "| Scanner exit code | $scannerExitCode |",
        "| Findings | $findingCount |",
        "| Annotations | $annotationCount |",
        "| Fail on | $failOn |",
        "| Result filter | $resultFilterSummary |",
        "| SARIF | $sarifPath |",
        "| JSONL | $jsonlPath |"
    )
    $summaryLines += Get-FindingBreakdownSummaryLines -JsonlPath $jsonlPath -Limit 10
    Add-StepSummary -Lines $summaryLines
}

exit 0
