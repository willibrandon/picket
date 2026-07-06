[CmdletBinding()]
param(
    [string]$Repository = "",

    [ValidateSet("open", "resolved", "all")]
    [string]$State = "open",

    [string]$OutputPath = "",

    [switch]$IncludeLocations
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath))
{
    $OutputPath = Join-Path $repositoryRoot "artifacts\oracles\github-secret-scanning\alerts.json"
}

function Resolve-GitHubRepository
{
    if (![string]::IsNullOrWhiteSpace($Repository))
    {
        return $Repository
    }

    $resolved = & gh repo view --json nameWithOwner --jq ".nameWithOwner"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($resolved))
    {
        throw "Could not resolve the current GitHub repository. Pass -Repository owner/name."
    }

    return $resolved.Trim()
}

function Invoke-GitHubJson
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & gh @Arguments
    if ($LASTEXITCODE -ne 0)
    {
        throw "gh $($Arguments -join ' ') failed."
    }

    if ([string]::IsNullOrWhiteSpace($output))
    {
        return $null
    }

    return $output | ConvertFrom-Json
}

function Get-PagedGitHubArray
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint
    )

    $pages = Invoke-GitHubJson -Arguments @(
        "api",
        "--paginate",
        "--slurp",
        "-H",
        "Accept: application/vnd.github+json",
        $Endpoint)

    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($page in @($pages))
    {
        foreach ($item in @($page))
        {
            [void]$items.Add($item)
        }
    }

    return $items
}

function ConvertTo-SafeLocation
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Location
    )

    $details = $Location.details
    [pscustomobject]@{
        Type = $Location.type
        Path = $details.path
        StartLine = $details.start_line
        EndLine = $details.end_line
        StartColumn = $details.start_column
        EndColumn = $details.end_column
        BlobSha = $details.blob_sha
        CommitSha = $details.commit_sha
    }
}

function ConvertTo-SafeAlert
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Alert,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Locations
    )

    [pscustomobject]@{
        Number = $Alert.number
        State = $Alert.state
        SecretType = $Alert.secret_type
        SecretTypeDisplayName = $Alert.secret_type_display_name
        CreatedAt = $Alert.created_at
        UpdatedAt = $Alert.updated_at
        ResolvedAt = $Alert.resolved_at
        Resolution = $Alert.resolution
        HtmlUrl = $Alert.html_url
        LocationsUrl = $Alert.locations_url
        Locations = $Locations
    }
}

$resolvedRepository = Resolve-GitHubRepository
$stateQuery = if ($State.Equals("all", [System.StringComparison]::Ordinal)) { "" } else { "state=$State&" }
$alertsEndpoint = "repos/$resolvedRepository/secret-scanning/alerts?$($stateQuery)per_page=100"
$rawAlerts = Get-PagedGitHubArray -Endpoint $alertsEndpoint
$safeAlerts = [System.Collections.Generic.List[object]]::new()

foreach ($alert in $rawAlerts)
{
    $locations = @()
    if ($IncludeLocations -and ![string]::IsNullOrWhiteSpace($alert.locations_url))
    {
        $locationsEndpoint = "repos/$resolvedRepository/secret-scanning/alerts/$($alert.number)/locations?per_page=100"
        $locations = @(Get-PagedGitHubArray -Endpoint $locationsEndpoint | ForEach-Object { ConvertTo-SafeLocation -Location $_ })
    }

    [void]$safeAlerts.Add((ConvertTo-SafeAlert -Alert $alert -Locations $locations))
}

$summary = $safeAlerts |
    Group-Object -Property SecretType |
    Sort-Object -Property Name |
    ForEach-Object {
        [pscustomobject]@{
            SecretType = $_.Name
            Count = $_.Count
        }
    }

$metadata = [pscustomobject]@{
    Schema = "picket.github-secret-scanning-oracle.v1"
    Repository = $resolvedRepository
    State = $State
    IncludeLocations = [bool]$IncludeLocations
    CapturedUtc = [DateTimeOffset]::UtcNow.ToString("O")
    AlertCount = $safeAlerts.Count
    Summary = @($summary)
    Alerts = $safeAlerts.ToArray()
}

$outputDirectory = Split-Path -Parent $OutputPath
if (![string]::IsNullOrWhiteSpace($outputDirectory))
{
    [void][System.IO.Directory]::CreateDirectory($outputDirectory)
}

$metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Write-Host "Captured GitHub secret scanning oracle metadata in '$OutputPath'."
