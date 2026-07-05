param(
    [switch]$Update,
    [switch]$AllowMissing,
    [string]$OutputPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputPath))
{
    $OutputPath = Join-Path $repositoryRoot "docs\UPSTREAM.md"
}

$references = @(
    [pscustomobject]@{
        Name = "Gitleaks"
        EnvironmentVariable = "PICKET_GITLEAKS_REPO"
        SiblingName = "gitleaks"
    },
    [pscustomobject]@{
        Name = "Scout"
        EnvironmentVariable = "PICKET_SCOUT_REPO"
        SiblingName = "scout"
    },
    [pscustomobject]@{
        Name = "TruffleHog"
        EnvironmentVariable = "PICKET_TRUFFLEHOG_REPO"
        SiblingName = "trufflehog"
    },
    [pscustomobject]@{
        Name = "Nosey Parker"
        EnvironmentVariable = "PICKET_NOSEYPARKER_REPO"
        SiblingName = "noseyparker"
    },
    [pscustomobject]@{
        Name = "Kingfisher"
        EnvironmentVariable = "PICKET_KINGFISHER_REPO"
        SiblingName = "kingfisher"
    },
    [pscustomobject]@{
        Name = ".NET Runtime"
        EnvironmentVariable = "PICKET_DOTNET_RUNTIME_REPO"
        SiblingName = "runtime"
    }
)

function Resolve-ReferencePath
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Reference
    )

    $configuredPath = [Environment]::GetEnvironmentVariable($Reference.EnvironmentVariable)
    if (![string]::IsNullOrWhiteSpace($configuredPath))
    {
        return $configuredPath
    }

    $parent = Split-Path -Parent $repositoryRoot
    return Join-Path $parent $Reference.SiblingName
}

function Invoke-Git
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryPath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & git -C $RepositoryPath @Arguments 2>$null
    if ($LASTEXITCODE -ne 0)
    {
        throw "git $($Arguments -join ' ') failed for '$RepositoryPath'."
    }

    return ($output -join "`n").Trim()
}

function Escape-MarkdownCell
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.Replace("\", "\\").Replace("|", "\|")
}

function Get-ReferencePin
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Reference
    )

    $path = Resolve-ReferencePath -Reference $Reference
    if (!(Test-Path -LiteralPath $path -PathType Container))
    {
        if ($AllowMissing)
        {
            return [pscustomobject]@{
                Name = $Reference.Name
                Version = "missing"
                Commit = "missing"
                Remote = "missing"
            }
        }

        throw "Reference clone '$($Reference.Name)' was not found at '$path'. Set $($Reference.EnvironmentVariable) or clone it as sibling '$($Reference.SiblingName)'."
    }

    [pscustomobject]@{
        Name = $Reference.Name
        Version = Invoke-Git -RepositoryPath $path -Arguments @("describe", "--tags", "--always", "--dirty")
        Commit = Invoke-Git -RepositoryPath $path -Arguments @("rev-parse", "HEAD")
        Remote = Invoke-Git -RepositoryPath $path -Arguments @("remote", "get-url", "origin")
    }
}

function New-PinsTable
{
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine("| Project | Version | Commit | Remote |")
    [void]$builder.AppendLine("|---|---:|---|---|")

    foreach ($reference in $references)
    {
        $pin = Get-ReferencePin -Reference $reference
        $name = Escape-MarkdownCell -Value $pin.Name
        $version = Escape-MarkdownCell -Value $pin.Version
        $commit = Escape-MarkdownCell -Value $pin.Commit
        $remote = Escape-MarkdownCell -Value $pin.Remote
        [void]$builder.AppendLine("| $name | ``$version`` | ``$commit`` | ``$remote`` |")
    }

    return $builder.ToString().TrimEnd()
}

$table = New-PinsTable

if (!$Update)
{
    $table
    exit 0
}

$startMarker = "<!-- upstream-pins:start -->"
$endMarker = "<!-- upstream-pins:end -->"
$content = Get-Content -Raw -LiteralPath $OutputPath
$startIndex = $content.IndexOf($startMarker, [StringComparison]::Ordinal)
$endIndex = $content.IndexOf($endMarker, [StringComparison]::Ordinal)

if ($startIndex -lt 0 -or $endIndex -lt 0 -or $endIndex -le $startIndex)
{
    throw "Could not find upstream pins markers in '$OutputPath'."
}

$replacement = "$startMarker`n$table`n$endMarker"
$updatedContent = [string]::Concat(
    $content.Substring(0, $startIndex),
    $replacement,
    $content.Substring($endIndex + $endMarker.Length))

[System.IO.File]::WriteAllText((Resolve-Path $OutputPath).Path, $updatedContent)
