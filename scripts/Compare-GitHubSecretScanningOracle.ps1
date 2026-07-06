[CmdletBinding()]
param(
    [string]$OraclePath = "",

    [string]$PicketReportPath = "",

    [string]$OutputPath = "",

    [switch]$FailOnDifference
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OraclePath))
{
    $OraclePath = Join-Path $repositoryRoot "artifacts\oracles\github-secret-scanning\alerts.json"
}

if ([string]::IsNullOrWhiteSpace($PicketReportPath))
{
    $PicketReportPath = Join-Path $repositoryRoot "artifacts\oracles\github-secret-scanning\picket-scan.jsonl"
}

if ([string]::IsNullOrWhiteSpace($OutputPath))
{
    $OutputPath = Join-Path $repositoryRoot "artifacts\oracles\github-secret-scanning\comparison.json"
}

$githubToPicketRuleIds = @{
    google_api_key = @("picket-google-api-key")
}

function Read-RequiredJson
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "$Description '$Path' does not exist."
    }

    return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
}

function Read-PicketJsonLines
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf))
    {
        throw "Picket report '$Path' does not exist."
    }

    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($line in [System.IO.File]::ReadLines($Path))
    {
        if ([string]::IsNullOrWhiteSpace($line))
        {
            continue
        }

        [void]$findings.Add(($line | ConvertFrom-Json))
    }

    return ,$findings
}

function Get-PropertyValue
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value)
    {
        return ""
    }

    return [string]$property.Value
}

function Get-IntegerPropertyValue
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value)
    {
        return 0
    }

    return [int]$property.Value
}

function New-LocationKey
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$Line
    )

    return "$($Path.Replace('\', '/')):$Line"
}

function Add-Location
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Map,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [object]$Location
    )

    if (!$Map.ContainsKey($Key))
    {
        $Map[$Key] = [System.Collections.Generic.List[object]]::new()
    }

    [void]$Map[$Key].Add($Location)
}

function ConvertTo-GitHubLocation
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Alert,

        [Parameter(Mandatory = $true)]
        [object]$Location
    )

    [pscustomobject]@{
        AlertNumber = Get-IntegerPropertyValue -Value $Alert -Name "Number"
        SecretType = Get-PropertyValue -Value $Alert -Name "SecretType"
        SecretTypeDisplayName = Get-PropertyValue -Value $Alert -Name "SecretTypeDisplayName"
        Path = Get-PropertyValue -Value $Location -Name "Path"
        StartLine = Get-IntegerPropertyValue -Value $Location -Name "StartLine"
        StartColumn = Get-IntegerPropertyValue -Value $Location -Name "StartColumn"
        EndLine = Get-IntegerPropertyValue -Value $Location -Name "EndLine"
        EndColumn = Get-IntegerPropertyValue -Value $Location -Name "EndColumn"
    }
}

function ConvertTo-PicketLocation
{
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$SecretType
    )

    [pscustomobject]@{
        SecretType = $SecretType
        RuleId = Get-PropertyValue -Value $Finding -Name "ruleId"
        Path = Get-PropertyValue -Value $Finding -Name "file"
        StartLine = Get-IntegerPropertyValue -Value $Finding -Name "startLine"
        StartColumn = Get-IntegerPropertyValue -Value $Finding -Name "startColumn"
        Fingerprint = Get-PropertyValue -Value $Finding -Name "fingerprint"
    }
}

function Test-RuleMapsToSecretType
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $true)]
        [string]$SecretType
    )

    if (!$githubToPicketRuleIds.ContainsKey($SecretType))
    {
        return $false
    }

    foreach ($mappedRuleId in @($githubToPicketRuleIds[$SecretType]))
    {
        if ($mappedRuleId.Equals($RuleId, [System.StringComparison]::Ordinal))
        {
            return $true
        }
    }

    return $false
}

$oracle = Read-RequiredJson -Path $OraclePath -Description "GitHub secret-scanning oracle"
if (!(Get-PropertyValue -Value $oracle -Name "Schema").Equals("picket.github-secret-scanning-oracle.v1", [System.StringComparison]::Ordinal))
{
    throw "Unsupported GitHub oracle schema in '$OraclePath'."
}

$picketFindings = Read-PicketJsonLines -Path $PicketReportPath
$allSecretTypes = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($alert in @($oracle.Alerts))
{
    [void]$allSecretTypes.Add((Get-PropertyValue -Value $alert -Name "SecretType"))
}

foreach ($secretType in $githubToPicketRuleIds.Keys)
{
    [void]$allSecretTypes.Add($secretType)
}

$typeComparisons = [System.Collections.Generic.List[object]]::new()
$missingLocations = [System.Collections.Generic.List[object]]::new()
$unexpectedLocations = [System.Collections.Generic.List[object]]::new()
$unmappedAlertTypes = [System.Collections.Generic.List[string]]::new()
$unmappedPicketRuleIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)

foreach ($secretType in $allSecretTypes)
{
    if ([string]::IsNullOrWhiteSpace($secretType))
    {
        continue
    }

    $mappedRuleIds = [System.Collections.Generic.List[string]]::new()
    if ($githubToPicketRuleIds.ContainsKey($secretType))
    {
        foreach ($mappedRuleId in @($githubToPicketRuleIds[$secretType]))
        {
            [void]$mappedRuleIds.Add($mappedRuleId)
        }
    }

    $hasMappedRuleIds = $mappedRuleIds.Count -ne 0
    if (!$hasMappedRuleIds)
    {
        [void]$unmappedAlertTypes.Add($secretType)
    }

    $githubLocations = [System.Collections.Generic.List[object]]::new()
    $githubLocationMap = @{}
    foreach ($alert in @($oracle.Alerts))
    {
        if (!(Get-PropertyValue -Value $alert -Name "SecretType").Equals($secretType, [System.StringComparison]::Ordinal))
        {
            continue
        }

        foreach ($location in @($alert.Locations))
        {
            $safeLocation = ConvertTo-GitHubLocation -Alert $alert -Location $location
            [void]$githubLocations.Add($safeLocation)
            Add-Location -Map $githubLocationMap -Key (New-LocationKey -Path $safeLocation.Path -Line $safeLocation.StartLine) -Location $safeLocation
        }
    }

    $picketLocations = [System.Collections.Generic.List[object]]::new()
    $picketLocationMap = @{}
    if ($hasMappedRuleIds)
    {
        foreach ($finding in $picketFindings)
        {
            $ruleId = Get-PropertyValue -Value $finding -Name "ruleId"
            if (!($mappedRuleIds -contains $ruleId))
            {
                continue
            }

            $safeFinding = ConvertTo-PicketLocation -Finding $finding -SecretType $secretType
            [void]$picketLocations.Add($safeFinding)
            Add-Location -Map $picketLocationMap -Key (New-LocationKey -Path $safeFinding.Path -Line $safeFinding.StartLine) -Location $safeFinding
        }
    }

    $matchingLocationCount = 0
    $missingLocationCount = 0
    $unexpectedLocationCount = 0
    if ($hasMappedRuleIds)
    {
        foreach ($githubKey in ($githubLocationMap.Keys | Sort-Object))
        {
            if (!$picketLocationMap.ContainsKey($githubKey))
            {
                foreach ($location in $githubLocationMap[$githubKey])
                {
                    [void]$missingLocations.Add($location)
                }
            }
        }

        foreach ($picketKey in ($picketLocationMap.Keys | Sort-Object))
        {
            if (!$githubLocationMap.ContainsKey($picketKey))
            {
                foreach ($location in $picketLocationMap[$picketKey])
                {
                    [void]$unexpectedLocations.Add($location)
                }
            }
        }

        foreach ($githubKey in $githubLocationMap.Keys)
        {
            if ($picketLocationMap.ContainsKey($githubKey))
            {
                $matchingLocationCount += [Math]::Min($githubLocationMap[$githubKey].Count, $picketLocationMap[$githubKey].Count)
            }
        }

        $missingLocationCount = [Math]::Max(0, $githubLocations.Count - $matchingLocationCount)
        $unexpectedLocationCount = [Math]::Max(0, $picketLocations.Count - $matchingLocationCount)
    }

    $alertCount = @($oracle.Alerts | Where-Object { (Get-PropertyValue -Value $_ -Name "SecretType").Equals($secretType, [System.StringComparison]::Ordinal) }).Count
    [void]$typeComparisons.Add([pscustomobject]@{
        SecretType = $secretType
        PicketRuleIds = $mappedRuleIds.ToArray()
        AlertCount = $alertCount
        GitHubLocationCount = $githubLocations.Count
        PicketFindingCount = $picketLocations.Count
        MatchingLocationCount = $matchingLocationCount
        MissingLocationCount = $missingLocationCount
        UnexpectedLocationCount = $unexpectedLocationCount
    })
}

foreach ($finding in $picketFindings)
{
    $ruleId = Get-PropertyValue -Value $finding -Name "ruleId"
    if ([string]::IsNullOrWhiteSpace($ruleId))
    {
        continue
    }

    $mapped = $false
    foreach ($secretType in $githubToPicketRuleIds.Keys)
    {
        if (Test-RuleMapsToSecretType -RuleId $ruleId -SecretType $secretType)
        {
            $mapped = $true
            break
        }
    }

    if (!$mapped)
    {
        [void]$unmappedPicketRuleIds.Add($ruleId)
    }
}

$metadata = [pscustomobject]@{
    Schema = "picket.github-secret-scanning-comparison.v1"
    OraclePath = (Resolve-Path -LiteralPath $OraclePath).Path
    PicketReportPath = (Resolve-Path -LiteralPath $PicketReportPath).Path
    ComparedUtc = [DateTimeOffset]::UtcNow.ToString("O")
    AlertCount = [int]$oracle.AlertCount
    PicketFindingCount = $picketFindings.Count
    TypeComparisons = $typeComparisons.ToArray()
    MissingLocationCount = $missingLocations.Count
    UnexpectedLocationCount = $unexpectedLocations.Count
    UnmappedAlertTypeCount = $unmappedAlertTypes.Count
    UnmappedPicketRuleIdCount = $unmappedPicketRuleIds.Count
    MissingLocations = $missingLocations.ToArray()
    UnexpectedLocations = $unexpectedLocations.ToArray()
    UnmappedAlertTypes = $unmappedAlertTypes.ToArray()
    UnmappedPicketRuleIds = [System.Linq.Enumerable]::ToArray[string]($unmappedPicketRuleIds)
}

$outputDirectory = Split-Path -Parent $OutputPath
if (![string]::IsNullOrWhiteSpace($outputDirectory))
{
    [void][System.IO.Directory]::CreateDirectory($outputDirectory)
}

$metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM

if ($FailOnDifference -and ($missingLocations.Count -ne 0 -or $unmappedAlertTypes.Count -ne 0))
{
    throw "GitHub secret-scanning oracle comparison has $($missingLocations.Count) missing locations and $($unmappedAlertTypes.Count) unmapped alert types. See '$OutputPath'."
}

Write-Host "Compared GitHub secret-scanning oracle metadata in '$OutputPath'."
