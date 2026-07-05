[CmdletBinding()]
param(
    [string]$CaptureDirectory = "",

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]*$")]
    [string]$Name,

    [string]$OutputRoot = "",

    [string]$RedactionMapPath = "",

    [switch]$AllowUnredacted,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($CaptureDirectory))
{
    $CaptureDirectory = Join-Path $repositoryRoot "artifacts\oracles\compatibility"
}

if ([string]::IsNullOrWhiteSpace($OutputRoot))
{
    $OutputRoot = Join-Path $repositoryRoot "tests\fixtures\oracles"
}

function Resolve-ExistingDirectory
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (!(Test-Path -LiteralPath $PathValue -PathType Container))
    {
        throw "$Description '$PathValue' does not exist."
    }

    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Resolve-OptionalFile
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($PathValue))
    {
        return ""
    }

    if (!(Test-Path -LiteralPath $PathValue -PathType Leaf))
    {
        throw "$Description '$PathValue' does not exist."
    }

    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Load-RedactionMap
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PathValue
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($PathValue))
    {
        return ,$entries
    }

    $json = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json
    foreach ($property in $json.PSObject.Properties)
    {
        $secret = [string]$property.Name
        $placeholder = [string]$property.Value
        if ([string]::IsNullOrEmpty($secret))
        {
            throw "Redaction map '$PathValue' contains an empty secret key."
        }

        if ([string]::IsNullOrWhiteSpace($placeholder))
        {
            throw "Redaction map '$PathValue' contains an empty placeholder for '$secret'."
        }

        $entries.Add([pscustomobject]@{
            Secret = $secret
            Placeholder = $placeholder
        })
    }

    $sortedEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in ($entries | Sort-Object { $_.Secret.Length } -Descending))
    {
        $sortedEntries.Add($entry)
    }

    return ,$sortedEntries
}

function Add-PathReplacement
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Replacements,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Placeholder
    )

    if ([string]::IsNullOrWhiteSpace($PathValue))
    {
        return
    }

    $Replacements.Add([pscustomobject]@{
        Original = $PathValue
        Replacement = $Placeholder
    })

    $normalized = $PathValue.Replace("\", "/")
    if ($normalized -ne $PathValue)
    {
        $Replacements.Add([pscustomobject]@{
            Original = $normalized
            Replacement = $Placeholder
        })
    }
}

function New-PathReplacements
{
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Comparison,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedCaptureDirectory
    )

    $replacements = [System.Collections.Generic.List[object]]::new()
    $workingDirectory = ""
    if ($Comparison.PSObject.Properties.Name -contains "WorkingDirectory")
    {
        $workingDirectory = [string]$Comparison.WorkingDirectory
    }

    Add-PathReplacement -Replacements $replacements -PathValue $repositoryRoot -Placeholder "<repo>"
    Add-PathReplacement -Replacements $replacements -PathValue $ResolvedCaptureDirectory -Placeholder "<capture>"
    Add-PathReplacement -Replacements $replacements -PathValue $workingDirectory -Placeholder "<working-directory>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.Source -Placeholder "<source>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.StdinPath -Placeholder "<stdin>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.Config -Placeholder "<config>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.BaselinePath -Placeholder "<baseline>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.ReportTemplate -Placeholder "<report-template>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.GitleaksMetadataPath -Placeholder "<gitleaks-metadata>"
    Add-PathReplacement -Replacements $replacements -PathValue $Comparison.PicketBinary -Placeholder "<picket-binary>"

    $sortedReplacements = [System.Collections.Generic.List[object]]::new()
    foreach ($replacement in ($replacements | Sort-Object { $_.Original.Length } -Descending))
    {
        $sortedReplacements.Add($replacement)
    }

    return ,$sortedReplacements
}

function Normalize-Content
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Redactions,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$PathReplacements
    )

    $normalized = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
    $normalized = [regex]::Replace($normalized, "(?m)^\d{1,2}:\d{2}(?:AM|PM)\s+", "<time> ")
    $normalized = [regex]::Replace($normalized, "(?m)( scanned ~[0-9.,]+ [A-Za-z]+ \([0-9.,]+ [A-Za-z]+\) in )\S+", '${1}<duration>')
    foreach ($replacement in $PathReplacements)
    {
        if (![string]::IsNullOrEmpty($replacement.Original))
        {
            $normalized = $normalized.Replace($replacement.Original, $replacement.Replacement)
        }
    }

    foreach ($redaction in $Redactions)
    {
        $normalized = $normalized.Replace($redaction.Secret, $redaction.Placeholder)
    }

    return $normalized
}

function Write-NormalizedFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Redactions,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$PathReplacements
    )

    if (!(Test-Path -LiteralPath $SourcePath -PathType Leaf))
    {
        throw "Expected capture file '$SourcePath' does not exist."
    }

    $content = Get-Content -Raw -LiteralPath $SourcePath
    $normalized = Normalize-Content -Content $content -Redactions $Redactions -PathReplacements $PathReplacements
    [System.IO.File]::WriteAllText($DestinationPath, $normalized, [System.Text.UTF8Encoding]::new($false))
}

function Get-FileSha256
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-NoUnsafePromotedContent
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Redactions,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$PathReplacements
    )

    foreach ($file in Get-ChildItem -LiteralPath $DirectoryPath -File -Recurse)
    {
        $content = Get-Content -Raw -LiteralPath $file.FullName
        if ($null -eq $content)
        {
            $content = ""
        }

        if ($content -match "(^|[\s`"'[{(,])([A-Za-z]:[\\/])")
        {
            throw "Promoted file '$($file.FullName)' still contains a Windows absolute path."
        }

        foreach ($replacement in $PathReplacements)
        {
            if ((![string]::IsNullOrWhiteSpace($replacement.Original)) -and $content.Contains($replacement.Original, [StringComparison]::OrdinalIgnoreCase))
            {
                throw "Promoted file '$($file.FullName)' still contains '$($replacement.Original)'."
            }
        }

        foreach ($redaction in $Redactions)
        {
            if ($content.Contains($redaction.Secret, [StringComparison]::Ordinal))
            {
                throw "Promoted file '$($file.FullName)' still contains an unredacted redaction-map key."
            }
        }
    }
}

function New-RelativePath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PathValue
    )

    return (Resolve-Path -LiteralPath $PathValue).Path.Substring((Resolve-Path -LiteralPath $BasePath).Path.Length).TrimStart("\", "/").Replace("\", "/")
}

if ([string]::IsNullOrWhiteSpace($RedactionMapPath) -and !$AllowUnredacted)
{
    throw "Refusing to promote oracle captures without -RedactionMapPath or -AllowUnredacted. Use -AllowUnredacted only for synthetic no-secret captures."
}

$resolvedCaptureDirectory = Resolve-ExistingDirectory -PathValue $CaptureDirectory -Description "capture directory"
$comparisonPath = Join-Path $resolvedCaptureDirectory "comparison.json"
if (!(Test-Path -LiteralPath $comparisonPath -PathType Leaf))
{
    throw "Capture directory '$resolvedCaptureDirectory' does not contain comparison.json."
}

$resolvedRedactionMapPath = Resolve-OptionalFile -PathValue $RedactionMapPath -Description "redaction map"
$redactions = Load-RedactionMap -PathValue $resolvedRedactionMapPath
$comparison = Get-Content -Raw -LiteralPath $comparisonPath | ConvertFrom-Json
$pathReplacements = New-PathReplacements -Comparison $comparison -ResolvedCaptureDirectory $resolvedCaptureDirectory

[void][System.IO.Directory]::CreateDirectory($OutputRoot)
$resolvedOutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$destination = Join-Path $resolvedOutputRoot $Name
if ((Test-Path -LiteralPath $destination) -and !$Force)
{
    throw "Destination '$destination' already exists. Pass -Force to overwrite it."
}

if (Test-Path -LiteralPath $destination)
{
    Remove-Item -LiteralPath $destination -Recurse -Force
}

[void][System.IO.Directory]::CreateDirectory($destination)
$promotedFiles = [System.Collections.Generic.List[object]]::new()
$promotedComparisons = [System.Collections.Generic.List[object]]::new()

foreach ($captureComparison in $comparison.Comparisons)
{
    $format = [string]$captureComparison.Format
    $targets = @(
        [pscustomobject]@{
            Kind = "gitleaks-report"
            SourcePath = [string]$captureComparison.GitleaksReportPath
            FileName = "gitleaks.$format"
        },
        [pscustomobject]@{
            Kind = "picket-report"
            SourcePath = [string]$captureComparison.PicketReportPath
            FileName = "picket.$format"
        },
        [pscustomobject]@{
            Kind = "gitleaks-stdout"
            SourcePath = [string]$captureComparison.GitleaksStdoutPath
            FileName = "gitleaks.$format.stdout.txt"
        },
        [pscustomobject]@{
            Kind = "picket-stdout"
            SourcePath = [string]$captureComparison.PicketStdoutPath
            FileName = "picket.$format.stdout.txt"
        },
        [pscustomobject]@{
            Kind = "gitleaks-stderr"
            SourcePath = [string]$captureComparison.GitleaksStderrPath
            FileName = "gitleaks.$format.stderr.txt"
        },
        [pscustomobject]@{
            Kind = "picket-stderr"
            SourcePath = [string]$captureComparison.PicketStderrPath
            FileName = "picket.$format.stderr.txt"
        }
    )

    foreach ($target in $targets)
    {
        $destinationPath = Join-Path $destination $target.FileName
        Write-NormalizedFile `
            -SourcePath $target.SourcePath `
            -DestinationPath $destinationPath `
            -Redactions $redactions `
            -PathReplacements $pathReplacements
        $promotedFiles.Add([pscustomobject]@{
            Kind = $target.Kind
            Format = $format
            Path = (New-RelativePath -BasePath $destination -PathValue $destinationPath)
            Sha256 = Get-FileSha256 -Path $destinationPath
        })
    }

    $promotedComparisons.Add([pscustomobject]@{
        Format = $format
        ExitCodeEqual = [bool]$captureComparison.ExitCodeEqual
        ReportBytesEqual = [bool]$captureComparison.ReportBytesEqual
        StdoutBytesEqual = [bool]$captureComparison.StdoutBytesEqual
        StderrBytesEqual = [bool]$captureComparison.StderrBytesEqual
        GitleaksExitCode = [int]$captureComparison.GitleaksExitCode
        PicketExitCode = [int]$captureComparison.PicketExitCode
    })
}

$gitleaksMetadata = Get-Content -Raw -LiteralPath $comparison.GitleaksMetadataPath | ConvertFrom-Json
$manifest = [pscustomobject]@{
    Schema = "picket.oracle.v1"
    Name = $Name
    Mode = [string]$comparison.Mode
    Formats = @($comparison.Comparisons | ForEach-Object { [string]$_.Format })
    Upstream = [pscustomobject]@{
        Tool = "gitleaks"
        Version = [string]$gitleaksMetadata.ToolVersion
        CloneVersion = [string]$gitleaksMetadata.Clone.Version
        Commit = [string]$gitleaksMetadata.Clone.Commit
        Remote = [string]$gitleaksMetadata.Clone.Remote
    }
    Redaction = [pscustomobject]@{
        MapRequired = !$AllowUnredacted
        EntryCount = $redactions.Count
    }
    Files = $promotedFiles.ToArray()
    Comparisons = $promotedComparisons.ToArray()
}

$manifestPath = Join-Path $destination "manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
Assert-NoUnsafePromotedContent -DirectoryPath $destination -Redactions $redactions -PathReplacements $pathReplacements
Write-Host "Promoted normalized compatibility oracle '$Name' to '$destination'."
