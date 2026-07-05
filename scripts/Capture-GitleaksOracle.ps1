[CmdletBinding()]
param(
    [ValidateSet("dir", "git", "stdin")]
    [string]$Mode = "dir",

    [string]$Source = ".",

    [ValidateSet("json", "csv", "junit", "sarif", "template")]
    [string[]]$ReportFormat = @("json"),

    [string]$Config = "",

    [string]$BaselinePath = "",

    [string]$ReportTemplate = "",

    [string]$OutputDirectory = "",

    [string]$GitleaksPath = "",

    [string]$StdinPath = "",

    [string]$LogOptions = "",

    [string]$Platform = "",

    [string[]]$AdditionalArguments = @(),

    [switch]$Staged,

    [switch]$PreCommit,

    [switch]$FollowSymlinks,

    [switch]$FailOnFindings,

    [switch]$AllowMissingClone
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory))
{
    $OutputDirectory = Join-Path $repositoryRoot "artifacts\oracles\gitleaks"
}

function Resolve-CommandPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandPath,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (Test-Path -LiteralPath $CommandPath -PathType Leaf)
    {
        return (Resolve-Path -LiteralPath $CommandPath).Path
    }

    $command = Get-Command $CommandPath -ErrorAction SilentlyContinue
    if ($null -ne $command)
    {
        return $command.Source
    }

    throw "Could not find $Description '$CommandPath'."
}

function Resolve-GitleaksExecutable
{
    if (![string]::IsNullOrWhiteSpace($GitleaksPath))
    {
        return Resolve-CommandPath -CommandPath $GitleaksPath -Description "Gitleaks executable"
    }

    $configuredPath = [Environment]::GetEnvironmentVariable("PICKET_GITLEAKS_BIN")
    if (![string]::IsNullOrWhiteSpace($configuredPath))
    {
        return Resolve-CommandPath -CommandPath $configuredPath -Description "Gitleaks executable from PICKET_GITLEAKS_BIN"
    }

    $command = Get-Command "gitleaks" -ErrorAction SilentlyContinue
    if ($null -ne $command)
    {
        return $command.Source
    }

    throw "Could not find Gitleaks. Set PICKET_GITLEAKS_BIN, pass -GitleaksPath, or put gitleaks on PATH."
}

function Resolve-GitleaksClone
{
    $configuredPath = [Environment]::GetEnvironmentVariable("PICKET_GITLEAKS_REPO")
    if (![string]::IsNullOrWhiteSpace($configuredPath))
    {
        return $configuredPath
    }

    $parent = Split-Path -Parent $repositoryRoot
    return Join-Path $parent "gitleaks"
}

function Resolve-ExistingPath
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($PathValue))
    {
        return ""
    }

    try
    {
        return (Resolve-Path -LiteralPath $PathValue -ErrorAction Stop).Path
    }
    catch
    {
        throw "$Description '$PathValue' does not exist."
    }
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

function Get-GitleaksCloneMetadata
{
    $clonePath = Resolve-GitleaksClone
    if (!(Test-Path -LiteralPath $clonePath -PathType Container))
    {
        if ($AllowMissingClone)
        {
            return [pscustomobject]@{
                Path = $clonePath
                Version = "missing"
                Commit = "missing"
                Remote = "missing"
            }
        }

        throw "Gitleaks clone was not found at '$clonePath'. Set PICKET_GITLEAKS_REPO or clone it as sibling 'gitleaks'."
    }

    [pscustomobject]@{
        Path = (Resolve-Path -LiteralPath $clonePath).Path
        Version = Invoke-Git -RepositoryPath $clonePath -Arguments @("describe", "--tags", "--always", "--dirty")
        Commit = Invoke-Git -RepositoryPath $clonePath -Arguments @("rev-parse", "HEAD")
        Remote = Invoke-Git -RepositoryPath $clonePath -Arguments @("remote", "get-url", "origin")
    }
}

function Invoke-ExternalProcess
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [string]$StandardInputPath = ""
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = ![string]::IsNullOrWhiteSpace($StandardInputPath)

    foreach ($argument in $Arguments)
    {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process)
    {
        throw "Failed to start '$FilePath'."
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (![string]::IsNullOrWhiteSpace($StandardInputPath))
    {
        $inputStream = [System.IO.File]::OpenRead($StandardInputPath)
        try
        {
            $inputStream.CopyTo($process.StandardInput.BaseStream)
            $process.StandardInput.Close()
        }
        finally
        {
            $inputStream.Dispose()
        }
    }

    $process.WaitForExit()

    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdoutTask.GetAwaiter().GetResult()
        Stderr = $stderrTask.GetAwaiter().GetResult()
    }
}

function Get-GitleaksVersion
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExecutablePath
    )

    $result = Invoke-ExternalProcess -FilePath $ExecutablePath -Arguments @("version")
    if ($result.ExitCode -ne 0)
    {
        return "unknown"
    }

    return $result.Stdout.Trim()
}

function Get-ReportExtension
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Format
    )

    switch ($Format)
    {
        "template" { return "txt" }
        default { return $Format }
    }
}

function New-GitleaksArguments
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedSource,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedConfig,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedBaselinePath,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedReportTemplate
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add($Mode)

    switch ($Mode)
    {
        "dir"
        {
            $arguments.Add($ResolvedSource)
            if ($FollowSymlinks)
            {
                $arguments.Add("--follow-symlinks")
            }
        }
        "git"
        {
            $arguments.Add($ResolvedSource)
            if (![string]::IsNullOrWhiteSpace($LogOptions))
            {
                $arguments.Add("--log-opts")
                $arguments.Add($LogOptions)
            }

            if (![string]::IsNullOrWhiteSpace($Platform))
            {
                $arguments.Add("--platform")
                $arguments.Add($Platform)
            }

            if ($Staged)
            {
                $arguments.Add("--staged")
            }

            if ($PreCommit)
            {
                $arguments.Add("--pre-commit")
            }
        }
        "stdin"
        {
        }
    }

    if (![string]::IsNullOrWhiteSpace($ResolvedConfig))
    {
        $arguments.Add("--config")
        $arguments.Add($ResolvedConfig)
    }

    if (![string]::IsNullOrWhiteSpace($ResolvedBaselinePath))
    {
        $arguments.Add("--baseline-path")
        $arguments.Add($ResolvedBaselinePath)
    }

    $arguments.Add("--report-format")
    $arguments.Add($Format)
    $arguments.Add("--report-path")
    $arguments.Add($ReportPath)
    $arguments.Add("--no-banner")
    $arguments.Add("--no-color")

    if (![string]::IsNullOrWhiteSpace($ResolvedReportTemplate))
    {
        $arguments.Add("--report-template")
        $arguments.Add($ResolvedReportTemplate)
    }

    foreach ($argument in $AdditionalArguments)
    {
        $arguments.Add($argument)
    }

    return $arguments.ToArray()
}

if ($Mode -eq "stdin")
{
    if ([string]::IsNullOrWhiteSpace($StdinPath))
    {
        throw "Mode 'stdin' requires -StdinPath so oracle input is reproducible."
    }
}
elseif ([string]::IsNullOrWhiteSpace($Source))
{
    $Source = "."
}

if ($ReportFormat.Contains("template") -and [string]::IsNullOrWhiteSpace($ReportTemplate))
{
    throw "Report format 'template' requires -ReportTemplate."
}

$gitleaksExecutable = Resolve-GitleaksExecutable
$gitleaksClone = Get-GitleaksCloneMetadata
$gitleaksVersion = Get-GitleaksVersion -ExecutablePath $gitleaksExecutable
$resolvedSource = ""
$resolvedStdinPath = ""

if ($Mode -eq "stdin")
{
    $resolvedStdinPath = Resolve-ExistingPath -PathValue $StdinPath -Description "stdin fixture"
}
else
{
    $resolvedSource = Resolve-ExistingPath -PathValue $Source -Description "source"
}

$resolvedConfig = Resolve-ExistingPath -PathValue $Config -Description "config"
$resolvedBaselinePath = Resolve-ExistingPath -PathValue $BaselinePath -Description "baseline"
$resolvedReportTemplate = Resolve-ExistingPath -PathValue $ReportTemplate -Description "report template"

[void][System.IO.Directory]::CreateDirectory($OutputDirectory)
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$results = [System.Collections.Generic.List[object]]::new()

foreach ($format in ($ReportFormat | Select-Object -Unique))
{
    $extension = Get-ReportExtension -Format $format
    $baseName = "gitleaks-$Mode.$extension"
    $reportPath = Join-Path $resolvedOutputDirectory $baseName
    $stdoutPath = Join-Path $resolvedOutputDirectory "$baseName.stdout.txt"
    $stderrPath = Join-Path $resolvedOutputDirectory "$baseName.stderr.txt"
    $arguments = New-GitleaksArguments `
        -Format $format `
        -ReportPath $reportPath `
        -ResolvedSource $resolvedSource `
        -ResolvedConfig $resolvedConfig `
        -ResolvedBaselinePath $resolvedBaselinePath `
        -ResolvedReportTemplate $resolvedReportTemplate
    $result = Invoke-ExternalProcess -FilePath $gitleaksExecutable -Arguments $arguments -StandardInputPath $resolvedStdinPath

    [System.IO.File]::WriteAllText($stdoutPath, $result.Stdout)
    [System.IO.File]::WriteAllText($stderrPath, $result.Stderr)

    if ($result.ExitCode -gt 1 -or ($FailOnFindings -and $result.ExitCode -ne 0))
    {
        throw "Gitleaks exited with code $($result.ExitCode) for format '$format'. See '$stderrPath'."
    }

    $results.Add([pscustomobject]@{
        Format = $format
        ExitCode = $result.ExitCode
        Arguments = $arguments
        ReportPath = $reportPath
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    })
}

$metadataPath = Join-Path $resolvedOutputDirectory "metadata.json"
$metadata = [pscustomobject]@{
    Tool = "gitleaks"
    ToolVersion = $gitleaksVersion
    Binary = $gitleaksExecutable
    Clone = $gitleaksClone
    Mode = $Mode
    Source = $resolvedSource
    StdinPath = $resolvedStdinPath
    Config = $resolvedConfig
    BaselinePath = $resolvedBaselinePath
    ReportTemplate = $resolvedReportTemplate
    AdditionalArguments = $AdditionalArguments
    CapturedUtc = [DateTimeOffset]::UtcNow.ToString("O")
    Results = $results.ToArray()
}

$metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $metadataPath -Encoding utf8NoBOM
Write-Host "Captured Gitleaks oracle reports in '$resolvedOutputDirectory'."
