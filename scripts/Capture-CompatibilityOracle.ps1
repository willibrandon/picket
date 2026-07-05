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

    [string]$PicketPath = "",

    [string]$StdinPath = "",

    [string]$WorkingDirectory = "",

    [string]$LogOptions = "",

    [string]$Platform = "",

    [string[]]$AdditionalArguments = @(),

    [switch]$Staged,

    [switch]$PreCommit,

    [switch]$FollowSymlinks,

    [switch]$FailOnFindings,

    [switch]$FailOnDifference,

    [switch]$AllowMissingClone
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory))
{
    $OutputDirectory = Join-Path $repositoryRoot "artifacts\oracles\compatibility"
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

function Resolve-PicketExecutable
{
    if (![string]::IsNullOrWhiteSpace($PicketPath))
    {
        return Resolve-CommandPath -CommandPath $PicketPath -Description "Picket executable"
    }

    $configuredPath = [Environment]::GetEnvironmentVariable("PICKET_BIN")
    if (![string]::IsNullOrWhiteSpace($configuredPath))
    {
        return Resolve-CommandPath -CommandPath $configuredPath -Description "Picket executable from PICKET_BIN"
    }

    $executableName = if ($IsWindows) { "picket.exe" } else { "picket" }
    $runtimeIdentifier = [System.Runtime.InteropServices.RuntimeInformation]::RuntimeIdentifier
    $candidatePaths = @(
        (Join-Path $repositoryRoot "src\Picket.Cli\bin\Release\net10.0\$runtimeIdentifier\$executableName"),
        (Join-Path $repositoryRoot "src\Picket.Cli\bin\Debug\net10.0\$runtimeIdentifier\$executableName")
    )

    foreach ($candidatePath in $candidatePaths)
    {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf)
        {
            return (Resolve-Path -LiteralPath $candidatePath).Path
        }
    }

    throw "Could not find built Picket executable. Run dotnet build -c Release, set PICKET_BIN, or pass -PicketPath."
}

function Resolve-ExistingPath
{
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$BaseDirectory
    )

    if ([string]::IsNullOrWhiteSpace($PathValue))
    {
        return ""
    }

    $resolvedPathValue = $PathValue
    if (![System.IO.Path]::IsPathFullyQualified($PathValue))
    {
        $resolvedPathValue = Join-Path $BaseDirectory $PathValue
    }

    try
    {
        return (Resolve-Path -LiteralPath $resolvedPathValue -ErrorAction Stop).Path
    }
    catch
    {
        throw "$Description '$PathValue' does not exist."
    }
}

function Resolve-WorkingDirectory
{
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory))
    {
        return (Get-Location).Path
    }

    if (!(Test-Path -LiteralPath $WorkingDirectory -PathType Container))
    {
        throw "working directory '$WorkingDirectory' does not exist."
    }

    return (Resolve-Path -LiteralPath $WorkingDirectory).Path
}

function Invoke-ExternalProcess
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectoryPath,

        [string]$StandardInputPath = ""
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = ![string]::IsNullOrWhiteSpace($StandardInputPath)
    $startInfo.WorkingDirectory = $WorkingDirectoryPath

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

function Get-FileSha256
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (!(Test-Path -LiteralPath $Path -PathType Leaf))
    {
        return ""
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-FileBytesEqual
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$LeftPath,

        [Parameter(Mandatory = $true)]
        [string]$RightPath
    )

    if (!(Test-Path -LiteralPath $LeftPath -PathType Leaf) -or !(Test-Path -LiteralPath $RightPath -PathType Leaf))
    {
        return $false
    }

    $left = [System.IO.File]::ReadAllBytes($LeftPath)
    $right = [System.IO.File]::ReadAllBytes($RightPath)
    if ($left.Length -ne $right.Length)
    {
        return $false
    }

    for ($i = 0; $i -lt $left.Length; $i++)
    {
        if ($left[$i] -ne $right[$i])
        {
            return $false
        }
    }

    return $true
}

function New-GitleaksScriptParameters
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$GitleaksOutputDirectory
    )

    $parameters = @{
        Mode = $Mode
        OutputDirectory = $GitleaksOutputDirectory
        ReportFormat = $ReportFormat
    }

    if ($Mode -eq "stdin")
    {
        $parameters["StdinPath"] = $StdinPath
    }
    else
    {
        $parameters["Source"] = $Source
    }

    Add-OptionalParameter -Parameters $parameters -Name "Config" -Value $Config
    Add-OptionalParameter -Parameters $parameters -Name "BaselinePath" -Value $BaselinePath
    Add-OptionalParameter -Parameters $parameters -Name "ReportTemplate" -Value $ReportTemplate
    Add-OptionalParameter -Parameters $parameters -Name "GitleaksPath" -Value $GitleaksPath
    Add-OptionalParameter -Parameters $parameters -Name "WorkingDirectory" -Value $resolvedWorkingDirectory
    Add-OptionalParameter -Parameters $parameters -Name "LogOptions" -Value $LogOptions
    Add-OptionalParameter -Parameters $parameters -Name "Platform" -Value $Platform
    Add-OptionalArrayParameter -Parameters $parameters -Name "AdditionalArguments" -Value $AdditionalArguments
    Add-OptionalSwitchParameter -Parameters $parameters -Name "Staged" -Enabled $Staged
    Add-OptionalSwitchParameter -Parameters $parameters -Name "PreCommit" -Enabled $PreCommit
    Add-OptionalSwitchParameter -Parameters $parameters -Name "FollowSymlinks" -Enabled $FollowSymlinks
    Add-OptionalSwitchParameter -Parameters $parameters -Name "FailOnFindings" -Enabled $FailOnFindings
    Add-OptionalSwitchParameter -Parameters $parameters -Name "AllowMissingClone" -Enabled $AllowMissingClone
    return $parameters
}

function Add-OptionalParameter
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Value = ""
    )

    if (![string]::IsNullOrWhiteSpace($Value))
    {
        $Parameters[$Name] = $Value
    }
}

function Add-OptionalArrayParameter
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string[]]$Value = @()
    )

    if ($Value.Count -gt 0)
    {
        $Parameters[$Name] = $Value
    }
}

function Add-OptionalSwitchParameter
{
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    if ($Enabled)
    {
        $Parameters[$Name] = $true
    }
}

function New-PicketArguments
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Format,

        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CommandSource,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CommandConfig,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CommandBaselinePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CommandReportTemplate
    )

    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add($Mode)

    switch ($Mode)
    {
        "dir"
        {
            $arguments.Add($CommandSource)
            if ($FollowSymlinks)
            {
                $arguments.Add("--follow-symlinks")
            }
        }
        "git"
        {
            $arguments.Add($CommandSource)
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

    if (![string]::IsNullOrWhiteSpace($CommandConfig))
    {
        $arguments.Add("--config")
        $arguments.Add($CommandConfig)
    }

    if (![string]::IsNullOrWhiteSpace($CommandBaselinePath))
    {
        $arguments.Add("--baseline-path")
        $arguments.Add($CommandBaselinePath)
    }

    $arguments.Add("--report-format")
    $arguments.Add($Format)
    $arguments.Add("--report-path")
    $arguments.Add($ReportPath)
    $arguments.Add("--no-banner")
    $arguments.Add("--no-color")

    if (![string]::IsNullOrWhiteSpace($CommandReportTemplate))
    {
        $arguments.Add("--report-template")
        $arguments.Add($CommandReportTemplate)
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

[void][System.IO.Directory]::CreateDirectory($OutputDirectory)
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$gitleaksOutputDirectory = Join-Path $resolvedOutputDirectory "gitleaks"
$picketOutputDirectory = Join-Path $resolvedOutputDirectory "picket"
[void][System.IO.Directory]::CreateDirectory($gitleaksOutputDirectory)
[void][System.IO.Directory]::CreateDirectory($picketOutputDirectory)
$resolvedWorkingDirectory = Resolve-WorkingDirectory

$gitleaksCaptureScript = Join-Path $PSScriptRoot "Capture-GitleaksOracle.ps1"
$gitleaksScriptParameters = New-GitleaksScriptParameters -GitleaksOutputDirectory $gitleaksOutputDirectory
& $gitleaksCaptureScript @gitleaksScriptParameters

$picketExecutable = Resolve-PicketExecutable
$resolvedSource = ""
$resolvedStdinPath = ""

if ($Mode -eq "stdin")
{
    $resolvedStdinPath = Resolve-ExistingPath -PathValue $StdinPath -Description "stdin fixture" -BaseDirectory $resolvedWorkingDirectory
}
else
{
    $resolvedSource = Resolve-ExistingPath -PathValue $Source -Description "source" -BaseDirectory $resolvedWorkingDirectory
}

$resolvedConfig = Resolve-ExistingPath -PathValue $Config -Description "config" -BaseDirectory $resolvedWorkingDirectory
$resolvedBaselinePath = Resolve-ExistingPath -PathValue $BaselinePath -Description "baseline" -BaseDirectory $resolvedWorkingDirectory
$resolvedReportTemplate = Resolve-ExistingPath -PathValue $ReportTemplate -Description "report template" -BaseDirectory $resolvedWorkingDirectory
$picketResults = [System.Collections.Generic.List[object]]::new()

foreach ($format in ($ReportFormat | Select-Object -Unique))
{
    $extension = Get-ReportExtension -Format $format
    $baseName = "picket-$Mode.$extension"
    $reportPath = Join-Path $picketOutputDirectory $baseName
    $stdoutPath = Join-Path $picketOutputDirectory "$baseName.stdout.txt"
    $stderrPath = Join-Path $picketOutputDirectory "$baseName.stderr.txt"
    $arguments = New-PicketArguments `
        -Format $format `
        -ReportPath $reportPath `
        -CommandSource $Source `
        -CommandConfig $Config `
        -CommandBaselinePath $BaselinePath `
        -CommandReportTemplate $ReportTemplate
    $result = Invoke-ExternalProcess -FilePath $picketExecutable -Arguments $arguments -WorkingDirectoryPath $resolvedWorkingDirectory -StandardInputPath $resolvedStdinPath

    [System.IO.File]::WriteAllText($stdoutPath, $result.Stdout)
    [System.IO.File]::WriteAllText($stderrPath, $result.Stderr)

    if ($result.ExitCode -gt 1 -or ($FailOnFindings -and $result.ExitCode -ne 0))
    {
        throw "Picket exited with code $($result.ExitCode) for format '$format'. See '$stderrPath'."
    }

    $picketResults.Add([pscustomobject]@{
        Format = $format
        ExitCode = $result.ExitCode
        Arguments = $arguments
        ReportPath = $reportPath
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    })
}

$gitleaksMetadataPath = Join-Path $gitleaksOutputDirectory "metadata.json"
$gitleaksMetadata = Get-Content -Raw -LiteralPath $gitleaksMetadataPath | ConvertFrom-Json
$comparisons = [System.Collections.Generic.List[object]]::new()

foreach ($picketResult in $picketResults)
{
    $format = $picketResult.Format
    $extension = Get-ReportExtension -Format $format
    $gitleaksResult = $gitleaksMetadata.Results | Where-Object { $_.Format -eq $format } | Select-Object -First 1
    $gitleaksReportPath = Join-Path $gitleaksOutputDirectory "gitleaks-$Mode.$extension"
    $gitleaksStdoutPath = Join-Path $gitleaksOutputDirectory "gitleaks-$Mode.$extension.stdout.txt"
    $gitleaksStderrPath = Join-Path $gitleaksOutputDirectory "gitleaks-$Mode.$extension.stderr.txt"

    $comparisons.Add([pscustomobject]@{
        Format = $format
        ExitCodeEqual = $gitleaksResult.ExitCode -eq $picketResult.ExitCode
        ReportBytesEqual = Test-FileBytesEqual -LeftPath $gitleaksReportPath -RightPath $picketResult.ReportPath
        StdoutBytesEqual = Test-FileBytesEqual -LeftPath $gitleaksStdoutPath -RightPath $picketResult.StdoutPath
        StderrBytesEqual = Test-FileBytesEqual -LeftPath $gitleaksStderrPath -RightPath $picketResult.StderrPath
        GitleaksExitCode = $gitleaksResult.ExitCode
        PicketExitCode = $picketResult.ExitCode
        GitleaksReportPath = $gitleaksReportPath
        PicketReportPath = $picketResult.ReportPath
        GitleaksReportSha256 = Get-FileSha256 -Path $gitleaksReportPath
        PicketReportSha256 = Get-FileSha256 -Path $picketResult.ReportPath
        GitleaksStdoutPath = $gitleaksStdoutPath
        PicketStdoutPath = $picketResult.StdoutPath
        GitleaksStderrPath = $gitleaksStderrPath
        PicketStderrPath = $picketResult.StderrPath
    })
}

$comparisonPath = Join-Path $resolvedOutputDirectory "comparison.json"
$metadata = [pscustomobject]@{
    Tool = "picket-compatibility-oracle"
    Mode = $Mode
    WorkingDirectory = $resolvedWorkingDirectory
    Source = $resolvedSource
    StdinPath = $resolvedStdinPath
    Config = $resolvedConfig
    BaselinePath = $resolvedBaselinePath
    ReportTemplate = $resolvedReportTemplate
    GitleaksMetadataPath = $gitleaksMetadataPath
    PicketBinary = $picketExecutable
    PicketResults = $picketResults.ToArray()
    CapturedUtc = [DateTimeOffset]::UtcNow.ToString("O")
    Comparisons = $comparisons.ToArray()
}

$metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $comparisonPath -Encoding utf8NoBOM

if ($FailOnDifference)
{
    foreach ($comparison in $comparisons)
    {
        if (!$comparison.ExitCodeEqual -or !$comparison.ReportBytesEqual)
        {
            throw "Compatibility oracle differs for format '$($comparison.Format)'. See '$comparisonPath'."
        }
    }
}

Write-Host "Captured compatibility oracle bundle in '$resolvedOutputDirectory'."
