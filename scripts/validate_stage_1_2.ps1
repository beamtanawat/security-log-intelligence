[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("1.2E", "1.2F", "1.2G")]
    [string]$Checkpoint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedRawHash = "EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$rawDataset = Join-Path $repositoryRoot "data\raw\network_log_SAFE.csv"
$analysisCli = Join-Path $repositoryRoot "src\analyze_data_quality.py"
$testsDirectory = Join-Path $repositoryRoot "tests"
$processedDirectory = Join-Path $repositoryRoot "data\processed"
$outputName = switch ($Checkpoint) {
    "1.2E" { "stage_1_2e_data_quality.json" }
    "1.2F" { "stage_1_2f_data_quality.json" }
    "1.2G" { "stage_1_2g_data_quality.json" }
}
$outputPath = Join-Path $processedDirectory $outputName

function Fail-Validation {
    param(
        [string]$Gate,
        [string]$Message
    )

    throw "${Gate}: ${Message}"
}

function Require-Path {
    param(
        [string]$Path,
        [string]$Description,
        [switch]$Directory
    )

    $pathType = if ($Directory) { "Container" } else { "Leaf" }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        Fail-Validation "Environment" "Required ${Description} is missing: ${Path}"
    }
}

function Require-LastExitCode {
    param(
        [string]$Gate,
        [string]$CommandDescription
    )

    if ($LASTEXITCODE -ne 0) {
        Fail-Validation $Gate "${CommandDescription} exited with code ${LASTEXITCODE}."
    }
}

$exitCode = 0
Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "========================================"
    Write-Host "Stage $Checkpoint Local Validation"
    Write-Host "========================================"

    Write-Host "`n[1/8] Environment"
    $pythonVersion = & python --version 2>&1
    Require-LastExitCode "Environment" "python --version"
    $pythonVersionText = ($pythonVersion | Out-String).Trim()
    if ($pythonVersionText -notmatch "^Python 3\.12\.") {
        Fail-Validation "Environment" "Python 3.12 is required; found '${pythonVersionText}'."
    }
    Write-Host "Python: PASS"
    Write-Host $pythonVersionText

    $pythonRuntime = & python -c "import sys; print(sys.executable); print(sys.version)" 2>&1
    Require-LastExitCode "Environment" "python runtime inspection"
    $pythonRuntime | ForEach-Object { Write-Host $_ }

    Require-Path $rawDataset "raw dataset"
    Require-Path $analysisCli "analysis CLI"
    Require-Path $testsDirectory "tests directory" -Directory

    Write-Host "`n[2/8] Raw Hash Before"
    $rawHashBefore = (Get-FileHash -LiteralPath $rawDataset -Algorithm SHA256).Hash
    Write-Host $rawHashBefore
    if ($rawHashBefore -ne $expectedRawHash) {
        Fail-Validation "Raw Data Integrity" "RAW DATA INTEGRITY FAILURE before analysis."
    }

    Write-Host "`n[3/8] Complete Test Suite"
    & python -m unittest discover -s $testsDirectory -v
    Require-LastExitCode "Full Tests" "Complete unittest suite"
    Write-Host "Full Tests: PASS"

    Write-Host "`n[4/8] Real Dataset Analysis"
    New-Item -ItemType Directory -Path $processedDirectory -Force | Out-Null
    & python $analysisCli $rawDataset --output $outputPath
    Require-LastExitCode "Real Dataset Analysis" "Read-only analysis CLI"
    Write-Host "Real Dataset Analysis: PASS"

    Write-Host "`n[5/8] Output Validation"
    Require-Path $outputPath "processed JSON output"
    $outputFile = Get-Item -LiteralPath $outputPath
    try {
        $outputJson = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json
    }
    catch {
        Fail-Validation "Output Validation" "Processed output is not valid JSON: $($_.Exception.Message)"
    }
    $topLevelNames = @($outputJson.PSObject.Properties.Name) -join ", "
    Write-Host "Output: $outputPath"
    Write-Host "Output size: $($outputFile.Length) bytes"
    Write-Host "Top-level JSON sections: $topLevelNames"

    Write-Host "`n[6/8] Raw Hash After"
    $rawHashAfter = (Get-FileHash -LiteralPath $rawDataset -Algorithm SHA256).Hash
    Write-Host $rawHashAfter
    if ($rawHashBefore -ne $rawHashAfter -or $rawHashAfter -ne $expectedRawHash) {
        Fail-Validation "Raw Data Integrity" "RAW DATA INTEGRITY FAILURE after analysis."
    }
    Write-Host "Raw Integrity: PASS"

    Write-Host "`n[7/8] Git Diff Check"
    & git diff --check
    Require-LastExitCode "git diff --check" "git diff --check"
    Write-Host "git diff --check: PASS"

    Write-Host "`n[8/8] Git Safety"
    $gitStatus = @(git status --short)
    Require-LastExitCode "Git Safety" "git status --short"
    if ($gitStatus.Count -eq 0) {
        Write-Host "git status --short: clean"
    }
    else {
        Write-Host "git status --short:"
        $gitStatus | ForEach-Object { Write-Host $_ }
    }

    $trackedDataFiles = @(git ls-files --stage -- data/raw/network_log_SAFE.csv data/processed)
    Require-LastExitCode "Git Safety" "git ls-files for raw and processed data"
    if ($trackedDataFiles.Count -ne 0) {
        Fail-Validation "Git Safety" "Raw or processed data is tracked or staged: $($trackedDataFiles -join '; ')"
    }
    Write-Host "Raw/Processed Git Safety: PASS"

    Write-Host "`n========================================"
    Write-Host "FINAL RESULT: PASS"
    Write-Host "========================================"
}
catch {
    Write-Host "`nFAILED GATE: $($_.Exception.Message)"
    Write-Host "========================================"
    Write-Host "FINAL RESULT: FAIL"
    Write-Host "========================================"
    $exitCode = 1
}
finally {
    Pop-Location
}

exit $exitCode
