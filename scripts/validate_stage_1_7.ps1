[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NormalizedInput,

    [Parameter(Mandatory = $true)]
    [string]$Bundle
)

# Local-only Stage 1.7 validation.  It reads the named normalized input and
# existing bundle, then owns and removes exactly one temporary sibling rerun.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$processedRoot = (Resolve-Path (Join-Path $repositoryRoot "data\processed")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$resolvedInput = (Resolve-Path $NormalizedInput).Path
$resolvedBundle = (Resolve-Path $Bundle).Path
$processedPrefix = $processedRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project Python interpreter is unavailable: $python"
}
if (-not $resolvedInput.StartsWith($processedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Normalized input must resolve beneath data/processed."
}
if (-not $resolvedBundle.StartsWith($processedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Feature bundle must resolve beneath data/processed."
}

function Invoke-PythonChecked {
    param([string[]]$Arguments)
    & $python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed with exit code $LASTEXITCODE."
    }
}

function Get-RequiredHash {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected file is missing: $Path"
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$inputHashBefore = Get-RequiredHash $resolvedInput
$temporaryBundle = Join-Path $processedRoot (".stage_1_7_validation." + [guid]::NewGuid().ToString("N") + ".tmp")

try {
    Invoke-PythonChecked @("--version")
    Invoke-PythonChecked @("-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v")
    Invoke-PythonChecked @("-m", "pytest", "tests", "-q")
    Invoke-PythonChecked @("src\audit_ai_features.py", "--bundle", $resolvedBundle, "--normalized", $resolvedInput)
    $metadataPath = Join-Path $resolvedBundle "stage_1_7_ai_feature_metadata.json"
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    if ($metadata.split.counts.REFERENCE -lt 4096) {
        throw "Stage 1.8 requires at least 4,096 REFERENCE records; Stage 1.7 bundle does not satisfy that gate."
    }
    Invoke-PythonChecked @("src\build_ai_features.py", "--input", $resolvedInput, "--output-dir", $temporaryBundle)
    Invoke-PythonChecked @("src\audit_ai_features.py", "--bundle", $temporaryBundle, "--normalized", $resolvedInput)

    $expectedFeature = Join-Path $resolvedBundle "stage_1_7_ai_features.jsonl"
    $expectedMetadata = Join-Path $resolvedBundle "stage_1_7_ai_feature_metadata.json"
    $rerunFeature = Join-Path $temporaryBundle "stage_1_7_ai_features.jsonl"
    $rerunMetadata = Join-Path $temporaryBundle "stage_1_7_ai_feature_metadata.json"
    if ((Get-RequiredHash $expectedFeature) -ne (Get-RequiredHash $rerunFeature)) {
        throw "Determinism validation failed: feature JSONL hashes differ."
    }
    if ((Get-RequiredHash $expectedMetadata) -ne (Get-RequiredHash $rerunMetadata)) {
        throw "Determinism validation failed: metadata hashes differ."
    }
    if ((Get-RequiredHash $resolvedInput) -ne $inputHashBefore) {
        throw "Normalized input hash changed during validation."
    }

    git diff --check
    if ($LASTEXITCODE -ne 0) { throw "git diff --check failed." }
    $trackedData = @(git ls-files -- data/raw data/processed)
    if ($LASTEXITCODE -ne 0) { throw "git ls-files data safety check failed." }
    if ($trackedData.Count -ne 0) { throw "Raw or processed data is Git-tracked." }
    git status --short
    if ($LASTEXITCODE -ne 0) { throw "git status failed." }
    Write-Output "STAGE 1.7 LOCAL VALIDATION PASS"
}
finally {
    if (Test-Path -LiteralPath $temporaryBundle) {
        Remove-Item -LiteralPath $temporaryBundle -Recurse -Force
    }
}
