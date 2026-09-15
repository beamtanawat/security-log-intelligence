[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NormalizedInput,

    [Parameter(Mandatory = $true)]
    [string]$FeaturesDir,

    [Parameter(Mandatory = $true)]
    [string]$ScoresDir,

    [Parameter(Mandatory = $true)]
    [string]$ApprovedManifestSha256
)

$ErrorActionPreference = "Stop"
if ($ApprovedManifestSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "ApprovedManifestSha256 must contain exactly 64 hexadecimal characters"
}
$ApprovedManifestSha256 = $ApprovedManifestSha256.ToLowerInvariant()

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

function Invoke-Stage18Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Program,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code ${LASTEXITCODE}: $Program $($Arguments -join ' ')"
    }
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Project Python was not found: $python"
}

$normalized = (Resolve-Path -LiteralPath $NormalizedInput -ErrorAction Stop).Path
$features = (Resolve-Path -LiteralPath $FeaturesDir -ErrorAction Stop).Path
$scores = (Resolve-Path -LiteralPath $ScoresDir -ErrorAction Stop).Path
$normalizedHashBefore = (Get-FileHash -LiteralPath $normalized -Algorithm SHA256).Hash
$featuresHashBefore = (Get-FileHash -LiteralPath (Join-Path $features "stage_1_7_ai_features.jsonl") -Algorithm SHA256).Hash
$metadataHashBefore = (Get-FileHash -LiteralPath (Join-Path $features "stage_1_7_ai_feature_metadata.json") -Algorithm SHA256).Hash

Invoke-Stage18Native $python "-m" "pip" "check"
Invoke-Stage18Native $python "-m" "unittest" "discover" "-s" "tests" "-p" "test_*.py" "-v"
Invoke-Stage18Native $python "-m" "pytest" "tests" "-q"

# This must succeed before any Stage 1.8 model is constructed.  It is the
# complete Stage 1.7 reconciliation against the immutable normalized JSONL.
Invoke-Stage18Native $python ".\src\audit_ai_features.py" "--bundle" $features "--normalized" $normalized

$metadataPath = Join-Path $features "stage_1_7_ai_feature_metadata.json"
$metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop

if ($metadata.feature_artifact.sha256 -cne "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1") {
    throw "Stage 1.7 feature SHA-256 does not match the approved identity"
}
if ($metadata.feature_artifact.row_count -ne 100000) {
    throw "Stage 1.7 feature row count is incompatible"
}
if ($metadata.feature_names.Count -ne 36) {
    throw "Stage 1.7 feature count is incompatible"
}
if ($metadata.split.counts.REFERENCE -ne 79947) {
    throw "Stage 1.7 REFERENCE partition count is incompatible"
}
if ($metadata.split.counts.HOLDOUT -ne 20053) {
    throw "Stage 1.7 HOLDOUT partition count is incompatible"
}

Invoke-Stage18Native $python ".\src\audit_anomaly_scores.py" "--features-dir" $features "--scores-dir" $scores "--approved-manifest-sha256" $ApprovedManifestSha256

$processedRoot = Join-Path $projectRoot "data\processed"
$rerun = Join-Path $processedRoot (".stage_1_8_validator_" + [guid]::NewGuid().ToString("N"))
try {
    Invoke-Stage18Native $python ".\src\score_anomalies.py" "--features-dir" $features "--output-dir" $rerun
    $rerunManifest = Join-Path $rerun "stage_1_8_manifest.json"
    $rerunManifestHash = (Get-FileHash -LiteralPath $rerunManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($rerunManifestHash -cne $ApprovedManifestSha256) {
        throw "Controlled rebuild manifest SHA-256 does not match the external approved identity"
    }
    Invoke-Stage18Native $python ".\src\audit_anomaly_scores.py" "--features-dir" $features "--scores-dir" $rerun "--approved-manifest-sha256" $ApprovedManifestSha256
    $publishedScoreHash = (Get-FileHash -LiteralPath (Join-Path $scores "stage_1_8_anomaly_scores.jsonl") -Algorithm SHA256).Hash
    $rerunScoreHash = (Get-FileHash -LiteralPath (Join-Path $rerun "stage_1_8_anomaly_scores.jsonl") -Algorithm SHA256).Hash
    if ($publishedScoreHash -ne $rerunScoreHash) {
        throw "Primary deterministic score payload hash mismatch"
    }
}
finally {
    if (Test-Path -LiteralPath $rerun) {
        Remove-Item -LiteralPath $rerun -Recurse -Force
    }
}

if ($normalizedHashBefore -ne (Get-FileHash -LiteralPath $normalized -Algorithm SHA256).Hash) {
    throw "Normalized input changed during validation"
}
if ($featuresHashBefore -ne (Get-FileHash -LiteralPath (Join-Path $features "stage_1_7_ai_features.jsonl") -Algorithm SHA256).Hash) {
    throw "Stage 1.7 feature artifact changed during validation"
}
if ($metadataHashBefore -ne (Get-FileHash -LiteralPath (Join-Path $features "stage_1_7_ai_feature_metadata.json") -Algorithm SHA256).Hash) {
    throw "Stage 1.7 feature metadata changed during validation"
}

git diff --check
if ($LASTEXITCODE -ne 0) {
    throw "git diff --check failed"
}
$trackedData = git ls-files -- "data/raw/network_log_SAFE.csv" "data/processed"
if ($LASTEXITCODE -ne 0 -or $trackedData) {
    throw "Raw or processed data is tracked by Git"
}

Write-Output "STAGE 1.8 LOCAL VALIDATION PASS"
