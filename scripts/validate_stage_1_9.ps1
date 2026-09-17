[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FeaturesDir,

    [Parameter(Mandatory = $true)]
    [string]$ScoresDir,

    [Parameter(Mandatory = $true)]
    [string]$ExplanationsDir,

    [Parameter(Mandatory = $true)]
    [string]$AutoTriageDir
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

function Invoke-Stage19Native {
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

$features = (Resolve-Path -LiteralPath $FeaturesDir -ErrorAction Stop).Path
$scores = (Resolve-Path -LiteralPath $ScoresDir -ErrorAction Stop).Path
$explanations = (Resolve-Path -LiteralPath $ExplanationsDir -ErrorAction Stop).Path
$autoTriage = (Resolve-Path -LiteralPath $AutoTriageDir -ErrorAction Stop).Path
$featurePath = Join-Path $features "stage_1_7_ai_features.jsonl"
$featureMetadataPath = Join-Path $features "stage_1_7_ai_feature_metadata.json"
$scorePath = Join-Path $scores "stage_1_8_anomaly_scores.jsonl"
$manifestPath = Join-Path $scores "stage_1_8_manifest.json"
$metadata = Get-Content -LiteralPath $featureMetadataPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
$normalized = [string]$metadata.normalized_input.path
$findings = Join-Path $projectRoot "data\processed\stage_1_4f_detection_findings.jsonl"
$summary = Join-Path $projectRoot "data\processed\stage_1_4f_detection_summary.json"

foreach ($required in @($normalized, $findings, $summary)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required immutable Stage 1.9 input is unavailable: $required"
    }
}

if ($metadata.feature_artifact.sha256 -cne "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1") {
    throw "Stage 1.7 feature SHA-256 does not match the approved identity"
}
if ((Get-FileHash -LiteralPath $scorePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne "f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4") {
    throw "Stage 1.8 score SHA-256 does not match the approved identity"
}
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne "9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77") {
    throw "Stage 1.8 manifest SHA-256 does not match the approved identity"
}

$hashesBefore = @{}
foreach ($path in @($normalized, $featurePath, $featureMetadataPath, $scorePath, $manifestPath, $findings, $summary)) {
    $hashesBefore[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

Invoke-Stage19Native $python "-m" "pip" "check"
Invoke-Stage19Native $python "-m" "unittest" "discover" "-s" "tests" "-p" "test_*.py" "-v"
Invoke-Stage19Native $python "-m" "pytest" "tests" "-q"
Invoke-Stage19Native $python ".\src\audit_ai_features.py" "--bundle" $features "--normalized" $normalized
Invoke-Stage19Native $python ".\src\audit_anomaly_scores.py" "--features-dir" $features "--scores-dir" $scores "--approved-manifest-sha256" "9c00081f8e18a092ed8a545b680495820c3514ccef57d78bdf0906804992be77"
Invoke-Stage19Native $python ".\src\audit_explainability.py" "--bundle" $explanations "--auto-triage-dir" $autoTriage "--features-dir" $features "--scores-dir" $scores "--normalized" $normalized "--findings" $findings "--summary" $summary

$processedRoot = Join-Path $projectRoot "data\processed"
$rerun = Join-Path $processedRoot (".stage_1_9_validator_" + [guid]::NewGuid().ToString("N"))
$rerunAutoTriage = Join-Path $processedRoot (".stage_1_9_auto_triage_validator_" + [guid]::NewGuid().ToString("N"))
try {
    Invoke-Stage19Native $python ".\src\explain_anomalies.py" "--features-dir" $features "--scores-dir" $scores "--normalized" $normalized "--findings" $findings "--summary" $summary "--output-dir" $rerun
    Invoke-Stage19Native $python ".\src\audit_explainability.py" "--bundle" $rerun "--features-dir" $features "--scores-dir" $scores "--normalized" $normalized "--findings" $findings "--summary" $summary
    Invoke-Stage19Native $python ".\src\auto_triage.py" "--explanations-dir" $rerun "--output-dir" $rerunAutoTriage
    Invoke-Stage19Native $python ".\src\audit_explainability.py" "--bundle" $rerun "--auto-triage-dir" $rerunAutoTriage
    foreach ($name in @("stage_1_9_explained_anomalies.jsonl", "stage_1_9_analyst_review_queue.csv")) {
        $publishedHash = (Get-FileHash -LiteralPath (Join-Path $explanations $name) -Algorithm SHA256).Hash
        $rerunHash = (Get-FileHash -LiteralPath (Join-Path $rerun $name) -Algorithm SHA256).Hash
        if ($publishedHash -cne $rerunHash) {
            throw "Stage 1.9 deterministic artifact hash mismatch: $name"
        }
    }
    foreach ($name in @("stage_1_9_auto_triage.csv", "stage_1_9_top_anomalies.csv", "stage_1_9_summary.json")) {
        $publishedHash = (Get-FileHash -LiteralPath (Join-Path $autoTriage $name) -Algorithm SHA256).Hash
        $rerunHash = (Get-FileHash -LiteralPath (Join-Path $rerunAutoTriage $name) -Algorithm SHA256).Hash
        if ($publishedHash -cne $rerunHash) {
            throw "Stage 1.9 deterministic auto-triage artifact hash mismatch: $name"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $rerun) {
        Remove-Item -LiteralPath $rerun -Recurse -Force
    }
    if (Test-Path -LiteralPath $rerunAutoTriage) {
        Remove-Item -LiteralPath $rerunAutoTriage -Recurse -Force
    }
}

foreach ($path in $hashesBefore.Keys) {
    if ($hashesBefore[$path] -cne (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash) {
        throw "Immutable Stage 1.9 input changed during validation: $path"
    }
}

git diff --check
if ($LASTEXITCODE -ne 0) {
    throw "git diff --check failed"
}
$trackedData = git ls-files -- "data/raw/network_log_SAFE.csv" "data/processed"
if ($LASTEXITCODE -ne 0 -or $trackedData) {
    throw "Raw or processed data is tracked by Git"
}

Write-Output "STAGE 1.9 LOCAL VALIDATION PASS"
