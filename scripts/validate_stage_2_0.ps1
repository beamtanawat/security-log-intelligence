[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$PackageDir,
    [Parameter(Mandatory = $false)] [string]$Report,
    [Parameter(Mandatory = $false)] [string]$FeaturesDir = ".\data\processed\stage_1_7",
    [Parameter(Mandatory = $false)] [string]$ScoresDir = ".\data\processed\stage_1_8",
    [Parameter(Mandatory = $false)] [string]$ExplanationsDir = ".\data\processed\stage_1_9_corrected_v3",
    [Parameter(Mandatory = $false)] [string]$AutoTriageDir = ".\data\processed\stage_1_9_auto_triage_corrected_v3"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Project Python was not found: $python" }

$package = (Resolve-Path -LiteralPath $PackageDir -ErrorAction Stop).Path
$features = (Resolve-Path -LiteralPath $FeaturesDir -ErrorAction Stop).Path
$scores = (Resolve-Path -LiteralPath $ScoresDir -ErrorAction Stop).Path
$explanations = (Resolve-Path -LiteralPath $ExplanationsDir -ErrorAction Stop).Path
$autoTriage = (Resolve-Path -LiteralPath $AutoTriageDir -ErrorAction Stop).Path
if ($package -match "stage_1_9|stage_1_9_corrected_driver_v2") { throw "Stage 2.0 package path must not be a Stage 1.9 artifact" }

$required = @("final_anomaly_findings.jsonl", "final_anomaly_findings.csv", "analysis_summary.json", "graphs", "tables")
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $package $name))) { throw "Required package item is missing: $name" }
}

$expectedHashes = @{
    (Join-Path $features "stage_1_7_ai_features.jsonl") = "1a147b23b92588e8c35b644664cf9b58e3fbc8a5aeb5ab8def9c755ca9885fb1"
    (Join-Path $features "stage_1_7_ai_feature_metadata.json") = "b74373532d5a15de84113d57249e642311a1b3b6c6e827b8747bba94082e2ae0"
    (Join-Path $scores "stage_1_8_anomaly_scores.jsonl") = "f98188b6042dd19afb275f44c4f7a4838356210c5032b1a395b7e8a899d8e8c4"
    (Join-Path $explanations "stage_1_9_explained_anomalies.jsonl") = "4ddf062473ad84715d73c8599ac03ad3f566c79492599da7a37a6712ac2416e0"
    (Join-Path $autoTriage "stage_1_9_auto_triage.csv") = "f38079cb935619670d4cffcc3d0ce34aad99d1431f7ed3ebf47a4afc79123ade"
    (Join-Path $autoTriage "stage_1_9_summary.json") = "da18469b426a00f21f79e3f9988b210774b8f811a0d663c53a9cd91607602bac"
    (Join-Path $autoTriage "stage_1_9_top_anomalies.csv") = "9cbef506fa8a6da28947ea472e3eb67a335c17c672b768f0e3a5693601c41ea7"
}
foreach ($path in $expectedHashes.Keys) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required immutable input is missing: $path" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHashes[$path]) { throw "Immutable input hash mismatch: $path" }
}

& $python -m unittest discover -s .\tests -p "test_*.py" -v
if ($LASTEXITCODE -ne 0) { throw "Stage 2.0 regression tests failed with exit code $LASTEXITCODE" }
& $python -m pytest .\tests -q
if ($LASTEXITCODE -ne 0) { throw "Stage 2.0 pytest regression failed with exit code $LASTEXITCODE" }

$reportArgument = if ($Report) { ", report_path=r'$((Resolve-Path -LiteralPath $Report -ErrorAction Stop).Path)'" } else { "" }
& $python -c "import sys; sys.path.insert(0, r'$projectRoot\src'); from reporting.audit import audit_package, read_jsonl; import json; features=read_jsonl(r'$features\stage_1_7_ai_features.jsonl'); metadata=json.load(open(r'$features\stage_1_7_ai_feature_metadata.json', encoding='utf-8')); scores=read_jsonl(r'$scores\stage_1_8_anomaly_scores.jsonl'); print(audit_package(r'$package', feature_rows=features, feature_names=metadata['feature_names'], score_rows=scores$reportArgument))"
if ($LASTEXITCODE -ne 0) { throw "Stage 2.0 package audit failed with exit code $LASTEXITCODE" }

$trackedData = git ls-files -- "data/raw" "data/processed"
if ($LASTEXITCODE -ne 0 -or $trackedData) { throw "Raw or processed data is tracked by Git" }
git diff --check
if ($LASTEXITCODE -ne 0) { throw "git diff --check failed" }
Write-Output "STAGE 2.0 PACKAGE VALIDATION PASS"
