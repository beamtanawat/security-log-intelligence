[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedRawHash = "EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D"
$expectedRecordCount = 100000
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$rawDataset = Join-Path $repositoryRoot "data\raw\network_log_SAFE.csv"
$processedDirectory = Join-Path $repositoryRoot "data\processed"
$normalizationCli = Join-Path $repositoryRoot "src\normalize_dataset.py"
$auditCli = Join-Path $repositoryRoot "src\audit_normalized_output.py"
$testsDirectory = Join-Path $repositoryRoot "tests"
$primaryOutput = Join-Path $processedDirectory "stage_1_3f_normalized_events.jsonl"
$summaryOutput = Join-Path $processedDirectory "stage_1_3f_normalization_summary.json"
$determinismOutput = Join-Path $processedDirectory ".stage_1_3f_determinism.jsonl"

function Fail-Validation {
    param([string]$Gate, [string]$Message)
    throw "${Gate}: ${Message}"
}

function Require-Path {
    param([string]$Path, [string]$Description, [switch]$Directory)
    $pathType = if ($Directory) { "Container" } else { "Leaf" }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        Fail-Validation "Environment" "Required ${Description} is missing: ${Path}"
    }
}

function Require-LastExitCode {
    param([string]$Gate, [string]$CommandDescription)
    if ($LASTEXITCODE -ne 0) {
        Fail-Validation $Gate "${CommandDescription} exited with code ${LASTEXITCODE}."
    }
}

function Convert-CommandJson {
    param([object[]]$Output, [string]$Gate)
    $jsonText = ($Output | Out-String).Trim()
    try {
        return $jsonText | ConvertFrom-Json
    }
    catch {
        Fail-Validation $Gate "Command did not produce one valid JSON summary."
    }
}

function Assert-JsonEqual {
    param([object]$Expected, [object]$Actual, [string]$Description)
    $expectedJson = $Expected | ConvertTo-Json -Depth 8 -Compress
    $actualJson = $Actual | ConvertTo-Json -Depth 8 -Compress
    if ($expectedJson -ne $actualJson) {
        Fail-Validation "Output Validation" "${Description} does not match the streaming audit."
    }
}

function Invoke-Normalization {
    param([string]$OutputPath)
    $commandOutput = & $python $normalizationCli --source fortigate --input $rawDataset --output $OutputPath 2>&1
    Require-LastExitCode "Real Dataset Normalization" "Stage 1.3 normalization CLI"
    return Convert-CommandJson $commandOutput "Real Dataset Normalization"
}

function Invoke-OutputAudit {
    param([string]$OutputPath)
    $commandOutput = & $python $auditCli --input $OutputPath --expected-record-count $expectedRecordCount 2>&1
    Require-LastExitCode "Output Validation" "Normalized JSON Lines audit"
    return Convert-CommandJson $commandOutput "Output Validation"
}

function Assert-RunSummary {
    param([object]$RunSummary, [object]$AuditSummary, [string]$Label)
    if ($RunSummary.input_record_count -ne $expectedRecordCount -or
        $RunSummary.valid_record_count -ne $expectedRecordCount -or
        $RunSummary.output_record_count -ne $expectedRecordCount -or
        $RunSummary.malformed_record_count -ne 0) {
        Fail-Validation "Output Validation" "${Label} run summary does not reconcile to ${expectedRecordCount} valid records and zero malformed records."
    }
    if ($AuditSummary.output_record_count -ne $expectedRecordCount) {
        Fail-Validation "Output Validation" "${Label} JSON Lines audit does not contain ${expectedRecordCount} records."
    }
    Assert-JsonEqual $RunSummary.mapping_coverage $AuditSummary.mapping_coverage "${Label} mapping coverage"
    Assert-JsonEqual $RunSummary.issue_counts $AuditSummary.issue_counts "${Label} issue counts"
    Assert-JsonEqual $RunSummary.unknown_field_names $AuditSummary.unknown_field_names "${Label} unknown field names"
}

$exitCode = 0
$determinismOutputCreated = $false
Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "========================================"
    Write-Host "Stage 1.3F Local Validation"
    Write-Host "========================================"

    Write-Host "`n[1/10] Environment and paths"
    Require-Path $python "Python virtual environment runtime"
    $pythonVersion = (& $python --version 2>&1 | Out-String).Trim()
    Require-LastExitCode "Environment" "Python version check"
    if ($pythonVersion -notmatch "^Python 3\.12\.") {
        Fail-Validation "Environment" "Python 3.12 is required; found '${pythonVersion}'."
    }
    Require-Path $rawDataset "raw dataset"
    Require-Path $processedDirectory "processed-data directory" -Directory
    Require-Path $normalizationCli "normalization CLI"
    Require-Path $auditCli "normalized-output audit"
    Require-Path $testsDirectory "tests directory" -Directory
    foreach ($path in @($primaryOutput, $summaryOutput, $determinismOutput)) {
        if (Test-Path -LiteralPath $path) {
            Fail-Validation "Output Safety" "Validation artifact already exists and will not be overwritten: ${path}"
        }
    }
    Write-Host "Python: $pythonVersion"
    Write-Host "Environment: PASS"

    Write-Host "`n[2/10] Git safety before run"
    $trackedDataFiles = @(git -c "safe.directory=$repositoryRoot" -C $repositoryRoot ls-files --stage -- data/raw data/processed)
    Require-LastExitCode "Git Safety" "git ls-files for raw and processed data"
    if ($trackedDataFiles.Count -ne 0) {
        Fail-Validation "Git Safety" "Raw or processed data is tracked or staged."
    }
    Write-Host "Raw/Processed Git Safety Before: PASS"

    Write-Host "`n[3/10] Complete test suite before real-data run"
    & $python -m unittest discover -s $testsDirectory -v
    Require-LastExitCode "Full Tests" "Complete unittest suite before real-data run"
    Write-Host "Full Tests Before: PASS"

    Write-Host "`n[4/10] Raw integrity before normalization"
    $rawFileBefore = Get-Item -LiteralPath $rawDataset
    $rawHashBefore = (Get-FileHash -LiteralPath $rawDataset -Algorithm SHA256).Hash
    if ($rawHashBefore -ne $expectedRawHash) {
        Fail-Validation "Raw Data Integrity" "RAW DATA INTEGRITY FAILURE before normalization."
    }
    Write-Host "Raw size before: $($rawFileBefore.Length) bytes"
    Write-Host "Raw SHA-256 before: $rawHashBefore"

    Write-Host "`n[5/10] Primary real-data normalization"
    $primaryRun = Invoke-Normalization $primaryOutput
    $primaryAudit = Invoke-OutputAudit $primaryOutput
    Assert-RunSummary $primaryRun $primaryAudit "Primary"
    $primaryOutputFile = Get-Item -LiteralPath $primaryOutput
    $primaryOutputHash = (Get-FileHash -LiteralPath $primaryOutput -Algorithm SHA256).Hash
    Write-Host "Primary records: $($primaryAudit.output_record_count)"
    Write-Host "Primary output size: $($primaryOutputFile.Length) bytes"
    Write-Host "Primary output SHA-256: $primaryOutputHash"
    Write-Host "Primary normalization and audit: PASS"

    Write-Host "`n[6/10] Determinism normalization"
    $determinismRun = Invoke-Normalization $determinismOutput
    $determinismOutputCreated = $true
    $determinismAudit = Invoke-OutputAudit $determinismOutput
    Assert-RunSummary $determinismRun $determinismAudit "Determinism"
    $determinismOutputHash = (Get-FileHash -LiteralPath $determinismOutput -Algorithm SHA256).Hash
    if ($primaryOutputHash -ne $determinismOutputHash) {
        Fail-Validation "Determinism" "The two normalized outputs have different SHA-256 hashes."
    }
    Remove-Item -LiteralPath $determinismOutput -Force
    $determinismOutputCreated = $false
    Write-Host "Determinism SHA-256: $determinismOutputHash"
    Write-Host "Determinism: PASS"

    Write-Host "`n[7/10] Raw integrity after normalization"
    $rawFileAfter = Get-Item -LiteralPath $rawDataset
    $rawHashAfter = (Get-FileHash -LiteralPath $rawDataset -Algorithm SHA256).Hash
    if ($rawHashBefore -ne $rawHashAfter -or
        $rawHashAfter -ne $expectedRawHash -or
        $rawFileBefore.Length -ne $rawFileAfter.Length) {
        Fail-Validation "Raw Data Integrity" "RAW DATA INTEGRITY FAILURE after normalization."
    }
    Write-Host "Raw size after: $($rawFileAfter.Length) bytes"
    Write-Host "Raw SHA-256 after: $rawHashAfter"
    Write-Host "Raw Integrity: PASS"

    Write-Host "`n[8/10] Complete test suite after real-data run"
    & $python -m unittest discover -s $testsDirectory -v
    Require-LastExitCode "Full Tests" "Complete unittest suite after real-data run"
    Write-Host "Full Tests After: PASS"

    Write-Host "`n[9/10] Diff and Git safety"
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot diff --check
    Require-LastExitCode "git diff --check" "git diff --check"
    $trackedDataFiles = @(git -c "safe.directory=$repositoryRoot" -C $repositoryRoot ls-files --stage -- data/raw data/processed)
    Require-LastExitCode "Git Safety" "git ls-files for raw and processed data"
    if ($trackedDataFiles.Count -ne 0) {
        Fail-Validation "Git Safety" "Raw or processed data is tracked or staged."
    }
    if (Test-Path -LiteralPath $determinismOutput) {
        Fail-Validation "Output Safety" "Determinism temporary artifact remains after validation."
    }
    Write-Host "git diff --check: PASS"
    Write-Host "Raw/Processed Git Safety After: PASS"

    Write-Host "`n[10/10] Write bounded validation summary"
    $validationSummary = [ordered]@{
        validation_stage = "1.3F"
        raw = [ordered]@{
            path = $rawDataset
            file_size_bytes_before = $rawFileBefore.Length
            file_size_bytes_after = $rawFileAfter.Length
            sha256_before = $rawHashBefore
            sha256_after = $rawHashAfter
        }
        primary_run = $primaryRun
        primary_output = [ordered]@{
            path = $primaryOutput
            file_size_bytes = $primaryOutputFile.Length
            sha256 = $primaryOutputHash
        }
        primary_audit = $primaryAudit
        determinism = [ordered]@{
            secondary_output_sha256 = $determinismOutputHash
            hashes_match = $true
            temporary_output_removed = $true
        }
        verdict = "PASS"
    }
    $validationSummary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryOutput -Encoding utf8
    Write-Host "Summary: $summaryOutput"
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
    if ($determinismOutputCreated -and (Test-Path -LiteralPath $determinismOutput)) {
        Remove-Item -LiteralPath $determinismOutput -Force
    }
    Pop-Location
}

exit $exitCode
