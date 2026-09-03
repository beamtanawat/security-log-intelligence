[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedRawHash = "EEBAFC6C16107F73622AEDA411E882A4E448B19BECD659114FF640F6CAD3BB9D"
$expectedNormalizedHash = "C195C6322665530D56F1BD5390B6B1C20728881A21EE36352C7C46E0A7138976"
$expectedNormalizedSizeBytes = [int64]907375745
$expectedRecordCount = 100000
$expectedFindingCount = 43
$expectedUniqueMatchedRecordCount = 25
$expectedRuleCounts = [ordered]@{
    "fortigate.anomaly_subtype_observation" = 18
    "fortigate.source_threat_observation" = 25
}
$expectedSeverityCounts = [ordered]@{
    "INFORMATIONAL" = 43
}
$expectedActiveRules = @(
    [ordered]@{
        rule_id = "fortigate.anomaly_subtype_observation"
        version = "1.0"
    }
    [ordered]@{
        rule_id = "fortigate.source_threat_observation"
        version = "1.0"
    }
)

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$rawDataset = Join-Path $repositoryRoot "data\raw\network_log_SAFE.csv"
$processedDirectory = Join-Path $repositoryRoot "data\processed"
$normalizedInput = Join-Path $processedDirectory "stage_1_3f_normalized_events.jsonl"
$detectionCli = Join-Path $repositoryRoot "src\evaluate_detections.py"
$testsDirectory = Join-Path $repositoryRoot "tests"
$primaryFindingsOutput = Join-Path $processedDirectory "stage_1_4f_detection_findings.jsonl"
$summaryOutput = Join-Path $processedDirectory "stage_1_4f_detection_summary.json"
$temporarySummaryOutput = Join-Path $processedDirectory (
    ".stage_1_4f_detection_summary.{0}.tmp" -f [guid]::NewGuid().ToString("N")
)
$determinismFindingsOutput = Join-Path $processedDirectory (
    ".stage_1_4f_determinism.{0}.jsonl" -f [guid]::NewGuid().ToString("N")
)

# The Stage 1.4E audit is deliberately a public Python function rather than a
# second command-line interface. This small bridge rehydrates the bounded CLI
# summary and asks the audit to verify every finding against its normalized input.
# It is written to a temporary file at runtime instead of being passed through
# ``python -c``: Windows PowerShell native argument handling can change embedded
# Python quotation marks in a multiline command argument.
$auditBridge = @'
import json
import sys
from pathlib import Path


def main() -> int:
    repository_root = Path(sys.argv[1])
    findings_path = Path(sys.argv[2])
    sys.path.insert(0, str(repository_root / "src"))

    from audit_detection_output import audit_detection_jsonl
    from detection.models import ActiveRuleVersion, DetectionRunSummary, FindingSample

    summary_data = json.load(sys.stdin)
    run_summary = DetectionRunSummary(
        input_path=summary_data["input_path"],
        output_path=summary_data["output_path"],
        normalized_input_schema_version=summary_data["normalized_input_schema_version"],
        normalized_input_record_count=summary_data["normalized_input_record_count"],
        evaluated_record_count=summary_data["evaluated_record_count"],
        invalid_input_count=summary_data["invalid_input_count"],
        total_finding_count=summary_data["total_finding_count"],
        findings_by_rule_id=summary_data["findings_by_rule_id"],
        findings_by_rule_severity=summary_data["findings_by_rule_severity"],
        unique_matched_source_record_count=(
            summary_data["unique_matched_source_record_count"]
        ),
        sample_findings_by_rule={
            rule_id: tuple(
                FindingSample(
                    finding_id=sample["finding_id"],
                    source_record_number=sample["source_record_number"],
                )
                for sample in samples
            )
            for rule_id, samples in summary_data["sample_findings_by_rule"].items()
        },
        active_rules=tuple(
            ActiveRuleVersion(
                rule_id=active_rule["rule_id"], version=active_rule["version"]
            )
            for active_rule in summary_data["active_rules"]
        ),
        finding_schema_version=summary_data["finding_schema_version"],
    )
    audit = audit_detection_jsonl(findings_path, run_summary)
    print(json.dumps(audit.to_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
'@

function Fail-Validation {
    param([string]$Gate, [string]$Message)
    throw "${Gate}: ${Message}"
}

function Fail-SecurityReview {
    param([string]$Message)
    throw "NEEDS SECURITY REVIEW: ${Message}"
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
    if (-not $jsonText.StartsWith("{")) {
        Fail-Validation $Gate "Command did not produce exactly one JSON object summary."
    }
    try {
        $parsedValues = @($jsonText | ConvertFrom-Json)
    }
    catch {
        Fail-Validation $Gate "Command did not produce one valid JSON summary."
    }
    if ($parsedValues.Count -ne 1 -or -not ($parsedValues[0] -is [pscustomobject])) {
        Fail-Validation $Gate "Command did not produce exactly one JSON object summary."
    }
    return $parsedValues[0]
}

function Assert-JsonEqual {
    param([object]$Expected, [object]$Actual, [string]$Description)

    $expectedJson = $Expected | ConvertTo-Json -Depth 12 -Compress
    $actualJson = $Actual | ConvertTo-Json -Depth 12 -Compress
    if ($expectedJson -ne $actualJson) {
        Fail-Validation "Output Validation" "${Description} does not reconcile."
    }
}

function Assert-CountMapping {
    param(
        [object]$Actual,
        [System.Collections.IDictionary]$Expected,
        [string]$Description
    )

    if ($null -eq $Actual) {
        Fail-Validation "Output Validation" "${Description} is missing."
    }

    $actualNames = @($Actual.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @($Expected.Keys | Sort-Object)
    if (@(Compare-Object $actualNames $expectedNames).Count -ne 0) {
        Fail-Validation "Output Validation" "${Description} has unexpected keys."
    }

    foreach ($name in $expectedNames) {
        $actualProperty = $Actual.PSObject.Properties[$name]
        if ($null -eq $actualProperty -or [int64]$actualProperty.Value -ne [int64]$Expected[$name]) {
            Fail-Validation "Output Validation" "${Description} does not contain the expected count for ${name}."
        }
    }
}

function Assert-CountMappingShape {
    param(
        [object]$Actual,
        [string[]]$AllowedNames,
        [string]$Description
    )

    if ($null -eq $Actual) {
        Fail-Validation "Output Validation" "${Description} is missing."
    }

    foreach ($property in $Actual.PSObject.Properties) {
        if ($AllowedNames -notcontains $property.Name) {
            Fail-Validation "Output Validation" "${Description} has an unsupported key: $($property.Name)."
        }
        if ($property.Value -is [bool]) {
            Fail-Validation "Output Validation" "${Description} has a non-numeric count for $($property.Name)."
        }
        try {
            $count = [int64]$property.Value
        }
        catch {
            Fail-Validation "Output Validation" "${Description} has a non-numeric count for $($property.Name)."
        }
        if ($count -lt 0) {
            Fail-Validation "Output Validation" "${Description} has a negative count for $($property.Name)."
        }
    }
}

function Assert-CountMappingTotal {
    param([object]$Actual, [int64]$ExpectedTotal, [string]$Description)

    $actualTotal = [int64]0
    foreach ($property in $Actual.PSObject.Properties) {
        $actualTotal += [int64]$property.Value
    }
    if ($actualTotal -ne $ExpectedTotal) {
        Fail-Validation "Output Validation" "${Description} does not reconcile to the total finding count."
    }
}

function Assert-SampleBounds {
    param([object]$Samples, [string]$Description)

    if ($null -eq $Samples) {
        Fail-Validation "Output Validation" "${Description} is missing."
    }

    foreach ($property in $Samples.PSObject.Properties) {
        if (@($property.Value).Count -gt 5) {
            Fail-Validation "Output Validation" "${Description} retains more than five samples for $($property.Name)."
        }
    }
}

function Assert-DataGitSafety {
    $trackedDataFiles = @(
        git -c "safe.directory=$repositoryRoot" -C $repositoryRoot ls-files --stage -- data/raw data/processed
    )
    Require-LastExitCode "Git Safety" "git ls-files for raw and processed data"
    if ($trackedDataFiles.Count -ne 0) {
        Fail-Validation "Git Safety" "Raw or processed data is tracked or staged."
    }
}

function Get-FileIntegrity {
    param([string]$Path)

    $file = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        file_size_bytes = [int64]$file.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    }
}

function Assert-RawIntegrity {
    param([object]$Integrity, [string]$Phase)

    if ($Integrity.sha256 -ne $expectedRawHash) {
        Fail-Validation "Raw Data Integrity" "Raw SHA-256 does not match the approved baseline ${Phase}."
    }
}

function Assert-NormalizedIntegrity {
    param([object]$Integrity, [string]$Phase)

    if ($Integrity.file_size_bytes -ne $expectedNormalizedSizeBytes) {
        Fail-Validation "Normalized Input Integrity" "Normalized input size does not match Stage 1.3 evidence ${Phase}."
    }
    if ($Integrity.sha256 -ne $expectedNormalizedHash) {
        Fail-Validation "Normalized Input Integrity" "Normalized input SHA-256 does not match Stage 1.3 evidence ${Phase}."
    }
}

function Invoke-Detection {
    param([string]$OutputPath, [switch]$CleanupIfPublished)

    $commandOutput = & $python $detectionCli --input $normalizedInput --output $OutputPath 2>&1
    Require-LastExitCode "Detection Evaluation" "Stage 1.4 detection CLI"
    if ($CleanupIfPublished) {
        # The path is unique for this run. Mark ownership after the CLI returns
        # successfully so malformed standard output still triggers exact cleanup.
        $script:determinismOutputCreated = $true
    }
    return Convert-CommandJson $commandOutput "Detection Evaluation"
}

function New-AuditBridgeFile {
    $temporaryPath = [System.IO.Path]::GetTempFileName()
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($temporaryPath, $auditBridge, $encoding)
        return $temporaryPath
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        throw
    }
}

function Invoke-FindingAudit {
    param([object]$RunSummary, [string]$OutputPath)

    $summaryJson = $RunSummary | ConvertTo-Json -Depth 12 -Compress
    $auditBridgePath = New-AuditBridgeFile
    try {
        $commandOutput = $summaryJson | & $python $auditBridgePath $repositoryRoot $OutputPath 2>&1
        Require-LastExitCode "Finding Audit" "Stage 1.4 streaming finding audit"
        return Convert-CommandJson $commandOutput "Finding Audit"
    }
    finally {
        if (Test-Path -LiteralPath $auditBridgePath) {
            Remove-Item -LiteralPath $auditBridgePath -Force
        }
    }
}

function Assert-RunSummary {
    param([object]$RunSummary, [string]$OutputPath, [string]$Label)

    if ($null -eq $RunSummary) {
        Fail-Validation "Output Validation" "${Label} detection summary is missing."
    }
    if ($RunSummary.input_path -ne $normalizedInput -or $RunSummary.output_path -ne $OutputPath) {
        Fail-Validation "Output Validation" "${Label} detection summary contains an unexpected input or output path."
    }
    if ($RunSummary.finding_schema_version -ne "1.0" -or $RunSummary.normalized_input_schema_version -ne "1.0") {
        Fail-Validation "Output Validation" "${Label} detection summary contains an unexpected schema version."
    }
    if ($RunSummary.normalized_input_record_count -ne $expectedRecordCount -or
        $RunSummary.evaluated_record_count -ne $expectedRecordCount -or
        $RunSummary.invalid_input_count -ne 0) {
        Fail-Validation "Output Validation" "${Label} detection summary does not reconcile to ${expectedRecordCount} evaluated records and zero invalid records."
    }

    Assert-CountMappingShape -Actual $RunSummary.findings_by_rule_id -AllowedNames @($expectedRuleCounts.Keys) -Description "${Label} findings by rule"
    Assert-CountMappingShape -Actual $RunSummary.findings_by_rule_severity -AllowedNames @($expectedSeverityCounts.Keys) -Description "${Label} findings by severity"
    Assert-CountMappingTotal -Actual $RunSummary.findings_by_rule_id -ExpectedTotal $RunSummary.total_finding_count -Description "${Label} findings by rule"
    Assert-CountMappingTotal -Actual $RunSummary.findings_by_rule_severity -ExpectedTotal $RunSummary.total_finding_count -Description "${Label} findings by severity"
    Assert-SampleBounds $RunSummary.sample_findings_by_rule "${Label} bounded samples"
    Assert-JsonEqual $expectedActiveRules @($RunSummary.active_rules) "${Label} active rule versions"
}

function Assert-AuditReconciliation {
    param([object]$RunSummary, [object]$AuditSummary, [string]$Label)

    if ($null -eq $AuditSummary) {
        Fail-Validation "Finding Audit" "${Label} audit summary is missing."
    }
    if ($AuditSummary.finding_count -ne $RunSummary.total_finding_count) {
        Fail-Validation "Finding Audit" "${Label} finding count does not reconcile to the detection summary."
    }
    if ($AuditSummary.unique_matched_source_record_count -ne $RunSummary.unique_matched_source_record_count) {
        Fail-Validation "Finding Audit" "${Label} matched-record count does not reconcile to the detection summary."
    }
    Assert-JsonEqual $RunSummary.findings_by_rule_id $AuditSummary.findings_by_rule_id "${Label} findings by rule"
    Assert-JsonEqual $RunSummary.findings_by_rule_severity $AuditSummary.findings_by_rule_severity "${Label} findings by severity"
    Assert-JsonEqual $RunSummary.sample_findings_by_rule $AuditSummary.sample_findings_by_rule "${Label} bounded samples"
}

function Assert-ExpectedReconciliation {
    param([object]$RunSummary)

    if ($RunSummary.total_finding_count -ne $expectedFindingCount -or
        $RunSummary.unique_matched_source_record_count -ne $expectedUniqueMatchedRecordCount) {
        Fail-SecurityReview "Measured total or unique matched-record counts differ from the pre-registered Stage 1.2 expectation."
    }
    try {
        Assert-CountMapping $RunSummary.findings_by_rule_id $expectedRuleCounts "Expected findings by rule"
        Assert-CountMapping $RunSummary.findings_by_rule_severity $expectedSeverityCounts "Expected findings by severity"
    }
    catch {
        Fail-SecurityReview "Measured rule or severity counts differ from the pre-registered Stage 1.2 expectation."
    }
}

function Assert-DeterministicSummary {
    param([object]$PrimarySummary, [object]$SecondarySummary)

    $primaryComparable = [ordered]@{
        finding_schema_version = $PrimarySummary.finding_schema_version
        input_path = $PrimarySummary.input_path
        normalized_input_schema_version = $PrimarySummary.normalized_input_schema_version
        normalized_input_record_count = $PrimarySummary.normalized_input_record_count
        evaluated_record_count = $PrimarySummary.evaluated_record_count
        invalid_input_count = $PrimarySummary.invalid_input_count
        total_finding_count = $PrimarySummary.total_finding_count
        findings_by_rule_id = $PrimarySummary.findings_by_rule_id
        findings_by_rule_severity = $PrimarySummary.findings_by_rule_severity
        unique_matched_source_record_count = $PrimarySummary.unique_matched_source_record_count
        sample_findings_by_rule = $PrimarySummary.sample_findings_by_rule
        active_rules = @($PrimarySummary.active_rules)
    }
    $secondaryComparable = [ordered]@{
        finding_schema_version = $SecondarySummary.finding_schema_version
        input_path = $SecondarySummary.input_path
        normalized_input_schema_version = $SecondarySummary.normalized_input_schema_version
        normalized_input_record_count = $SecondarySummary.normalized_input_record_count
        evaluated_record_count = $SecondarySummary.evaluated_record_count
        invalid_input_count = $SecondarySummary.invalid_input_count
        total_finding_count = $SecondarySummary.total_finding_count
        findings_by_rule_id = $SecondarySummary.findings_by_rule_id
        findings_by_rule_severity = $SecondarySummary.findings_by_rule_severity
        unique_matched_source_record_count = $SecondarySummary.unique_matched_source_record_count
        sample_findings_by_rule = $SecondarySummary.sample_findings_by_rule
        active_rules = @($SecondarySummary.active_rules)
    }
    Assert-JsonEqual $primaryComparable $secondaryComparable "Primary and determinism detection summaries"
}

function Write-NewUtf8File {
    param([string]$Path, [string]$Content)

    $fileStream = $null
    $writer = $null
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $fileStream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $writer = New-Object System.IO.StreamWriter($fileStream, $encoding)
        $writer.Write($Content)
    }
    finally {
        if ($null -ne $writer) {
            $writer.Dispose()
        }
        elseif ($null -ne $fileStream) {
            $fileStream.Dispose()
        }
    }
}

$exitCode = 0
$determinismOutputCreated = $false
$temporarySummaryOutputCreated = $false
Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "========================================"
    Write-Host "Stage 1.4F Local Validation"
    Write-Host "========================================"

    Write-Host "`n[1/11] Environment and output safety"
    Require-Path $python "Python virtual environment runtime"
    $pythonVersion = (& $python --version 2>&1 | Out-String).Trim()
    Require-LastExitCode "Environment" "Python version check"
    if ($pythonVersion -notmatch "^Python 3\.12\.") {
        Fail-Validation "Environment" "Python 3.12 is required; found '${pythonVersion}'."
    }
    Require-Path $rawDataset "raw dataset"
    Require-Path $processedDirectory "processed-data directory" -Directory
    Require-Path $normalizedInput "Stage 1.3 normalized input"
    Require-Path $detectionCli "Stage 1.4 detection CLI"
    Require-Path $testsDirectory "tests directory" -Directory
    foreach ($path in @($primaryFindingsOutput, $summaryOutput, $temporarySummaryOutput, $determinismFindingsOutput)) {
        if (Test-Path -LiteralPath $path) {
            Fail-Validation "Output Safety" "Validation artifact already exists and will not be overwritten: ${path}"
        }
    }
    Write-Host "Python: $pythonVersion"
    Write-Host "Environment and output safety: PASS"

    Write-Host "`n[2/11] Git safety before evaluation"
    Assert-DataGitSafety
    Write-Host "Raw/Processed Git Safety Before: PASS"

    Write-Host "`n[3/11] Complete test suite before real-data evaluation"
    & $python -m unittest discover -s $testsDirectory -v
    Require-LastExitCode "Full Tests" "Complete unittest suite before real-data evaluation"
    Write-Host "Full Tests Before: PASS"

    Write-Host "`n[4/11] Input integrity before evaluation"
    $rawIntegrityBefore = Get-FileIntegrity $rawDataset
    $normalizedIntegrityBefore = Get-FileIntegrity $normalizedInput
    Assert-RawIntegrity $rawIntegrityBefore "before evaluation"
    Assert-NormalizedIntegrity $normalizedIntegrityBefore "before evaluation"
    Write-Host "Raw SHA-256 before: $($rawIntegrityBefore.sha256)"
    Write-Host "Normalized input size: $($normalizedIntegrityBefore.file_size_bytes) bytes"
    Write-Host "Normalized input SHA-256: $($normalizedIntegrityBefore.sha256)"
    Write-Host "Input integrity: PASS"

    Write-Host "`n[5/11] Primary detection evaluation"
    $primaryRun = Invoke-Detection $primaryFindingsOutput
    Assert-RunSummary $primaryRun $primaryFindingsOutput "Primary"
    $primaryAudit = Invoke-FindingAudit $primaryRun $primaryFindingsOutput
    Assert-AuditReconciliation $primaryRun $primaryAudit "Primary"
    Assert-ExpectedReconciliation $primaryRun
    $primaryFindingsIntegrity = Get-FileIntegrity $primaryFindingsOutput
    Write-Host "Primary findings: $($primaryRun.total_finding_count)"
    Write-Host "Primary finding output size: $($primaryFindingsIntegrity.file_size_bytes) bytes"
    Write-Host "Primary finding output SHA-256: $($primaryFindingsIntegrity.sha256)"
    Write-Host "Primary evaluation and streaming audit: PASS"

    Write-Host "`n[6/11] Determinism evaluation"
    $determinismRun = Invoke-Detection -OutputPath $determinismFindingsOutput -CleanupIfPublished
    Assert-RunSummary $determinismRun $determinismFindingsOutput "Determinism"
    Assert-DeterministicSummary $primaryRun $determinismRun
    $determinismFindingsIntegrity = Get-FileIntegrity $determinismFindingsOutput
    if ($primaryFindingsIntegrity.sha256 -ne $determinismFindingsIntegrity.sha256) {
        Fail-Validation "Determinism" "The two finding outputs have different SHA-256 hashes."
    }
    Remove-Item -LiteralPath $determinismFindingsOutput -Force
    $determinismOutputCreated = $false
    Write-Host "Determinism finding SHA-256: $($determinismFindingsIntegrity.sha256)"
    Write-Host "Determinism: PASS"

    Write-Host "`n[7/11] Input integrity after evaluation"
    $rawIntegrityAfter = Get-FileIntegrity $rawDataset
    $normalizedIntegrityAfter = Get-FileIntegrity $normalizedInput
    Assert-RawIntegrity $rawIntegrityAfter "after evaluation"
    Assert-NormalizedIntegrity $normalizedIntegrityAfter "after evaluation"
    if ($rawIntegrityBefore.file_size_bytes -ne $rawIntegrityAfter.file_size_bytes -or
        $rawIntegrityBefore.sha256 -ne $rawIntegrityAfter.sha256) {
        Fail-Validation "Raw Data Integrity" "Raw data changed during detection evaluation."
    }
    if ($normalizedIntegrityBefore.file_size_bytes -ne $normalizedIntegrityAfter.file_size_bytes -or
        $normalizedIntegrityBefore.sha256 -ne $normalizedIntegrityAfter.sha256) {
        Fail-Validation "Normalized Input Integrity" "Normalized input changed during detection evaluation."
    }
    Write-Host "Raw and normalized input integrity: PASS"

    Write-Host "`n[8/11] Complete test suite after real-data evaluation"
    & $python -m unittest discover -s $testsDirectory -v
    Require-LastExitCode "Full Tests" "Complete unittest suite after real-data evaluation"
    Write-Host "Full Tests After: PASS"

    Write-Host "`n[9/11] Diff and Git safety"
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot diff --check
    Require-LastExitCode "Git Safety" "git diff --check"
    Assert-DataGitSafety
    if (Test-Path -LiteralPath $determinismFindingsOutput) {
        Fail-Validation "Output Safety" "Determinism temporary artifact remains after validation."
    }
    Write-Host "git diff --check: PASS"
    Write-Host "Raw/Processed Git Safety After: PASS"

    Write-Host "`n[10/11] Write bounded validation summary"
    $validationSummary = [ordered]@{
        validation_stage = "1.4F"
        python_version = $pythonVersion
        raw = [ordered]@{
            path = $rawDataset
            file_size_bytes_before = $rawIntegrityBefore.file_size_bytes
            file_size_bytes_after = $rawIntegrityAfter.file_size_bytes
            sha256_before = $rawIntegrityBefore.sha256
            sha256_after = $rawIntegrityAfter.sha256
        }
        normalized_input = [ordered]@{
            path = $normalizedInput
            file_size_bytes_before = $normalizedIntegrityBefore.file_size_bytes
            file_size_bytes_after = $normalizedIntegrityAfter.file_size_bytes
            sha256_before = $normalizedIntegrityBefore.sha256
            sha256_after = $normalizedIntegrityAfter.sha256
        }
        primary_run = $primaryRun
        primary_findings = [ordered]@{
            path = $primaryFindingsOutput
            file_size_bytes = $primaryFindingsIntegrity.file_size_bytes
            sha256 = $primaryFindingsIntegrity.sha256
        }
        primary_audit = $primaryAudit
        determinism = [ordered]@{
            secondary_findings_sha256 = $determinismFindingsIntegrity.sha256
            hashes_match = $true
            temporary_findings_removed = $true
        }
        validation_checks = [ordered]@{
            full_tests_before = "PASS"
            full_tests_after = "PASS"
            raw_processed_git_safety_before = "PASS"
            raw_processed_git_safety_after = "PASS"
            git_diff_check = "PASS"
        }
        expected_reconciliation = [ordered]@{
            source_threat_observation_count = 25
            anomaly_subtype_observation_count = 18
            total_finding_count = 43
            unique_matched_source_record_count = 25
            informational_finding_count = 43
        }
        verdict = "PASS"
    }
    $summaryJson = $validationSummary | ConvertTo-Json -Depth 12
    $temporarySummaryOutputCreated = $true
    Write-NewUtf8File $temporarySummaryOutput $summaryJson
    try {
        $writtenSummary = Get-Content -LiteralPath $temporarySummaryOutput -Raw | ConvertFrom-Json
    }
    catch {
        Fail-Validation "Validation Summary" "The written validation summary is not valid JSON."
    }
    if ($writtenSummary.verdict -ne "PASS") {
        Fail-Validation "Validation Summary" "The written validation summary does not retain the PASS verdict."
    }
    [System.IO.File]::Move($temporarySummaryOutput, $summaryOutput)
    $temporarySummaryOutputCreated = $false
    Assert-DataGitSafety
    Write-Host "Summary: $summaryOutput"

    Write-Host "`n[11/11] Final status"
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot status --short
    Require-LastExitCode "Git Safety" "git status"
    Write-Host "========================================"
    Write-Host "FINAL RESULT: PASS"
    Write-Host "========================================"
}
catch {
    $message = $_.Exception.Message
    $verdict = if ($message -like "NEEDS SECURITY REVIEW:*") {
        "NEEDS SECURITY REVIEW"
    }
    else {
        "FAIL"
    }
    Write-Host "`nFAILED GATE: ${message}"
    Write-Host "========================================"
    Write-Host "FINAL RESULT: ${verdict}"
    Write-Host "========================================"
    $exitCode = 1
}
finally {
    if ($determinismOutputCreated -and (Test-Path -LiteralPath $determinismFindingsOutput)) {
        Remove-Item -LiteralPath $determinismFindingsOutput -Force
    }
    if ($temporarySummaryOutputCreated -and (Test-Path -LiteralPath $temporarySummaryOutput)) {
        Remove-Item -LiteralPath $temporarySummaryOutput -Force
    }
    Pop-Location
}

exit $exitCode
