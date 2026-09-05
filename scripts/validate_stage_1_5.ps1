[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = (Resolve-Path (Join-Path $scriptDirectory "..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$testsDirectory = Join-Path $repositoryRoot "tests"
$processedDirectory = Join-Path $repositoryRoot "data\processed"
$findingsPath = Join-Path $processedDirectory "stage_1_4f_detection_findings.jsonl"
$summaryPath = Join-Path $processedDirectory "stage_1_4f_detection_summary.json"
$primaryDatabase = Join-Path $processedDirectory "stage_1_5f_detection_store.sqlite3"
$secondaryDatabase = Join-Path $processedDirectory (
    ".stage_1_5f_detection_store_second_{0}.sqlite3" -f ([guid]::NewGuid().ToString("N"))
)
$loadCli = Join-Path $repositoryRoot "src\load_detection_store.py"
$queryCli = Join-Path $repositoryRoot "src\query_detection_store.py"
$auditCli = Join-Path $repositoryRoot "src\audit_detection_store.py"
$stage16Plan = "docs/plans/stage_1_6_read_only_api_plan.md"

$expectedFindingsSha256 = "5212f083bb3832158bcd650535536c22d1b8dbf582496726f998ece949ee20dc"
$expectedSummarySha256 = "d3585bf577cb1b16aca2a8afb65d18959941e28fc2b9cd6c396c35cf03dd16fe"
$expectedEvaluatedRecordCount = 100000
$expectedFindingCount = 43
$expectedUniqueSourceRecordCount = 25
$expectedRuleCounts = [ordered]@{
    "fortigate.anomaly_subtype_observation" = 18
    "fortigate.source_threat_observation" = 25
}
$expectedSeverityCounts = [ordered]@{
    "INFORMATIONAL" = 43
}

$validationBridge = @'
import json
import sys
from pathlib import Path

repository_root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repository_root / "src"))

from storage.input import ApprovedArtifactIdentity, validate_detection_artifacts

validated = validate_detection_artifacts(
    sys.argv[2],
    sys.argv[3],
    ApprovedArtifactIdentity(sys.argv[4], sys.argv[5]),
)
print(
    json.dumps(
        {
            "run_id": validated.run_id,
            "findings_sha256": validated.findings_sha256,
            "summary_sha256": validated.summary_sha256,
            "finding_count": validated.finding_count,
            "evidence_count": validated.evidence_count,
            "rule_count": validated.rule_count,
            "summary": validated.summary.to_dict(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
)
'@

function Fail-Validation {
    param([string]$Stage, [string]$Message)

    throw "${Stage}: ${Message}"
}

function Require-LastExitCode {
    param([string]$Stage, [string]$Description)

    if ($LASTEXITCODE -ne 0) {
        Fail-Validation $Stage "${Description} failed with exit code ${LASTEXITCODE}."
    }
}

function Require-Path {
    param([string]$Path, [string]$Description, [switch]$Directory)

    if (-not (Test-Path -LiteralPath $Path -PathType $(if ($Directory) { "Container" } else { "Leaf" }))) {
        Fail-Validation "Environment" "Missing ${Description}: ${Path}"
    }
}

function Get-FileIntegrity {
    param([string]$Path)

    $file = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        file_size_bytes = [int64]$file.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-TextSha256 {
    param([string]$Text)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return -join ($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    }
    finally {
        $hasher.Dispose()
    }
}

function ConvertTo-PythonProcessArgument {
    param([string]$Value)

    if ($null -eq $Value) {
        Fail-Validation "Python Invocation" "Python arguments must not be null."
    }
    if ($Value.Contains('"')) {
        Fail-Validation "Python Invocation" "Python arguments must not contain double quotes."
    }
    return '"' + $Value + '"'
}

function Get-BoundedNativeText {
    param([string]$Text, [int]$MaximumLength = 4000)

    $trimmed = $Text.Trim()
    if ($trimmed.Length -le $MaximumLength) {
        return $trimmed
    }
    return $trimmed.Substring(0, $MaximumLength) + "`n... output truncated ..."
}

function Invoke-PythonProcess {
    param([string[]]$Arguments)

    if ($Arguments.Count -eq 0) {
        Fail-Validation "Python Invocation" "Python invocation requires at least one argument."
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $python
    $startInfo.Arguments = (@($Arguments | ForEach-Object {
        ConvertTo-PythonProcessArgument $_
    }) -join " ")
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            Fail-Validation "Python Invocation" "Python process did not start."
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{
            stdout = $stdoutTask.GetAwaiter().GetResult()
            stderr = $stderrTask.GetAwaiter().GetResult()
            exit_code = $process.ExitCode
        }
    }
    finally {
        $process.Dispose()
    }
}

function Require-PythonProcessSuccess {
    param([object]$Result, [string]$Stage, [string]$Description)

    if ($Result.exit_code -eq 0) {
        return
    }
    $details = @()
    if (-not [string]::IsNullOrWhiteSpace($Result.stderr)) {
        $details += "stderr:`n$(Get-BoundedNativeText $Result.stderr)"
    }
    if (-not [string]::IsNullOrWhiteSpace($Result.stdout)) {
        $details += "stdout:`n$(Get-BoundedNativeText $Result.stdout)"
    }
    $detailText = if ($details.Count -gt 0) {
        "`n" + ([string]::Join("`n", $details))
    }
    else {
        ""
    }
    Fail-Validation $Stage "${Description} failed with exit code $($Result.exit_code).${detailText}"
}

function Invoke-CompleteTestSuite {
    param([string]$Description)

    $result = Invoke-PythonProcess @(
        "-m", "unittest", "discover", "-s", $testsDirectory, "-p", "test_*.py", "-v"
    )
    if (-not [string]::IsNullOrWhiteSpace($result.stdout)) {
        Write-Host -NoNewline $result.stdout
    }
    if (-not [string]::IsNullOrWhiteSpace($result.stderr)) {
        Write-Host -NoNewline $result.stderr
    }
    Require-PythonProcessSuccess $result "Full Tests" $Description
}

function Convert-CommandJson {
    param([object[]]$CommandOutput, [string]$Stage)

    $text = ($CommandOutput | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        Fail-Validation $Stage "Command produced no JSON output."
    }
    try {
        return $text | ConvertFrom-Json
    }
    catch {
        Fail-Validation $Stage "Command output is not valid JSON."
    }
}

function Invoke-JsonCli {
    param([string]$Stage, [string]$ScriptPath, [string[]]$Arguments)

    $result = Invoke-PythonProcess (@($ScriptPath) + @($Arguments))
    Require-PythonProcessSuccess $result $Stage (Split-Path -Leaf $ScriptPath)
    return Convert-CommandJson @($result.stdout) $Stage
}

function Invoke-QueryCli {
    param([string]$Stage, [string[]]$Arguments)

    $result = Invoke-PythonProcess (@($queryCli) + @($Arguments))
    Require-PythonProcessSuccess $result $Stage "Stage 1.5D query CLI"
    $lines = @(
        ($result.stdout -split "`r?`n") |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $objects = @()
    foreach ($line in $lines) {
        try {
            $objects += $line | ConvertFrom-Json
        }
        catch {
            Fail-Validation $Stage "Query output is not valid JSON Lines."
        }
    }
    return [pscustomobject]@{
        lines = $lines
        objects = $objects
        sha256 = Get-TextSha256 (([string]::Join("`n", $lines)) + "`n")
    }
}

function Assert-Equal {
    param([object]$Actual, [object]$Expected, [string]$Description)

    if ($Actual -ne $Expected) {
        Fail-Validation "Reconciliation" "${Description}: expected '${Expected}', found '${Actual}'."
    }
}

function Assert-JsonEqual {
    param([object]$Actual, [object]$Expected, [string]$Description)

    $actualJson = $Actual | ConvertTo-Json -Depth 20 -Compress
    $expectedJson = $Expected | ConvertTo-Json -Depth 20 -Compress
    Assert-Equal $actualJson $expectedJson $Description
}

function Get-PropertyValue {
    param([object]$Value, [string]$PropertyName, [string]$Description)

    $property = $Value.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        Fail-Validation "Query Validation" "${Description} is missing property '${PropertyName}'."
    }
    return $property.Value
}

function Get-CountMap {
    param([object[]]$Values, [string]$PropertyName, [string]$Description)

    $counts = [ordered]@{}
    foreach ($value in $Values) {
        $key = [string](Get-PropertyValue $value $PropertyName $Description)
        if ($counts.Contains($key)) {
            $counts[$key] = [int64]$counts[$key] + 1
        }
        else {
            $counts[$key] = [int64]1
        }
    }
    return $counts
}

function ConvertTo-CountMap {
    param([object]$Value, [string]$Description)

    $counts = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Value -isnot [System.ValueType]) {
            Fail-Validation "Reconciliation" "${Description} contains a non-numeric value."
        }
        $counts[$property.Name] = [int64]$property.Value
    }
    return $counts
}

function Assert-CountMap {
    param([System.Collections.IDictionary]$Actual, [System.Collections.IDictionary]$Expected, [string]$Description)

    $actualKeys = @($Actual.Keys | Sort-Object)
    $expectedKeys = @($Expected.Keys | Sort-Object)
    if (($actualKeys -join "|") -ne ($expectedKeys -join "|")) {
        Fail-Validation "Reconciliation" "${Description} has unexpected keys."
    }
    foreach ($key in $expectedKeys) {
        Assert-Equal ([int64]$Actual[$key]) ([int64]$Expected[$key]) "${Description} for ${key}"
    }
}

function Get-UniquePropertyCount {
    param([object[]]$Values, [string]$PropertyName, [string]$Description)

    $uniqueValues = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($value in $Values) {
        [void]$uniqueValues.Add([string](Get-PropertyValue $value $PropertyName $Description))
    }
    return $uniqueValues.Count
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

function Assert-Stage16PlanUntracked {
    $statusLines = @(
        git -c "safe.directory=$repositoryRoot" -C $repositoryRoot status --short
    )
    Require-LastExitCode "Git Safety" "git status"
    if ($statusLines -notcontains "?? $stage16Plan") {
        Fail-Validation "Git Safety" "The Stage 1.6 plan must remain untracked and unstaged."
    }
}

function Assert-PathUnderProcessedDirectory {
    param([string]$Path, [string]$Description)

    $processedRoot = [System.IO.Path]::GetFullPath($processedDirectory)
    $candidate = [System.IO.Path]::GetFullPath($Path)
    $prefix = $processedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail-Validation "Output Safety" "${Description} is outside data/processed."
    }
}

function Remove-VerifiedSecondaryArtifacts {
    param([string]$DatabasePath)

    Assert-PathUnderProcessedDirectory $DatabasePath "Secondary database"
    foreach ($candidate in @(
        $DatabasePath,
        "${DatabasePath}-journal",
        "${DatabasePath}-wal",
        "${DatabasePath}-shm"
    )) {
        if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction Stop
        }
    }
}

function Assert-PrimarySidecarsAbsent {
    param([string]$DatabasePath)

    foreach ($candidate in @(
        "${DatabasePath}-journal",
        "${DatabasePath}-wal",
        "${DatabasePath}-shm"
    )) {
        if (Test-Path -LiteralPath $candidate) {
            Fail-Validation "Artifact Safety" "SQLite sidecar remains: ${candidate}"
        }
    }
}

function New-ValidationBridgeFile {
    $temporaryPath = [System.IO.Path]::GetTempFileName()
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $validationBridge,
            [System.Text.UTF8Encoding]::new($false)
        )
        return $temporaryPath
    }
    catch {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
        throw
    }
}

function Invoke-StrictArtifactValidation {
    $bridgePath = New-ValidationBridgeFile
    try {
        $result = Invoke-PythonProcess @(
            $bridgePath,
            $repositoryRoot,
            $findingsPath,
            $summaryPath,
            $expectedFindingsSha256,
            $expectedSummarySha256
        )
        Require-PythonProcessSuccess $result "Strict Validation" "Stage 1.5B validation boundary"
        return Convert-CommandJson @($result.stdout) "Strict Validation"
    }
    finally {
        if (Test-Path -LiteralPath $bridgePath) {
            Remove-Item -LiteralPath $bridgePath -Force
        }
    }
}

function Invoke-QueryValidation {
    param([string]$DatabasePath, [object]$ValidatedArtifacts)

    $runId = [string]$ValidatedArtifacts.run_id
    $runQuery = Invoke-QueryCli "Query Validation" @(
        "--database", $DatabasePath, "run", "--run-id", $runId
    )
    Assert-Equal $runQuery.objects.Count 1 "Detection-run query result count"
    $run = $runQuery.objects[0]
    Assert-Equal $run.run_id $runId "Stored run ID"
    Assert-Equal $run.findings_sha256 $ValidatedArtifacts.findings_sha256 "Stored findings SHA-256"
    Assert-Equal $run.summary_sha256 $ValidatedArtifacts.summary_sha256 "Stored summary SHA-256"
    Assert-Equal $run.evaluated_record_count $expectedEvaluatedRecordCount "Evaluated record count"
    Assert-Equal $run.invalid_input_count 0 "Invalid input count"
    Assert-Equal $run.total_finding_count $expectedFindingCount "Stored finding count"
    Assert-Equal $run.unique_matched_source_record_count $expectedUniqueSourceRecordCount "Stored unique source-record count"

    $findingsQuery = Invoke-QueryCli "Query Validation" @(
        "--database", $DatabasePath, "findings", "--run-id", $runId, "--limit", "50"
    )
    $findings = @($findingsQuery.objects)
    Assert-Equal $findings.Count $expectedFindingCount "Bounded finding-list count"
    $countsByRule = Get-CountMap $findings "rule_id" "Stored findings"
    $countsBySeverity = Get-CountMap $findings "rule_severity" "Stored findings"
    $countsByReason = Get-CountMap $findings "reason_code" "Stored findings"
    $countsBySource = Get-CountMap $findings "source_type" "Stored findings"
    Assert-CountMap $countsByRule $expectedRuleCounts "Stored findings by rule"
    Assert-CountMap $countsBySeverity $expectedSeverityCounts "Stored findings by severity"
    Assert-CountMap $countsByRule (ConvertTo-CountMap $ValidatedArtifacts.summary.findings_by_rule_id "Validated summary findings by rule") "Validated summary findings by rule"
    Assert-CountMap $countsBySeverity (ConvertTo-CountMap $ValidatedArtifacts.summary.findings_by_rule_severity "Validated summary findings by severity") "Validated summary findings by severity"
    Assert-Equal (Get-UniquePropertyCount $findings "source_record_number" "Stored findings") $expectedUniqueSourceRecordCount "Unique source-record count"

    $filterOutputHashes = [ordered]@{}
    foreach ($ruleId in $countsByRule.Keys) {
        $ruleQuery = Invoke-QueryCli "Query Validation" @(
            "--database", $DatabasePath, "findings", "--run-id", $runId,
            "--rule-id", $ruleId, "--limit", "50"
        )
        Assert-Equal $ruleQuery.objects.Count $countsByRule[$ruleId] "Rule-filtered finding count for ${ruleId}"
        foreach ($finding in $ruleQuery.objects) {
            Assert-Equal $finding.rule_id $ruleId "Rule-filtered finding rule ID"
        }
        $filterOutputHashes["rule:$ruleId"] = $ruleQuery.sha256
    }
    foreach ($severity in $countsBySeverity.Keys) {
        $severityQuery = Invoke-QueryCli "Query Validation" @(
            "--database", $DatabasePath, "findings", "--run-id", $runId,
            "--severity", $severity, "--limit", "50"
        )
        Assert-Equal $severityQuery.objects.Count $countsBySeverity[$severity] "Severity-filtered finding count for ${severity}"
        foreach ($finding in $severityQuery.objects) {
            Assert-Equal $finding.rule_severity $severity "Severity-filtered finding severity"
        }
        $filterOutputHashes["severity:$severity"] = $severityQuery.sha256
    }
    foreach ($reasonCode in $countsByReason.Keys) {
        $reasonQuery = Invoke-QueryCli "Query Validation" @(
            "--database", $DatabasePath, "findings", "--run-id", $runId,
            "--reason-code", $reasonCode, "--limit", "50"
        )
        Assert-Equal $reasonQuery.objects.Count $countsByReason[$reasonCode] "Reason-filtered finding count for ${reasonCode}"
        foreach ($finding in $reasonQuery.objects) {
            Assert-Equal $finding.reason_code $reasonCode "Reason-filtered finding reason code"
        }
        $filterOutputHashes["reason:$reasonCode"] = $reasonQuery.sha256
    }
    foreach ($sourceType in $countsBySource.Keys) {
        $sourceQuery = Invoke-QueryCli "Query Validation" @(
            "--database", $DatabasePath, "findings", "--run-id", $runId,
            "--source-type", $sourceType, "--limit", "50"
        )
        Assert-Equal $sourceQuery.objects.Count $countsBySource[$sourceType] "Source-filtered finding count for ${sourceType}"
        foreach ($finding in $sourceQuery.objects) {
            Assert-Equal $finding.source_type $sourceType "Source-filtered finding source type"
        }
        $filterOutputHashes["source:$sourceType"] = $sourceQuery.sha256
    }

    $representativeFinding = $findings[0]
    $singleFindingQuery = Invoke-QueryCli "Query Validation" @(
        "--database", $DatabasePath, "finding", "--finding-id", $representativeFinding.finding_id
    )
    Assert-Equal $singleFindingQuery.objects.Count 1 "Representative finding query result count"
    $singleFindingJson = $singleFindingQuery.objects[0] | ConvertTo-Json -Depth 12 -Compress
    $representativeFindingJson = $representativeFinding | ConvertTo-Json -Depth 12 -Compress
    Assert-Equal $singleFindingJson $representativeFindingJson "Representative finding reconstruction"

    $evidenceQuery = Invoke-QueryCli "Query Validation" @(
        "--database", $DatabasePath, "evidence", "--run-id", $runId,
        "--finding-id", $representativeFinding.finding_id, "--limit", "50"
    )
    if ($evidenceQuery.objects.Count -lt 1) {
        Fail-Validation "Query Validation" "Representative finding has no stored evidence."
    }
    foreach ($evidence in $evidenceQuery.objects) {
        Assert-Equal $evidence.run_id $runId "Representative evidence run ID"
        Assert-Equal $evidence.finding_id $representativeFinding.finding_id "Representative evidence finding ID"
    }

    return [pscustomobject]@{
        run = $run
        findings_by_rule_id = $countsByRule
        findings_by_rule_severity = $countsBySeverity
        findings_by_reason_code = $countsByReason
        findings_by_source_type = $countsBySource
        unique_matched_source_record_count = Get-UniquePropertyCount $findings "source_record_number" "Stored findings"
        representative_finding_id = $representativeFinding.finding_id
        representative_evidence_count = $evidenceQuery.objects.Count
        query_output_sha256 = [ordered]@{
            run = $runQuery.sha256
            bounded_findings = $findingsQuery.sha256
            representative_finding = $singleFindingQuery.sha256
            representative_evidence = $evidenceQuery.sha256
            filters = $filterOutputHashes
        }
    }
}

$exitCode = 0
$secondaryDatabaseOwned = $false
Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "========================================"
    Write-Host "Stage 1.5F Local Storage Validation"
    Write-Host "========================================"

    Write-Host "`n[1/12] Environment and approved-input safety"
    Require-Path $python "Python virtual environment runtime"
    Require-Path $testsDirectory "tests directory" -Directory
    Require-Path $processedDirectory "processed-data directory" -Directory
    Require-Path $findingsPath "approved Stage 1.4 finding JSONL"
    Require-Path $summaryPath "approved Stage 1.4 summary"
    Require-Path $loadCli "Stage 1.5C import CLI"
    Require-Path $queryCli "Stage 1.5D query CLI"
    Require-Path $auditCli "Stage 1.5E audit CLI"
    Assert-PathUnderProcessedDirectory $primaryDatabase "Primary database"
    Assert-PathUnderProcessedDirectory $secondaryDatabase "Secondary database"
    if (Test-Path -LiteralPath $primaryDatabase) {
        Fail-Validation "Output Safety" "Primary database already exists and will not be overwritten: ${primaryDatabase}"
    }
    if (Test-Path -LiteralPath $secondaryDatabase) {
        Fail-Validation "Output Safety" "Secondary database path unexpectedly exists: ${secondaryDatabase}"
    }
    $pythonVersionResult = Invoke-PythonProcess @("--version")
    Require-PythonProcessSuccess $pythonVersionResult "Environment" "Python version check"
    $pythonVersion = ($pythonVersionResult.stdout + $pythonVersionResult.stderr).Trim()
    if ($pythonVersion -notmatch "^Python 3\.12\.") {
        Fail-Validation "Environment" "Python 3.12 is required; found '${pythonVersion}'."
    }
    Write-Host "Python: $pythonVersion"
    Write-Host "Approved inputs: PASS"

    Write-Host "`n[2/12] Git and upstream-artifact safety before validation"
    Assert-DataGitSafety
    Assert-Stage16PlanUntracked
    $findingsIntegrityBefore = Get-FileIntegrity $findingsPath
    $summaryIntegrityBefore = Get-FileIntegrity $summaryPath
    Assert-Equal $findingsIntegrityBefore.sha256 $expectedFindingsSha256 "Approved finding JSONL SHA-256"
    Assert-Equal $summaryIntegrityBefore.sha256 $expectedSummarySha256 "Approved summary SHA-256"
    Write-Host "Input finding SHA-256: $($findingsIntegrityBefore.sha256)"
    Write-Host "Input summary SHA-256: $($summaryIntegrityBefore.sha256)"
    Write-Host "Git and artifact safety before: PASS"

    Write-Host "`n[3/12] Complete synthetic test suite before real-data validation"
    Invoke-CompleteTestSuite "Complete unittest suite before real-data validation"
    Write-Host "Full Tests Before: PASS"

    Write-Host "`n[4/12] Strict Stage 1.5B input validation"
    $validatedArtifacts = Invoke-StrictArtifactValidation
    Assert-Equal $validatedArtifacts.run_id $expectedFindingsSha256 "Validated run identity"
    Assert-Equal $validatedArtifacts.findings_sha256 $expectedFindingsSha256 "Validated finding identity"
    Assert-Equal $validatedArtifacts.summary_sha256 $expectedSummarySha256 "Validated summary identity"
    Assert-Equal $validatedArtifacts.finding_count $expectedFindingCount "Validated finding count"
    Assert-Equal $validatedArtifacts.summary.evaluated_record_count $expectedEvaluatedRecordCount "Validated evaluated record count"
    Assert-Equal $validatedArtifacts.summary.invalid_input_count 0 "Validated invalid input count"
    Assert-Equal $validatedArtifacts.summary.unique_matched_source_record_count $expectedUniqueSourceRecordCount "Validated unique source-record count"
    Assert-CountMap (ConvertTo-CountMap $validatedArtifacts.summary.findings_by_rule_id "Validated findings by rule") $expectedRuleCounts "Validated findings by rule"
    Assert-CountMap (ConvertTo-CountMap $validatedArtifacts.summary.findings_by_rule_severity "Validated findings by severity") $expectedSeverityCounts "Validated findings by severity"
    Write-Host "Strict validation: PASS"

    Write-Host "`n[5/12] Primary transactional SQLite import"
    $primaryImport = Invoke-JsonCli "Primary Import" $loadCli @(
        "--findings", $findingsPath, "--summary", $summaryPath, "--database", $primaryDatabase
    )
    Assert-Equal $primaryImport.run_id $validatedArtifacts.run_id "Primary import run ID"
    Assert-Equal $primaryImport.findings_sha256 $validatedArtifacts.findings_sha256 "Primary import finding SHA-256"
    Assert-Equal $primaryImport.summary_sha256 $validatedArtifacts.summary_sha256 "Primary import summary SHA-256"
    Assert-Equal $primaryImport.finding_count $validatedArtifacts.finding_count "Primary import finding count"
    Assert-Equal $primaryImport.evidence_count $validatedArtifacts.evidence_count "Primary import evidence count"
    Write-Host "Primary import: PASS"

    Write-Host "`n[6/12] Primary independent audit and bounded queries"
    $primaryAudit = Invoke-JsonCli "Primary Audit" $auditCli @("--database", $primaryDatabase)
    Assert-Equal $primaryAudit.run_id $validatedArtifacts.run_id "Primary audit run ID"
    Assert-Equal $primaryAudit.findings_sha256 $validatedArtifacts.findings_sha256 "Primary audit finding SHA-256"
    Assert-Equal $primaryAudit.summary_sha256 $validatedArtifacts.summary_sha256 "Primary audit summary SHA-256"
    Assert-Equal $primaryAudit.reconstructed_findings_sha256 $validatedArtifacts.findings_sha256 "Primary reconstructed finding SHA-256"
    Assert-Equal $primaryAudit.finding_count $validatedArtifacts.finding_count "Primary audit finding count"
    Assert-Equal $primaryAudit.evidence_count $validatedArtifacts.evidence_count "Primary audit evidence count"
    $primaryQueries = Invoke-QueryValidation $primaryDatabase $validatedArtifacts
    Write-Host "Primary audit and queries: PASS"

    Write-Host "`n[7/12] Secondary deterministic SQLite import"
    $secondaryDatabaseOwned = $true
    $secondaryImport = Invoke-JsonCli "Secondary Import" $loadCli @(
        "--findings", $findingsPath, "--summary", $summaryPath, "--database", $secondaryDatabase
    )
    Assert-Equal $secondaryImport.run_id $primaryImport.run_id "Secondary import run ID"
    Assert-Equal $secondaryImport.findings_sha256 $primaryImport.findings_sha256 "Secondary import finding SHA-256"
    Assert-Equal $secondaryImport.summary_sha256 $primaryImport.summary_sha256 "Secondary import summary SHA-256"
    Write-Host "Secondary import: PASS"

    Write-Host "`n[8/12] Secondary audit and determinism reconciliation"
    $secondaryAudit = Invoke-JsonCli "Secondary Audit" $auditCli @("--database", $secondaryDatabase)
    $secondaryQueries = Invoke-QueryValidation $secondaryDatabase $validatedArtifacts
    Assert-Equal $secondaryAudit.logical_export_sha256 $primaryAudit.logical_export_sha256 "Canonical logical export SHA-256"
    Assert-Equal $secondaryAudit.reconstructed_findings_sha256 $primaryAudit.reconstructed_findings_sha256 "Reconstructed finding JSONL SHA-256"
    Assert-Equal $secondaryAudit.finding_count $primaryAudit.finding_count "Deterministic finding count"
    Assert-Equal $secondaryAudit.evidence_count $primaryAudit.evidence_count "Deterministic evidence count"
    Assert-CountMap $secondaryQueries.findings_by_rule_id $primaryQueries.findings_by_rule_id "Deterministic findings by rule"
    Assert-CountMap $secondaryQueries.findings_by_rule_severity $primaryQueries.findings_by_rule_severity "Deterministic findings by severity"
    Assert-CountMap $secondaryQueries.findings_by_reason_code $primaryQueries.findings_by_reason_code "Deterministic findings by reason"
    Assert-CountMap $secondaryQueries.findings_by_source_type $primaryQueries.findings_by_source_type "Deterministic findings by source type"
    Assert-Equal $secondaryQueries.unique_matched_source_record_count $primaryQueries.unique_matched_source_record_count "Deterministic unique source-record count"
    Assert-JsonEqual $secondaryQueries.query_output_sha256 $primaryQueries.query_output_sha256 "Deterministic query output SHA-256"
    Remove-VerifiedSecondaryArtifacts $secondaryDatabase
    $secondaryDatabaseOwned = $false
    Write-Host "Determinism reconciliation: PASS"

    Write-Host "`n[9/12] Source-artifact integrity after storage validation"
    $findingsIntegrityAfter = Get-FileIntegrity $findingsPath
    $summaryIntegrityAfter = Get-FileIntegrity $summaryPath
    Assert-Equal $findingsIntegrityAfter.file_size_bytes $findingsIntegrityBefore.file_size_bytes "Finding JSONL file size after validation"
    Assert-Equal $findingsIntegrityAfter.sha256 $findingsIntegrityBefore.sha256 "Finding JSONL SHA-256 after validation"
    Assert-Equal $summaryIntegrityAfter.file_size_bytes $summaryIntegrityBefore.file_size_bytes "Summary file size after validation"
    Assert-Equal $summaryIntegrityAfter.sha256 $summaryIntegrityBefore.sha256 "Summary SHA-256 after validation"
    Write-Host "Approved Stage 1.4 artifacts remain unchanged: PASS"

    Write-Host "`n[10/12] Complete synthetic test suite after real-data validation"
    Invoke-CompleteTestSuite "Complete unittest suite after real-data validation"
    Write-Host "Full Tests After: PASS"

    Write-Host "`n[11/12] Git and generated-artifact safety"
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot diff --check
    Require-LastExitCode "Git Safety" "git diff --check"
    Assert-DataGitSafety
    Assert-Stage16PlanUntracked
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot check-ignore -q -- "data/processed/stage_1_5f_detection_store.sqlite3"
    Require-LastExitCode "Artifact Safety" "Primary database ignore rule"
    Assert-PrimarySidecarsAbsent $primaryDatabase
    if (Test-Path -LiteralPath $secondaryDatabase) {
        Fail-Validation "Artifact Safety" "Secondary database remains after cleanup."
    }
    Write-Host "Git and generated-artifact safety: PASS"

    Write-Host "`n[12/12] Bounded measured validation summary"
    $validationSummary = [ordered]@{
        validation_stage = "1.5F"
        python_version = $pythonVersion
        inputs = [ordered]@{
            findings_path = "data/processed/stage_1_4f_detection_findings.jsonl"
            findings_sha256 = $validatedArtifacts.findings_sha256
            summary_path = "data/processed/stage_1_4f_detection_summary.json"
            summary_sha256 = $validatedArtifacts.summary_sha256
        }
        primary_database_path = "data/processed/stage_1_5f_detection_store.sqlite3"
        run_identity = [ordered]@{
            run_id = $primaryAudit.run_id
            findings_sha256 = $primaryAudit.findings_sha256
            summary_sha256 = $primaryAudit.summary_sha256
        }
        reconciliation = [ordered]@{
            evaluated_record_count = $primaryQueries.run.evaluated_record_count
            invalid_input_count = $primaryQueries.run.invalid_input_count
            total_finding_count = $primaryAudit.finding_count
            evidence_count = $primaryAudit.evidence_count
            unique_matched_source_record_count = $primaryQueries.unique_matched_source_record_count
            findings_by_rule_id = $primaryQueries.findings_by_rule_id
            findings_by_rule_severity = $primaryQueries.findings_by_rule_severity
            findings_by_reason_code = $primaryQueries.findings_by_reason_code
            findings_by_source_type = $primaryQueries.findings_by_source_type
        }
        audit = [ordered]@{
            logical_export_sha256 = $primaryAudit.logical_export_sha256
            reconstructed_findings_sha256 = $primaryAudit.reconstructed_findings_sha256
            rule_count = $primaryAudit.rule_count
        }
        determinism = [ordered]@{
            secondary_database_removed = $true
            logical_export_hashes_match = $true
            reconstructed_finding_hashes_match = $true
            query_output_hashes_match = $true
        }
        security_interpretation = "Stored findings are informational rule observations, not confirmed attacks, malicious activity, or compromise."
        verdict = "PASS"
    }
    $validationSummary | ConvertTo-Json -Depth 12
    & git -c "safe.directory=$repositoryRoot" -C $repositoryRoot status --short
    Require-LastExitCode "Git Safety" "git status"
    Write-Host "========================================"
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
    if ($secondaryDatabaseOwned) {
        Remove-VerifiedSecondaryArtifacts $secondaryDatabase
    }
    Pop-Location
}

exit $exitCode
