[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Database,

    [Parameter(Mandatory = $true)]
    [string]$FindingsInput,

    [Parameter(Mandatory = $true)]
    [string]$SummaryInput,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedRunId,

    [ValidateRange(1, 65535)]
    [int]$Port = 8000,

    [string]$SummaryOutput
)

$ErrorActionPreference = "Stop"

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = (Resolve-Path (Join-Path $scriptDirectory "..")).Path
$python = Join-Path $repositoryRoot ".venv\Scripts\python.exe"
$testsDirectory = Join-Path $repositoryRoot "tests"
$validator = Join-Path $repositoryRoot "src\validate_api.py"

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

function Require-File {
    param([string]$Path, [string]$Description)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail-Validation "Inputs" "Missing ${Description}."
    }
}

function Assert-GitDataSafety {
    $tracked = @(
        & git -C $repositoryRoot ls-files -- `
            "data/raw/**" "data/processed/**" "*.db" "*.sqlite" "*.sqlite3" `
            "*.db-wal" "*.db-shm"
    )
    Require-LastExitCode "Git Safety" "tracked data/database inspection"
    if ($tracked.Count -gt 0) {
        Fail-Validation "Git Safety" "Raw, processed, or SQLite artifacts are tracked."
    }
}

function Invoke-Python {
    param([string]$Stage, [string[]]$Arguments)

    & $python @Arguments
    Require-LastExitCode $Stage "Python command"
}

function Invoke-CompleteSuite {
    param([string]$Label)

    Write-Host "`n${Label}: unittest"
    Invoke-Python $Label @("-m", "unittest", "discover", "-s", $testsDirectory, "-p", "test_*.py", "-v")
    Write-Host "${Label}: pytest"
    Invoke-Python $Label @("-m", "pytest", $testsDirectory, "-q")
}

$exitCode = 0
Push-Location -LiteralPath $repositoryRoot
try {
    Write-Host "========================================"
    Write-Host "Stage 1.6F Real-Store API Validation"
    Write-Host "========================================"

    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Fail-Validation "Environment" "Project Python virtual environment is unavailable."
    }
    Require-File $validator "Stage 1.6F validator"
    Require-File $Database "database"
    Require-File $FindingsInput "finding artifact"
    Require-File $SummaryInput "summary artifact"

    Write-Host "`n[1/6] Python and dependency validation"
    $pythonVersion = & $python --version 2>&1
    Require-LastExitCode "Environment" "Python version check"
    if (([string]$pythonVersion) -notmatch "^Python 3\.12\.") {
        Fail-Validation "Environment" "Python 3.12 is required."
    }
    Write-Host $pythonVersion
    Invoke-Python "Dependencies" @("-m", "pip", "check")

    Write-Host "`n[2/6] Synthetic regression before real validation"
    Invoke-CompleteSuite "Full suite before validation"

    Write-Host "`n[3/6] Git and input safety before real validation"
    Assert-GitDataSafety
    & git -C $repositoryRoot diff --check
    Require-LastExitCode "Git Safety" "git diff --check"

    Write-Host "`n[4/6] Real read-only API validation"
    $validatorArguments = @(
        $validator,
        "--database", $Database,
        "--findings", $FindingsInput,
        "--summary", $SummaryInput,
        "--expected-run-id", $ExpectedRunId,
        "--port", $Port.ToString()
    )
    if (-not [string]::IsNullOrWhiteSpace($SummaryOutput)) {
        $validatorArguments += @("--summary-output", $SummaryOutput)
    }
    Invoke-Python "Real API validation" $validatorArguments

    Write-Host "`n[5/6] Synthetic regression after real validation"
    Invoke-CompleteSuite "Full suite after validation"

    Write-Host "`n[6/6] Final Git safety"
    & git -C $repositoryRoot diff --check
    Require-LastExitCode "Git Safety" "git diff --check"
    Assert-GitDataSafety
    & git -C $repositoryRoot diff --stat
    Require-LastExitCode "Git Safety" "git diff --stat"
    & git -C $repositoryRoot status --short
    Require-LastExitCode "Git Safety" "git status"
    Write-Host "========================================"
    Write-Host "FINAL RESULT: PASS"
    Write-Host "========================================"
}
catch {
    Write-Host "FAILED GATE: $($_.Exception.Message)"
    Write-Host "========================================"
    Write-Host "FINAL RESULT: FAIL"
    Write-Host "========================================"
    $exitCode = 1
}
finally {
    Pop-Location
}

exit $exitCode
