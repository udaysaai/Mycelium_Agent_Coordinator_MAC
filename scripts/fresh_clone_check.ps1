# scripts/fresh_clone_check.ps1
# Phase 0.7 Reproducible Fresh-Clone Verification Script
# Writes un-truncated UTF-8 output directly at capture time.

$ErrorActionPreference = "Stop"

$repoDir = (Get-Item $PSScriptRoot).Parent.FullName
$evidenceDir = Join-Path $repoDir "evidence"
if (-not (Test-Path $evidenceDir)) {
    New-Item -ItemType Directory -Path $evidenceDir -Force | Out-Null
}

$evidenceFile = Join-Path $evidenceDir "fresh_clone_pytest.txt"
$tempBase = [System.IO.Path]::GetTempPath()
$uniqueDir = "mac_fresh_check_" + [System.Guid]::NewGuid().ToString("N")
$tempDir = Join-Path $tempBase $uniqueDir

Write-Host "[1/6] Creating clean temporary clone directory: $tempDir"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    $cloneDir = Join-Path $tempDir "repo"
    Write-Host "[2/6] Cloning repository into fresh directory..."
    git clone $repoDir $cloneDir
    if ($LASTEXITCODE -ne 0) {
        throw "git clone failed with exit code $LASTEXITCODE"
    }

    $commitHash = ""
    Push-Location $cloneDir
    try {
        $commitHash = (git rev-parse HEAD).Trim()
    } finally {
        Pop-Location
    }

    $venvDir = Join-Path $tempDir "venv"
    Write-Host "[3/6] Creating fresh virtual environment at $venvDir..."
    python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) {
        throw "python -m venv failed with exit code $LASTEXITCODE"
    }

    $pythonExe = Join-Path $venvDir "Scripts\python.exe"
    $pipExe = Join-Path $venvDir "Scripts\pip.exe"

    Write-Host "[4/6] Installing dependencies from pinned requirements.txt..."
    $reqFile = Join-Path $cloneDir "requirements.txt"
    & $pipExe install -r $reqFile --no-warn-script-location
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed with exit code $LASTEXITCODE"
    }

    Write-Host "[5/6] Capturing environment metadata..."
    $pyVer = (& $pythonExe --version 2>&1).Trim()
    $pipList = (& $pipExe freeze 2>&1) -join "`n"

    $header = @"
================================================================================
MAC FRESH CLONE VERIFICATION RUN (Phase 0.7)
Commit: $commitHash
Python: $pyVer
Capture Time: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')
Encoding: UTF-8 (Direct Capture)
================================================================================

--- PIP FREEZE ---
$pipList

--- PYTEST EXECUTION ---
"@

    # Initialize evidence file with UTF-8 encoding
    [System.IO.File]::WriteAllText($evidenceFile, ($header + "`n`n"), [System.Text.Encoding]::UTF8)

    Write-Host "[6/6] Executing pytest -v -rs and streaming raw UTF-8 output to $evidenceFile..."
    Push-Location $cloneDir
    try {
        # Execute pytest and append output in UTF-8
        $pytestOutput = & $pythonExe -m pytest -v -rs *>&1
        $testExitCode = $LASTEXITCODE
        $pytestText = $pytestOutput -join "`r`n"
        [System.IO.File]::AppendAllText($evidenceFile, ($pytestText + "`r`n`nExit Code: $testExitCode`r`n"), [System.Text.Encoding]::UTF8)
        Write-Host $pytestText
    } finally {
        Pop-Location
    }

    Write-Host "`nTest Execution Finished. Exit Code: $testExitCode"
    if ($testExitCode -ne 0) {
        exit $testExitCode
    }
} finally {
    Write-Host "Cleaning up temporary clone directory..."
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
