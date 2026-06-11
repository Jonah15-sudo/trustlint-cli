# run_vps_dry_run.ps1
# VPS Dry Run — spl-tls-analyze (PowerShell equivalent)
#
# Builds the Docker image, runs the CLI against the VPS dry-run dataset,
# writes JSON and Markdown reports, and prints a summary.
#
# Usage:
#   .\scripts\run_vps_dry_run.ps1
#
# Prerequisites:
#   - Docker Desktop installed and running
#   - Run from the project root (spl_v7_project_with_frontier\spl_v7_project)
#
# This script does NOT:
#   - Expose ports
#   - Start a web server
#   - Start a long-running service
#   - Require a domain or HTTPS
#   - Perform large-scale scanning

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location -LiteralPath $ProjectRoot

$ImageTag = "spl-tls-analyze:0.2.0b0"
$Dataset = "/app/datasets/vps_dry_run_domains.txt"
$ReportDir = "reports/vps_dry_run"
$JsonOut = "/app/reports/vps_dry_run/results.json"
$MdOut = "/app/reports/vps_dry_run/report.md"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VPS DRY RUN - spl-tls-analyze" -ForegroundColor Cyan
Write-Host "  Image: $ImageTag" -ForegroundColor Cyan
Write-Host "  Dataset: $Dataset" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build the Docker image
Write-Host "[1/4] Building Docker image..." -ForegroundColor Yellow
$build = docker build -q -t $ImageTag . 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Docker build failed. Check Dockerfile and try again." -ForegroundColor Red
    exit 1
}
Write-Host "  OK" -ForegroundColor Green
Write-Host ""

# Step 2: Verify dataset exists
Write-Host "[2/4] Checking dataset..." -ForegroundColor Yellow
$datasetPath = Join-Path $ProjectRoot "datasets/vps_dry_run_domains.txt"
if (-not (Test-Path $datasetPath)) {
    Write-Host "ERROR: datasets/vps_dry_run_domains.txt not found" -ForegroundColor Red
    exit 1
}
Write-Host "  OK" -ForegroundColor Green
Write-Host ""

# Step 3: Create report directory
Write-Host "[3/4] Creating report directory..." -ForegroundColor Yellow
$null = New-Item -ItemType Directory -Force -Path (Join-Path $ProjectRoot $ReportDir)
Write-Host "  OK ($ReportDir)" -ForegroundColor Green
Write-Host ""

# Step 4: Run the CLI
Write-Host "[4/4] Running CLI against VPS dry-run dataset..." -ForegroundColor Yellow
Write-Host ""

$result = docker run --rm `
    -v "${ProjectRoot}/datasets:/app/datasets" `
    -v "${ProjectRoot}/reports:/app/reports" `
    $ImageTag `
    $Dataset `
    --json-out $JsonOut `
    --markdown-out $MdOut 2>&1

$exitCode = $LASTEXITCODE

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DRY RUN COMPLETE" -ForegroundColor Cyan
Write-Host "  Exit code: $exitCode" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Print summary from JSON if available
$jsonPath = Join-Path $ProjectRoot "$ReportDir/results.json"
if (Test-Path $jsonPath) {
    Write-Host ""
    $data = Get-Content $jsonPath -Raw | ConvertFrom-Json
    $s = $data.summary
    Write-Host "  Total domains:    $($s.total_domains)"
    Write-Host "  ALLOW:            $($s.allow)"
    Write-Host "  REVIEW:           $($s.review)"
    Write-Host "  DENY:             $($s.deny)"
    Write-Host "  Highest risk:     $($s.highest_risk)"
    Write-Host "  Probe limited:    $($s.probe_limited)"
    Write-Host "  Probe errors:     $($s.probe_errors)"
    Write-Host "  Fallback ALLOW:   $($s.fallback)"
    Write-Host ""

    if ($s.allow -eq 8 -and $s.review -eq 6 -and $s.deny -eq 1) {
        Write-Host "  Results match expected dry-run baseline." -ForegroundColor Green
    } else {
        Write-Host "  Results differ from expected baseline (8 ALLOW / 6 REVIEW / 1 DENY)." -ForegroundColor Yellow
        Write-Host "  This may be due to network drift - document in VPS_DRY_RUN_REPORT_TEMPLATE.md" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Reports:" -ForegroundColor Cyan
Write-Host "    JSON:      $ReportDir/results.json" -ForegroundColor Cyan
Write-Host "    Markdown:  $ReportDir/report.md" -ForegroundColor Cyan
Write-Host ""

exit $exitCode
