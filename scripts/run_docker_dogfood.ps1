# run_docker_dogfood.ps1
# Run dogfood inside Docker and compare results with native CLI.
#
# Prerequisites:
#   - Docker Desktop installed and running
#   - Image built: docker build -t spl-tls-analyze:0.2.0b0 .
#
# Expected result: 19 ALLOW / 11 REVIEW / 1 DENY

$image = "spl-tls-analyze:0.2.0b0"
$domainFile = "/app/datasets/dogfood_domains.txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DOCKER DOGFOOD RUN" -ForegroundColor Cyan
Write-Host "  Image: $image" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$result = docker run --rm --network host -v "${PWD}/reports:/app/reports" $image $domainFile --json-out /app/reports/docker_dogfood_results.json 2>&1

# Print the console output
Write-Host "CONSOLE OUTPUT:" -ForegroundColor Yellow
$result | ForEach-Object { Write-Host $_ }
Write-Host ""

# Parse the JSON result
$jsonPath = Join-Path $PWD "reports/docker_dogfood_results.json"
if (Test-Path $jsonPath) {
    $json = Get-Content $jsonPath -Raw | ConvertFrom-Json
    $summary = $json.summary

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  DOCKER DOGFOOD SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Total domains:    $($summary.total_domains)"
    Write-Host "  ALLOW:            $($summary.allow)"
    Write-Host "  REVIEW:           $($summary.review)"
    Write-Host "  DENY:             $($summary.deny)"
    Write-Host "  Highest risk:     $($summary.highest_risk)"
    Write-Host "  Probe limited:    $($summary.probe_limited)"
    Write-Host "  Probe errors:     $($summary.probe_errors)"
    Write-Host ""

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  EXPECTED (native):  19 ALLOW / 11 REVIEW / 1 DENY" -ForegroundColor Yellow
    Write-Host "  DOCKER:             $($summary.allow) ALLOW / $($summary.review) REVIEW / $($summary.deny) DENY" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan

    if ($summary.allow -eq 19 -and $summary.review -eq 11 -and $summary.deny -eq 1) {
        Write-Host "  DOGFOOD MATCHED — behavior is reproducible in Docker" -ForegroundColor Green
    } else {
        Write-Host "  DOGFOOD DIFFERS — document drift in DOCKER_USAGE.md" -ForegroundColor Red
        Write-Host "  Possible causes: network differences, DNS resolution," -ForegroundColor Red
        Write-Host "  container timeouts, or OpenSSL version mismatch." -ForegroundColor Red
    }
    Write-Host "========================================" -ForegroundColor Cyan
} else {
    Write-Host "  WARNING: JSON output not found at $jsonPath" -ForegroundColor Red
    Write-Host "  The Docker run may have failed or --json-out path differs." -ForegroundColor Red
}
