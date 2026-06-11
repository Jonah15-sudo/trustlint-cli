#!/usr/bin/env bash
#
# run_vps_dry_run.sh — VPS Dry Run for spl-tls-analyze
#
# Builds the Docker image, runs the CLI against the VPS dry-run dataset,
# writes JSON and Markdown reports, and prints a summary.
#
# Usage:
#   ./scripts/run_vps_dry_run.sh
#
# Prerequisites:
#   - Docker installed
#   - Run from the project root (spl_v7_project_with_frontier/spl_v7_project)
#
# This script does NOT:
#   - Expose ports
#   - Start a web server
#   - Start a long-running service
#   - Require a domain or HTTPS
#   - Perform large-scale scanning

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

IMAGE_TAG="spl-tls-analyze:0.2.0b0"
DATASET="/app/datasets/vps_dry_run_domains.txt"
REPORT_DIR="reports/vps_dry_run"
JSON_OUT="/app/reports/vps_dry_run/results.json"
MD_OUT="/app/reports/vps_dry_run/report.md"

echo "========================================"
echo "  VPS DRY RUN — spl-tls-analyze"
echo "  Image: $IMAGE_TAG"
echo "  Dataset: $DATASET"
echo "========================================"
echo ""

# Step 1: Build the Docker image
echo "[1/4] Building Docker image..."
docker build -q -t "$IMAGE_TAG" . 2>/dev/null || {
    echo "ERROR: Docker build failed. Check Dockerfile and try again."
    exit 1
}
echo "  OK"
echo ""

# Step 2: Verify dataset exists
echo "[2/4] Checking dataset..."
if [ ! -f "datasets/vps_dry_run_domains.txt" ]; then
    echo "ERROR: datasets/vps_dry_run_domains.txt not found"
    exit 1
fi
echo "  OK ($(wc -l < datasets/vps_dry_run_domains.txt) lines)"
echo ""

# Step 3: Create report directory
echo "[3/4] Creating report directory..."
mkdir -p "$REPORT_DIR"
echo "  OK ($REPORT_DIR)"
echo ""

# Step 4: Run the CLI
echo "[4/4] Running CLI against VPS dry-run dataset..."
echo ""

set +e
docker run --rm \
    -v "$(pwd)/datasets:/app/datasets" \
    -v "$(pwd)/reports:/app/reports" \
    "$IMAGE_TAG" \
    "$DATASET" \
    --json-out "$JSON_OUT" \
    --markdown-out "$MD_OUT"
EXIT_CODE=$?
set -e

echo ""
echo "========================================"
echo "  DRY RUN COMPLETE"
echo "  Exit code: $EXIT_CODE"
echo "========================================"

# Print summary from JSON if available
if [ -f "$REPORT_DIR/results.json" ]; then
    echo ""
    python3 -c "
import json
with open('$REPORT_DIR/results.json') as f:
    data = json.load(f)
s = data.get('summary', {})
print(f'  Total domains:    {s.get(\"total_domains\", \"?\")}')
print(f'  ALLOW:            {s.get(\"allow\", \"?\")}')
print(f'  REVIEW:           {s.get(\"review\", \"?\")}')
print(f'  DENY:             {s.get(\"deny\", \"?\")}')
print(f'  Highest risk:     {s.get(\"highest_risk\", \"?\")}')
print(f'  Probe limited:    {s.get(\"probe_limited\", \"?\")}')
print(f'  Probe errors:     {s.get(\"probe_errors\", \"?\")}')
print(f'  Fallback ALLOW:   {s.get(\"fallback\", \"?\")}')
print()
if s.get('allow') == 8 and s.get('review') == 6 and s.get('deny') == 1:
    print('  Results match expected dry-run baseline.')
else:
    print('  Results differ from expected baseline (8 ALLOW / 6 REVIEW / 1 DENY).')
    print('  This may be due to network drift — document in VPS_DRY_RUN_REPORT_TEMPLATE.md')
"
fi

echo ""
echo "  Reports:"
echo "    JSON:    $REPORT_DIR/results.json"
echo "    Markdown: $REPORT_DIR/report.md"
echo ""

exit $EXIT_CODE
