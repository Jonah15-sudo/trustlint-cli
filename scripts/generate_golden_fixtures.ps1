# Generate golden output fixtures from cli_golden_samples.json
# Run from the project root directory

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$Python = "python"
$Script = @"
from __future__ import annotations

import json
import os
import sys

PROJECT_ROOT = os.path.abspath(".")
sys.path.insert(0, PROJECT_ROOT)

from unittest.mock import patch, MagicMock
from scripts.spl_tls_analyze import (
    analyze_domain,
    format_structured_text,
    format_json_output,
    format_markdown_output,
    format_batch_summary,
)
from scripts.run_local_tls_validation import probe_domain

SAMPLES_PATH = os.path.join(PROJECT_ROOT, "datasets", "cli_golden_samples.json")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "tests", "fixtures", "cli_golden")

with open(SAMPLES_PATH, "r", encoding="utf-8") as f:
    dataset = json.load(f)

samples = dataset["samples"]

# Create fixture directories
for sub in ("console", "json", "markdown"):
    os.makedirs(os.path.join(FIXTURES_DIR, sub), exist_ok=True)

# Process each sample
results = []
for sample in samples:
    sid = sample["id"]
    domain = sample["domain"]
    profile = sample["profile"]
    mock_probe = sample["mocked_probe"]

    with patch("scripts.spl_tls_analyze.probe_domain", return_value=mock_probe):
        r = analyze_domain(domain, profile=profile, timeout=10.0)

    # Normalize timestamps in result
    r["probe_timestamp"] = "GENERATED_AT_PLACEHOLDER"

    # Console fixture
    console_text = format_structured_text(r)
    # Normalize any timestamps in console output
    # (console output doesn't show probe_timestamp directly, but safe to normalize)
    console_path = os.path.join(FIXTURES_DIR, "console", f"{sid}.txt")
    with open(console_path, "w", encoding="utf-8") as cf:
        cf.write(console_text)
    print(f"  Wrote console fixture: {sid}.txt", flush=True)

    # JSON fixture (single-result batch)
    json_text = format_json_output([r], profile)
    json_path = os.path.join(FIXTURES_DIR, "json", f"{sid}.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        jf.write(json_text)
    print(f"  Wrote JSON fixture: {sid}.json", flush=True)

    # Markdown fixture (single-result batch)
    md_text = format_markdown_output([r], profile)
    md_path = os.path.join(FIXTURES_DIR, "markdown", f"{sid}.md")
    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write(md_text)
    print(f"  Wrote Markdown fixture: {sid}.md", flush=True)

    results.append(r)

# Batch fixture
batch_console = format_batch_summary(results)
batch_console_path = os.path.join(FIXTURES_DIR, "console", "_batch_summary.txt")
with open(batch_console_path, "w", encoding="utf-8") as cf:
    cf.write(batch_console)
print(f"  Wrote batch console fixture: _batch_summary.txt", flush=True)

batch_json = format_json_output(results, "balanced")
batch_json_path = os.path.join(FIXTURES_DIR, "json", "_batch.json")
with open(batch_json_path, "w", encoding="utf-8") as jf:
    jf.write(batch_json)
print(f"  Wrote batch JSON fixture: _batch.json", flush=True)

batch_md = format_markdown_output(results, "balanced")
batch_md_path = os.path.join(FIXTURES_DIR, "markdown", "_batch.md")
with open(batch_md_path, "w", encoding="utf-8") as mf:
    mf.write(batch_md)
print(f"  Wrote batch Markdown fixture: _batch.md", flush=True)

print(f"\nDone. Generated {len(samples)} individual fixtures + 3 batch fixtures.")
"@

# Write temp Python script and execute it
$TempScript = Join-Path $env:TEMP "gen_fixtures.py"
$Script | Set-Content -Path $TempScript -Encoding UTF8

Write-Host "Generating golden fixtures..."
& $Python $TempScript

Remove-Item $TempScript -Force
