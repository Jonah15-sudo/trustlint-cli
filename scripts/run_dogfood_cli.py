"""Phase 12 — Dogfood CLI runner.

Runs spl-tls-analyze against the dogfood dataset and saves JSON + Markdown
reports to reports/dogfood/.

Usage:
    python scripts/run_dogfood_cli.py [--timeout SECONDS] [--profile NAME]

Default: balanced profile, 10s timeout per domain.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                domains.append(stripped)
    return domains


def run_dogfood(
    domains_file: str,
    profile: str = "balanced",
    timeout: float = 10.0,
    verbose: bool = False,
) -> Dict[str, Any]:
    # Import CLI functions — works from installed package or source
    from scripts.spl_tls_analyze import (
        analyze_domain,
        format_structured_text,
        compute_summary,
    )

    domains = load_domains(domains_file)
    total = len(domains)
    print(f"[dogfood] Loading {total} domains from {os.path.basename(domains_file)}", flush=True)
    print(f"[dogfood] Profile: {profile}, Timeout: {timeout}s", flush=True)
    print(f"[dogfood] Started at: {datetime.now(timezone.utc).isoformat()}Z", flush=True)
    print()

    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    successes = 0
    skipped = 0

    start_time = time.time()

    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{total}] {domain} ...", end=" ", flush=True)
        try:
            r = analyze_domain(domain, profile=profile, timeout=timeout)
            results.append(r)
            successes += 1
            decision = r["final"]["decision"]
            risk = r["final"]["risk"]
            warnings = r["tls_probe"]["warnings"]
            lim = " [LIMITED]" if warnings else ""
            print(f"{decision} / {risk}{lim}", flush=True)
            if verbose:
                print(format_structured_text(r))
                print()
        except Exception as e:
            errors.append(f"{domain}: {e}")
            skipped += 1
            print(f"ERROR -- {e}", flush=True)

    elapsed = time.time() - start_time

    summary = compute_summary(results) if results else {}

    report = {
        "dogfood_metadata": {
            "tool": "spl-tls-analyze",
            "phase": "12 — Dogfood",
            "profile": profile,
            "timeout_seconds": timeout,
            "dataset": os.path.basename(domains_file),
            "total_domains_loaded": total,
            "successes": successes,
            "errors": skipped,
            "started_at": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat() + "Z",
            "elapsed_seconds": round(elapsed, 1),
            "production_ready": False,
            "scope": "local-only",
        },
        "summary": summary,
        "results": results,
        "errors": errors,
    }

    print()
    print(f"[dogfood] Completed in {elapsed:.1f}s")
    print(f"[dogfood] {successes} succeeded, {skipped} errors")
    if summary:
        print(f"[dogfood] ALLOW={summary.get('allow',0)} REVIEW={summary.get('review',0)} "
              f"DENY={summary.get('deny',0)} highest_risk={summary.get('highest_risk','N/A')}")

    return report


def save_report(report: Dict[str, Any], output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, "dogfood_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[dogfood] JSON report written to {json_path}")

    # Generate Markdown report
    from scripts.spl_tls_analyze import format_markdown_output

    results = report["results"]
    profile = report["dogfood_metadata"]["profile"]
    md = format_markdown_output(results, profile)
    md_path = os.path.join(output_dir, "DOGFOOD_REPORT.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[dogfood] Markdown report written to {md_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run spl-tls-analyze dogfood on the dogfood dataset",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Probe timeout per domain in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--profile", choices=["conservative", "balanced", "strict"],
        default="balanced",
        help="Decision operating profile (default: balanced)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print per-domain structured output",
    )
    args = parser.parse_args()

    domains_file = os.path.join(PROJECT_ROOT, "datasets", "dogfood_domains.txt")
    output_dir = os.path.join(PROJECT_ROOT, "reports", "dogfood")

    if not os.path.exists(domains_file):
        print(f"Error: {domains_file} not found", file=sys.stderr)
        return 1

    report = run_dogfood(
        domains_file=domains_file,
        profile=args.profile,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    save_report(report, output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
