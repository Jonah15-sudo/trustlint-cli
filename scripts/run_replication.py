#!/usr/bin/env python3
"""
Month 5 — Replication & Statistical Validation Campaign

Runs multiple independent A/B campaigns and generates:
  - REPLICATION_REPORT.md (which effects repeated / disappeared / uncertain)
  - PROMOTION_READINESS.md  (PROMOTE / HOLD / REJECT per signal)
"""

from __future__ import annotations

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from experiments.replication import ReplicationRunner
from experiments.replication_report import generate_replication_report
from experiments.promotion_readiness import generate_promotion_readiness


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Month 5 — OFE Replication Campaign"
    )
    parser.add_argument(
        "--campaigns", type=int, default=12,
        help="Number of independent campaigns to run (default: 12)"
    )
    parser.add_argument(
        "--raw-dir", default="experiments/replication",
        help="Output directory for per-campaign results (default: experiments/replication)"
    )
    parser.add_argument(
        "--report-path", default="REPLICATION_REPORT.md",
        help="Path for the replication report (default: REPLICATION_REPORT.md)"
    )
    parser.add_argument(
        "--readiness-path", default="PROMOTION_READINESS.md",
        help="Path for the promotion readiness report (default: PROMOTION_READINESS.md)"
    )
    parser.add_argument(
        "--skip-rerun", action="store_true",
        help="Skip re-running campaigns; aggregate from existing results"
    )

    args = parser.parse_args()

    if args.skip_rerun:
        print("Skipping re-run — aggregating from existing results...")
        aggregate = _aggregate_existing(args.raw_dir)
    else:
        runner = ReplicationRunner(
            campaign_count=args.campaigns,
            raw_dir=args.raw_dir,
        )
        aggregate = runner.run_all()

        # Save aggregate
        agg_path = os.path.join(args.raw_dir, "aggregate_results.json")
        with open(agg_path, "w") as f:
            json.dump(aggregate, f, indent=2, ensure_ascii=True)
        print(f"Wrote {agg_path}")

    generate_replication_report(aggregate, args.report_path)
    generate_promotion_readiness(aggregate, args.readiness_path)

    print("\nDone.")
    print(f"  Replication report:  {args.report_path}")
    print(f"  Promotion readiness: {args.readiness_path}")


def _aggregate_existing(raw_dir: str) -> dict:
    import glob
    from experiments.replication import ReplicationRunner

    runner = ReplicationRunner(raw_dir=raw_dir)
    campaigns: list[dict] = []
    run_dir = os.path.join(raw_dir, "runs")

    if not os.path.isdir(run_dir):
        print(f"No runs directory found at {run_dir}")

    seed_dirs = sorted(glob.glob(os.path.join(run_dir, "campaign_*")))
    if not seed_dirs:
        print(f"No campaign directories found under {run_dir}")

    for sd in seed_dirs:
        result_path = os.path.join(sd, "experiment_results.json")
        if os.path.isfile(result_path):
            with open(result_path) as f:
                campaigns.append(json.load(f))

    if not campaigns:
        print("No campaign results loaded — returning empty aggregate")

    return runner._aggregate(campaigns)


if __name__ == "__main__":
    main()
