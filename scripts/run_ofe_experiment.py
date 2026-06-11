from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.experiment_runner import ExperimentRunner
from experiments.report import ExperimentReport


def main() -> None:
    print("=" * 56)
    print("  SPL v7.1 -- OFE Experimental Campaign")
    print("=" * 56)

    runner = ExperimentRunner(raw_dir="experiments/raw_runs")
    result = runner.run()

    reporter = ExperimentReport(result, raw_dir="experiments/raw_runs")
    json_path = reporter.save_json("experiment_results.json")
    md_path = reporter.save_markdown("comparison_report.md")

    print(f"\n  JSON: {json_path}")
    print(f"  Report: {md_path}")

    b = result["baseline"]
    o = result["ofe"]
    c = result["comparison"]
    print("\n--- Results ---")
    print(f"  Accuracy:     A={b['accuracy']['accuracy']:.4f}  B={o['accuracy']['accuracy']:.4f}  diff={c['accuracy']['absolute_difference']:+.4f}")
    print(f"  Calibration:  A={b['calibration']['calibration_error']:.4f}  B={o['calibration']['calibration_error']:.4f}  diff={c['calibration_error']['absolute_difference']:+.4f}")
    print(f"  Error rate:   A={b['failure_rate']['error_rate']:.4f}  B={o['failure_rate']['error_rate']:.4f}  diff={c['error_rate']['absolute_difference']:+.4f}")
    print(f"  Collapse:     A={b['collapse']['collapse_rate']:.4f}  B={o['collapse']['collapse_rate']:.4f}  diff={c['collapse_rate']['absolute_difference']:+.4f}")
    print(f"  Weaknesses:   A={b['total_weaknesses']}  B={o['total_weaknesses']}")
    print("Done.")


if __name__ == "__main__":
    main()
