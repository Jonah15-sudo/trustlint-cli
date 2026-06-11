from __future__ import annotations

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from weakness_mapper.extractor import WeaknessExtractor
from weakness_mapper.registry import WeaknessRegistry
from weakness_mapper.cluster import WeaknessClusterer
from weakness_mapper.reporter import CapabilityReporter

REPORTS_DIR = "reports/frontier_validation"
REGISTRY_PATH = "weakness_registry.json"
CAPABILITY_REPORT_PATH = "capability_report.json"


def main() -> None:
    registry = WeaknessRegistry(REGISTRY_PATH)
    registry.clear()

    session_files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*_session.json")))
    all_session_data = []

    for sf in session_files:
        base = os.path.basename(sf).replace("_session.json", "")
        rf = sf.replace("_session.json", "_report.json")

        if not os.path.isfile(rf):
            print(f"  SKIP {base}: no report file")
            continue

        with open(sf) as f:
            session_data = json.load(f)
        with open(rf) as f:
            report_data = json.load(f)

        all_session_data.append(session_data)
        weaknesses = WeaknessExtractor.extract(session_data, report_data)
        added = registry.add_weaknesses(weaknesses, session_data.get("session_id", ""))
        print(f"  {base}: extracted {len(weaknesses)} weaknesses, {added} new to registry")

    clusters = WeaknessClusterer.cluster(registry.get_all())
    print(f"\nRegistry: {len(registry.get_all())} total weaknesses")
    print(f"Clusters: {len(clusters)}")
    for c in clusters:
        print(f"  {c.cluster_id}: {c.category}/{c.feature} "
              f"(reproducibility={c.reproducibility_count}, "
              f"sessions={len(c.session_ids)})")

    reporter = CapabilityReporter(registry)
    report = reporter.save_json(CAPABILITY_REPORT_PATH, session_data=all_session_data)
    print(f"\nCapability report saved to {CAPABILITY_REPORT_PATH}")
    print(f"  Total weaknesses: {report['report_metadata']['total_weaknesses']}")
    print(f"  Reproducible: {report['report_metadata']['reproducible_count']}")
    print(f"  Collapse zones: {len(report['collapse_regions'])}")
    print(f"  Recurring failure regions: {len(report['capability_boundaries']['recurring_failure_regions'])}")

    if report["weakest_areas"]:
        print("\n  Weakest areas:")
        for w in report["weakest_areas"][:5]:
            print(f"    {w['category']}/{w['feature']} "
                  f"(reproducibility={w['reproducibility_count']})")

    if report["strongest_areas"]:
        print("\n  Strongest areas (never flagged as weak):")
        for w in report["strongest_areas"][:10]:
            print(f"    {w['category']}/{w['feature']}")


if __name__ == "__main__":
    main()
