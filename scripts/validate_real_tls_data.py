from __future__ import annotations

import csv
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from experiments.real_data_loader import load_real_tls_data

_REQUIRED_FIELDS = [
    "case_id", "timestamp", "tls_valid", "tls_expiry_days", "http_status",
    "partial_response", "timeout", "hsts_present", "csp_present",
    "latency_ms", "bytes_received", "label",
]

_BOOLEAN_FIELDS = {"tls_valid", "partial_response", "timeout", "hsts_present", "csp_present", "label"}

_INTEGER_FIELDS = {"tls_expiry_days", "latency_ms", "bytes_received"}

_MIN_ROWS = 5000
_MIN_POSITIVE_PCT = 10.0


def _is_valid_iso8601(ts: str) -> bool:
    try:
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return True
    except (ValueError, TypeError):
        return False


def _validate_bool(value: Any, path: str) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes"):
            return True
        if value.lower() in ("false", "0", "no"):
            return False
    if isinstance(value, int):
        if value == 1:
            return True
        if value == 0:
            return False
    return None


def _validate_int(value: Any, path: str) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    return None


def validate_row(row: Dict[str, Any], seen_ids: set) -> List[str]:
    errors: List[str] = []

    for field in _REQUIRED_FIELDS:
        if field not in row or row[field] is None:
            errors.append(f"missing required field: {field}")
            return errors

    case_id = str(row.get("case_id", ""))
    if case_id in seen_ids:
        errors.append(f"duplicate case_id: {case_id}")
        return errors

    timestamp = str(row.get("timestamp", ""))
    if not _is_valid_iso8601(timestamp):
        errors.append(f"invalid timestamp: {timestamp}")

    for field in _BOOLEAN_FIELDS:
        val = row.get(field)
        if val is not None:
            parsed = _validate_bool(val, field)
            if parsed is None:
                errors.append(f"invalid boolean in {field}: {val!r}")
                return errors

    for field in _INTEGER_FIELDS:
        val = row.get(field)
        if val is not None:
            parsed = _validate_int(val, field)
            if parsed is None:
                errors.append(f"invalid integer in {field}: {val!r}")
                return errors

    latency = _validate_int(row.get("latency_ms"), "latency_ms")
    if latency is not None and latency < 0:
        errors.append(f"negative latency_ms: {latency}")
        return errors

    bytes_recv = _validate_int(row.get("bytes_received"), "bytes_received")
    if bytes_recv is not None and bytes_recv < 0:
        errors.append(f"negative bytes_received: {bytes_recv}")
        return errors

    expiry = _validate_int(row.get("tls_expiry_days"), "tls_expiry_days")
    if expiry is not None and expiry > 36500:
        errors.append(f"tls_expiry_days exceeds 36500: {expiry}")
        return errors

    return errors


def generate_report(
    file_path: str,
    total_rows: int,
    valid_rows: int,
    skipped_rows: int,
    duplicate_ids: List[str],
    warnings: List[str],
    positive_count: int,
    negative_count: int,
    passed: bool,
) -> Dict[str, Any]:
    total_labeled = positive_count + negative_count
    return {
        "file_path": os.path.abspath(file_path),
        "validation_timestamp": datetime.utcnow().isoformat() + "Z",
        "total_rows": total_rows,
        "valid_rows": valid_rows,
        "skipped_rows": skipped_rows,
        "duplicate_case_ids": duplicate_ids,
        "duplicate_count": len(duplicate_ids),
        "warnings": warnings,
        "label_counts": {
            "positive": positive_count,
            "negative": negative_count,
            "total_labeled": total_labeled,
            "positive_percent": round(positive_count / total_labeled * 100, 2) if total_labeled else 0.0,
        },
        "passed": passed,
    }


def validate_file(file_path: str) -> Dict[str, Any]:
    result = load_real_tls_data(file_path)
    rows = result["valid_rows"]
    summary = result["validation"]

    total = summary["total"]
    valid = summary["valid"]
    skipped = summary["skipped"]
    dup_ids = summary.get("duplicate_ids", [])
    pos = summary.get("positive_count", 0)
    neg = summary.get("negative_count", 0)

    warnings: List[str] = []
    for err in summary.get("validation_errors", []):
        warnings.append(f"row {err.get('row')}: {err.get('error')}")

    if total < _MIN_ROWS:
        warnings.append(f"low row count: {total} (minimum recommended: {_MIN_ROWS})")

    total_labeled = pos + neg
    if total_labeled > 0:
        pct = pos / total_labeled * 100
        if pct < _MIN_POSITIVE_PCT:
            warnings.append(f"low positive label ratio: {pct:.1f}% (minimum recommended: {_MIN_POSITIVE_PCT}%)")

    if skipped > 0:
        warnings.append(f"{skipped} rows were skipped during validation")

    passed = (valid > 0 and skipped == 0 and total >= _MIN_ROWS)

    report = generate_report(
        file_path=file_path,
        total_rows=total,
        valid_rows=valid,
        skipped_rows=skipped,
        duplicate_ids=dup_ids,
        warnings=warnings,
        positive_count=pos,
        negative_count=neg,
        passed=passed,
    )

    return report


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/validate_real_tls_data.py <path_to_dataset>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print(f"Error: file not found: {file_path}")
        sys.exit(1)

    print(f"Validating: {file_path}")
    report = validate_file(file_path)

    report_path = "real_tls_data_validation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Report saved: {report_path}")
    print(f"  Total rows: {report['total_rows']}")
    print(f"  Valid rows: {report['valid_rows']}")
    print(f"  Skipped rows: {report['skipped_rows']}")
    print(f"  Duplicates: {report['duplicate_count']}")
    print(f"  Positive labels: {report['label_counts']['positive']}")
    print(f"  Negative labels: {report['label_counts']['negative']}")
    print(f"  Positive %: {report['label_counts']['positive_percent']}%")
    print(f"  Passed: {report['passed']}")

    if report["warnings"]:
        print("\nWarnings:")
        for w in report["warnings"]:
            print(f"  - {w}")

    if not report["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
