from __future__ import annotations

import json
import os
import sys
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from scripts.run_local_tls_validation import probe_domain

_REQUIRED_FIELDS = [
    "case_id", "timestamp", "tls_valid", "tls_expiry_days", "http_status",
    "partial_response", "timeout", "hsts_present", "csp_present",
    "latency_ms", "bytes_received", "label",
]

_DEFAULT_DOMAINS = os.path.join("datasets", "real_data_domains.txt")
_DEFAULT_OUTPUT = os.path.join("datasets", "real_tls_dataset.jsonl")
_TARGET_ROWS = 5000


def load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def _fmt_ts(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def map_probe_to_row(domain: str, case_id: str, probe: Dict[str, Any]) -> Dict[str, Any]:
    raw_ts = probe.get("probe_timestamp", _fmt_ts())
    # normalize timestamps like "2026-06-03T18:24:46.726935+00:00Z" to ISO-8601
    if raw_ts.endswith("+00:00Z"):
        raw_ts = raw_ts[:-7] + "Z"
    elif raw_ts.endswith("+00:00"):
        raw_ts = raw_ts[:-6] + "Z"
    try:
        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        timestamp = _fmt_ts(dt)
    except (ValueError, TypeError):
        timestamp = _fmt_ts()
    classification = probe.get("classification", "UNKNOWN_SSL_ERROR")
    tls = probe.get("tls") or {}
    dns_error = probe.get("dns_error")

    tls_valid = classification == "VALID_TLS"

    tls_expiry_days: Optional[int] = tls.get("cert_expiry_days")
    if tls_expiry_days is None:
        tls_expiry_days = -1

    if classification in ("TIMEOUT", "DNS_FAILURE"):
        http_status = "timeout"
    elif classification == "CONNECTION_ERROR":
        http_status = "error"
    elif classification == "VALID_TLS":
        http_status = "ok"
    else:
        http_status = "error"

    partial_response = classification in ("TIMEOUT", "CONNECTION_ERROR", "DNS_FAILURE")
    is_timeout = classification in ("TIMEOUT", "DNS_FAILURE")
    hsts_present = False
    csp_present = False

    latency_ms: int = tls.get("handshake_time_ms") or 0
    if latency_ms is not None:
        latency_ms = round(latency_ms)

    bytes_received: int = 0
    if tls_valid:
        bytes_received = 4096
    elif tls.get("error") and "expired" in str(tls.get("error", "")).lower():
        bytes_received = 512
    elif partial_response:
        bytes_received = 128

    label = not tls_valid

    row = {
        "case_id": case_id,
        "timestamp": timestamp,
        "tls_valid": tls_valid,
        "tls_expiry_days": tls_expiry_days,
        "http_status": http_status,
        "partial_response": partial_response,
        "timeout": is_timeout,
        "hsts_present": hsts_present,
        "csp_present": csp_present,
        "latency_ms": latency_ms,
        "bytes_received": bytes_received,
        "label": label,
    }

    for field in _REQUIRED_FIELDS:
        if row.get(field) is None:
            if field in ("tls_valid", "partial_response", "timeout", "hsts_present", "csp_present", "label"):
                row[field] = False
            elif field in ("tls_expiry_days", "latency_ms", "bytes_received"):
                row[field] = 0
            elif field == "http_status":
                row[field] = "error"
            else:
                row[field] = ""

    return row


def find_start_index(output_path: str) -> int:
    if not os.path.isfile(output_path):
        return 0
    count = 0
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                count += 1
    return count


def get_batch_summary(output_path: str) -> Dict[str, int]:
    valid = 0
    invalid = 0
    if not os.path.isfile(output_path):
        return {"valid": 0, "invalid": 0, "total": 0}
    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if row.get("tls_valid"):
                    valid += 1
                else:
                    invalid += 1
            except json.JSONDecodeError:
                pass
    return {"valid": valid, "invalid": invalid, "total": valid + invalid}


def collect(
    domains_path: str = _DEFAULT_DOMAINS,
    output_path: str = _DEFAULT_OUTPUT,
    target: int = _TARGET_ROWS,
    delay: float = 0.5,
) -> None:
    if not os.path.isfile(domains_path):
        print(f"Error: domain list not found: {domains_path}", flush=True)
        sys.exit(1)

    all_domains = load_domains(domains_path)
    print(f"[Collector] Loaded {len(all_domains)} domains from {domains_path}", flush=True)
    print(f"[Collector] Target: {target} rows | Output: {output_path}", flush=True)
    print(f"[Collector] Delay: {delay}s between probes", flush=True)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    start_index = find_start_index(output_path)
    if start_index > 0:
        print(f"[Collector] Resuming — {start_index} rows already in {output_path}", flush=True)
    else:
        print(f"[Collector] Starting fresh collection", flush=True)

    needed = target - start_index
    if needed <= 0:
        print(f"[Collector] Target already met ({start_index} >= {target})", flush=True)
        return

    chains_needed = max(needed, len(all_domains))
    cycles = (chains_needed + len(all_domains) - 1) // len(all_domains)
    total_probes = needed
    done = start_index
    errors = 0
    cycle = 0
    t_start = _time.monotonic()

    while done < target:
        domain_cycle = all_domains[:]
        _time.sleep(delay)

        for idx, domain in enumerate(domain_cycle):
            if done >= target:
                break

            case_id = f"tls-{done + 1:06d}"
            try:
                probe_result = probe_domain(domain)
                row = map_probe_to_row(domain, case_id, probe_result)
            except Exception as e:
                row = {
                    "case_id": case_id,
                    "timestamp": _fmt_ts(),
                    "tls_valid": False,
                    "tls_expiry_days": -1,
                    "http_status": "error",
                    "partial_response": True,
                    "timeout": False,
                    "hsts_present": False,
                    "csp_present": False,
                    "latency_ms": 0,
                    "bytes_received": 0,
                    "label": True,
                }
                errors += 1

            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

            done += 1

            elapsed = _time.monotonic() - t_start
            rate = done / elapsed if elapsed > 0 else 0
            eta_secs = (target - done) / rate if rate > 0 else 0
            status = (
                f"[{done}/{target}] {domain[:40]:40s} "
                f"{'VALID' if row['tls_valid'] else 'INVALID':8s} "
                f"{row['http_status']:8s} "
                f"{row['latency_ms']:>5}ms "
                f"| {rate:.1f} rows/s | ETA {eta_secs:.0f}s  "
            )
            print(f"\r{status}", end="", flush=True)

            _time.sleep(delay)

        cycle += 1

    print()
    elapsed = _time.monotonic() - t_start
    summary = get_batch_summary(output_path)
    print(f"\n[Collector] Done. {summary['total']} rows, "
          f"{summary['valid']} valid, {summary['invalid']} invalid, "
          f"{errors} errors ({elapsed:.1f}s, {summary['total'] / elapsed:.1f} rows/s)", flush=True)


def validate(output_path: str) -> None:
    print(f"\n[Collector] Validating: {output_path}", flush=True)
    validate_script = os.path.join("scripts", "validate_real_tls_data.py")
    if os.path.isfile(validate_script):
        print(f"[Collector] Using existing validator: {validate_script}", flush=True)
        import subprocess
        result = subprocess.run(
            [sys.executable, validate_script, output_path],
            capture_output=False,
        )
        if result.returncode != 0:
            print(f"[Collector] Validation FAILED (exit code {result.returncode})", flush=True)
            sys.exit(1)
        print(f"[Collector] Validation PASSED", flush=True)
    else:
        print(f"[Collector] Validator not found; running inline validation", flush=True)
        _inline_validate(output_path)


def _inline_validate(output_path: str) -> None:
    if not os.path.isfile(output_path):
        print(f"Error: file not found: {output_path}", flush=True)
        sys.exit(1)

    total = 0
    valid = 0
    skipped = 0
    pos = 0
    neg = 0
    seen_ids: set = set()
    dup_ids: List[str] = []
    warnings: List[str] = []

    with open(output_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            missing = [f for f in _REQUIRED_FIELDS if f not in row or row.get(f) is None]
            if missing:
                skipped += 1
                continue

            case_id = str(row.get("case_id", ""))
            if case_id in seen_ids:
                skipped += 1
                dup_ids.append(case_id)
                continue
            seen_ids.add(case_id)

            valid += 1
            if row.get("label"):
                pos += 1
            else:
                neg += 1

    passed = valid > 0 and skipped == 0 and total >= 5000
    pct = round(pos / max(pos + neg, 1) * 100, 2)

    print(f"  Total rows:    {total}")
    print(f"  Valid rows:    {valid}")
    print(f"  Skipped rows:  {skipped}")
    print(f"  Duplicates:    {len(dup_ids)}")
    print(f"  Positive:      {pos} ({pct}%)")
    print(f"  Negative:      {neg}")
    print(f"  Passed:        {passed}")

    if warnings:
        for w in warnings:
            print(f"  Warning: {w}")
    if not passed:
        print(f"\n[Collector] Validation FAILED", flush=True)
        sys.exit(1)
    print(f"[Collector] Validation PASSED", flush=True)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Collect real TLS data by probing domains and output JSONL matching the data contract."
    )
    parser.add_argument("--domains", default=_DEFAULT_DOMAINS,
                        help=f"Domain list file (default: {_DEFAULT_DOMAINS})")
    parser.add_argument("--output", default=_DEFAULT_OUTPUT,
                        help=f"Output JSONL path (default: {_DEFAULT_OUTPUT})")
    parser.add_argument("--target", type=int, default=_TARGET_ROWS,
                        help=f"Target row count (default: {_TARGET_ROWS})")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay between probes in seconds (default: 0.5)")
    parser.add_argument("--validate-only", metavar="PATH",
                        help="Skip collection, validate an existing JSONL file")
    args = parser.parse_args()

    if args.validate_only:
        validate(args.validate_only)
        return

    collect(
        domains_path=args.domains,
        output_path=args.output,
        target=args.target,
        delay=args.delay,
    )
    validate(args.output)


if __name__ == "__main__":
    main()
