from __future__ import annotations

import json
import os
import sys
import time as _time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_local_tls_validation import probe_domain

REPORT_DIR = "reports/reliability_campaign"
BENCHMARK_DATASET = "datasets/reliability_benchmark_domains.txt"
RATE_LIMIT_SECONDS = 0.5
NUM_RUNS = 5
RUN_SPACING_SECONDS = 30


def load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def run_campaign(domains: List[str], run_label: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    start = _time.monotonic()

    print(f"[Campaign {run_label}] Starting probe of {len(domains)} domains...", flush=True)

    for i, domain in enumerate(domains):
        print(f"  [{i + 1}/{len(domains)}] {domain}...", end=" ", flush=True)
        try:
            r = probe_domain(domain)
            classification = r.get("classification", "UNKNOWN_SSL_ERROR")
            tls = r.get("tls") or {}
            handshake = tls.get("handshake_time_ms", None)
            err = tls.get("error") or r.get("dns_error") or ""
            ip = r.get("resolved_ip", None)
            print(f"{classification} ({handshake}ms)" if handshake else f"{classification}", flush=True)
            results[domain] = {
                "classification": classification,
                "handshake_time_ms": handshake,
                "error": err,
                "resolved_ip": ip,
                "overall_status": r.get("overall_status", ""),
                "tls_version": tls.get("tls_version"),
                "cert_issuer": tls.get("cert_issuer"),
                "cert_expiry_days": tls.get("cert_expiry_days"),
                "chain_subtype": tls.get("chain_subtype"),
                "dns_error": r.get("dns_error", ""),
            }
        except Exception as e:
            print(f"ERROR ({e})", flush=True)
            results[domain] = {
                "classification": "PROBE_ERROR",
                "handshake_time_ms": None,
                "error": str(e),
                "resolved_ip": None,
                "overall_status": "probe_error",
                "tls_version": None,
                "cert_issuer": None,
                "cert_expiry_days": None,
                "chain_subtype": None,
                "dns_error": "",
            }

        if i < len(domains) - 1:
            _time.sleep(RATE_LIMIT_SECONDS)

    elapsed = _time.monotonic() - start
    print(f"[Campaign {run_label}] Completed in {elapsed:.1f}s", flush=True)

    return {
        "run_label": run_label,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "elapsed_seconds": round(elapsed, 1),
        "domains_probed": len(results),
        "results": results,
    }


def compute_stability(campaigns: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_domains: set = set()
    for c in campaigns:
        all_domains.update(c["results"].keys())

    domain_stability: Dict[str, Any] = {}
    transitions: Counter = Counter()
    total_probes = 0
    stable_classification = 0
    stable_decision = 0
    timeout_count = 0
    dns_failure_count = 0
    probe_error_count = 0
    handshake_times: Dict[str, List[float]] = {}
    classification_sequences: Dict[str, List[str]] = {}
    resolved_ips: Dict[str, set] = {}
    full_transition_matrix: Dict[str, Counter] = {}

    for domain in sorted(all_domains):
        classifications: List[str] = []
        decisions: List[str] = []
        times: List[float] = []
        ips: set = set()

        for c in campaigns:
            r = c["results"].get(domain)
            if not r:
                continue
            total_probes += 1
            classifications.append(r.get("classification", "UNKNOWN_SSL_ERROR"))
            decisions.append(r.get("overall_status", "unknown"))
            if r.get("handshake_time_ms") is not None:
                times.append(r["handshake_time_ms"])
            if r.get("resolved_ip"):
                ips.add(r["resolved_ip"])
            if r.get("classification") == "TIMEOUT":
                timeout_count += 1
            if r.get("classification") == "DNS_FAILURE":
                dns_failure_count += 1
            if r.get("classification") == "PROBE_ERROR":
                probe_error_count += 1

        classification_sequences[domain] = classifications

        # Track transitions
        for i in range(1, len(classifications)):
            trans = (classifications[i - 1], classifications[i])
            transitions[trans] += 1
            if trans not in full_transition_matrix:
                full_transition_matrix[trans] = Counter()
            full_transition_matrix[trans][domain] += 1

        # Classification stability: all same
        unique_class = set(classifications)
        is_class_stable = len(unique_class) == 1
        if is_class_stable:
            stable_classification += 1

        # Decision stability
        unique_dec = set(decisions)
        is_dec_stable = len(unique_dec) == 1
        if is_dec_stable:
            stable_decision += 1

        if times:
            handshake_times[domain] = times

        resolved_ips[domain] = ips

        domain_stability[domain] = {
            "classification_sequence": classifications,
            "unique_classifications": sorted(unique_class),
            "classifications_stable": is_class_stable,
            "decisions_stable": is_dec_stable,
            "total_probes": len(classifications),
            "handshake_times_ms": times,
            "handshake_mean_ms": round(sum(times) / len(times), 1) if times else None,
            "handshake_std_ms": round(
                (sum((t - sum(times) / len(times)) ** 2 for t in times) / len(times)) ** 0.5, 1
            ) if len(times) > 1 else 0.0,
            "resolved_ips": sorted(ips),
            "ip_count": len(ips),
        }

    total_domains = len(all_domains)

    # Summary stats
    class_stable_pct = round(stable_classification / total_domains * 100, 1) if total_domains else 0
    dec_stable_pct = round(stable_decision / total_domains * 100, 1) if total_domains else 0

    # Handshake performance variance across campaigns
    handshake_variances: Dict[str, Any] = {}
    for domain, times in handshake_times.items():
        if len(times) > 1:
            mean_t = sum(times) / len(times)
            variance = sum((t - mean_t) ** 2 for t in times) / len(times)
            cv = (variance ** 0.5) / mean_t if mean_t > 0 else 0
            handshake_variances[domain] = {
                "mean_ms": round(mean_t, 1),
                "std_ms": round(variance ** 0.5, 1),
                "cv": round(cv, 3),
                "min_ms": min(times),
                "max_ms": max(times),
            }

    # Unstable domains (classification changes)
    unstable_domains = [
        d for d, s in domain_stability.items() if not s["classifications_stable"]
    ]

    # Top transitions
    top_transitions = [
        {"from": f, "to": t, "count": c}
        for (f, t), c in transitions.most_common(20)
    ]

    return {
        "total_domains": total_domains,
        "total_probes": total_probes,
        "num_campaigns": len(campaigns),
        "classification_stable_domains": stable_classification,
        "classification_stability_pct": class_stable_pct,
        "decision_stable_domains": stable_decision,
        "decision_stability_pct": dec_stable_pct,
        "timeout_count": timeout_count,
        "dns_failure_count": dns_failure_count,
        "probe_error_count": probe_error_count,
        "operational_error_rate_pct": round(
            (timeout_count + dns_failure_count + probe_error_count) / total_probes * 100, 2
        ) if total_probes else 0,
        "probe_success_rate_pct": round(
            (total_probes - timeout_count - dns_failure_count - probe_error_count) / total_probes * 100, 2
        ) if total_probes else 0,
        "unstable_domains": unstable_domains,
        "unstable_domain_count": len(unstable_domains),
        "unstable_rate_pct": round(len(unstable_domains) / total_domains * 100, 2) if total_domains else 0,
        "top_transitions": top_transitions,
        "domain_stability": domain_stability,
        "handshake_performance": handshake_variances,
        "full_transition_matrix": {f"{f}->{t}": dict(d) for (f, t), d in full_transition_matrix.items()},
    }


def generate_scorecard(stability: Dict[str, Any]) -> str:
    lines = [
        "# Operational Reliability Scorecard",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"Campaigns: {stability['num_campaigns']}",
        f"Benchmark domains: {stability['total_domains']}",
        f"Total probes: {stability['total_probes']}",
        "",
        "## Core Stability Metrics",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Classification stability rate | {stability['classification_stability_pct']}% |",
        f"| Decision stability rate | {stability['decision_stability_pct']}% |",
        f"| Operational error rate | {stability['operational_error_rate_pct']}% |",
        f"| Probe success rate | {stability['probe_success_rate_pct']}% |",
        f"| Unstable domains | {stability['unstable_domain_count']} ({stability['unstable_rate_pct']}%) |",
        "",
        "## Classification vs Decision Stability",
        "",
        f"- **Classification stable domains**: {stability['classification_stable_domains']}/{stability['total_domains']} ({stability['classification_stability_pct']}%)",
        f"- **Decision stable domains**: {stability['decision_stable_domains']}/{stability['total_domains']} ({stability['decision_stability_pct']}%)",
        "",
        "## Operational Errors",
        "",
        "| Error Type | Count | Across Campaigns |",
        "|---|---|---|",
        f"| TIMEOUT | {stability['timeout_count']} | {stability['num_campaigns']} runs |",
        f"| DNS_FAILURE | {stability['dns_failure_count']} | {stability['num_campaigns']} runs |",
        f"| PROBE_ERROR | {stability['probe_error_count']} | {stability['num_campaigns']} runs |",
        f"| **Total operational errors** | {stability['timeout_count'] + stability['dns_failure_count'] + stability['probe_error_count']} | |",
        "",
        f"**Operational error rate**: {stability['operational_error_rate_pct']}% of all probes",
        f"**Probe success rate**: {stability['probe_success_rate_pct']}% of all probes",
        "",
        "## Unstable Domains",
        "",
    ]

    unstable = stability.get("unstable_domains", [])
    if unstable:
        lines.append(f"Found **{len(unstable)}** domains with classification changes across campaigns:")
        lines.append("")
        lines.append("| Domain | Classification Sequence | IP Changes | Root Cause Notes |")
        lines.append("|---|---|---|---|")
        for domain in unstable:
            ds = stability["domain_stability"][domain]
            seq = " → ".join(ds["classification_sequence"])
            ip_count = ds["ip_count"]
            lines.append(f"| {domain} | {seq} | {ip_count} IPs | See drift analysis |")
    else:
        lines.append("**No unstable domains detected.** All domains maintained consistent classification across all campaigns.")
    lines.append("")

    if stability.get("top_transitions"):
        lines.extend([
            "## Top Classification Transitions",
            "",
            "| From | To | Count |",
            "|---|---|---|",
        ])
        for t in stability["top_transitions"]:
            lines.append(f"| {t['from']} | {t['to']} | {t['count']} |")
        lines.append("")

    return "\n".join(lines)


def save_results(campaigns: List[Dict[str, Any]], stability: Dict[str, Any]):
    os.makedirs(REPORT_DIR, exist_ok=True)

    # Save individual campaign results
    campaign_path = os.path.join(REPORT_DIR, "campaigns.json")
    with open(campaign_path, "w", encoding="utf-8") as f:
        json.dump(campaigns, f, indent=2, default=str)
    print(f"[Reliability] Campaign results saved to {campaign_path}", flush=True)

    # Save stability analysis
    stability_path = os.path.join(REPORT_DIR, "stability_analysis.json")
    # Extract for JSON (remove domain_stability which is large)
    stability_export = {k: v for k, v in stability.items() if k != "domain_stability"}
    stability_export["domain_count"] = stability["total_domains"]
    with open(stability_path, "w", encoding="utf-8") as f:
        json.dump(stability_export, f, indent=2, default=str)
    print(f"[Reliability] Stability analysis saved to {stability_path}", flush=True)

    # Save scorecard
    scorecard = generate_scorecard(stability)
    scorecard_path = os.path.join(REPORT_DIR, "reliability_scorecard.md")
    with open(scorecard_path, "w", encoding="utf-8") as f:
        f.write(scorecard)
    print(f"[Reliability] Scorecard saved to {scorecard_path}", flush=True)

    # Save per-domain stability detail
    detail_path = os.path.join(REPORT_DIR, "domain_stability_detail.json")
    with open(detail_path, "w", encoding="utf-8") as f:
        json.dump(stability.get("domain_stability", {}), f, indent=2, default=str)
    print(f"[Reliability] Domain stability detail saved to {detail_path}", flush=True)


def main():
    print("=" * 60, flush=True)
    print("Phase 25: Operational Reliability Validation", flush=True)
    print("=" * 60, flush=True)

    domains = load_domains(BENCHMARK_DATASET)
    print(f"[Reliability] Loaded {len(domains)} benchmark domains from {BENCHMARK_DATASET}", flush=True)

    campaigns: List[Dict[str, Any]] = []

    for run_num in range(1, NUM_RUNS + 1):
        if run_num > 1:
            print(f"\n[Reliability] Waiting {RUN_SPACING_SECONDS}s before Run {run_num}...", flush=True)
            _time.sleep(RUN_SPACING_SECONDS)

        run_label = f"Run-{run_num}"
        campaign = run_campaign(domains, run_label)
        campaigns.append(campaign)
        print(f"[Reliability] Run {run_num} complete. {campaign['elapsed_seconds']}s", flush=True)

    print("\n[Reliability] All campaigns complete. Computing stability...", flush=True)
    stability = compute_stability(campaigns)

    print(f"[Reliability] Stability summary:", flush=True)
    print(f"  Classification stability: {stability['classification_stability_pct']}%", flush=True)
    print(f"  Decision stability: {stability['decision_stability_pct']}%", flush=True)
    print(f"  Unstable domains: {stability['unstable_domain_count']}", flush=True)
    print(f"  Operational error rate: {stability['operational_error_rate_pct']}%", flush=True)

    save_results(campaigns, stability)

    print(f"\n[Reliability] Phase 25 complete. Reports in {REPORT_DIR}/", flush=True)

    if stability["unstable_domain_count"]:
        print(f"\n[Reliability] WARNING: {stability['unstable_domain_count']} unstable domains detected.", flush=True)
        print("[Reliability] Drift analysis required for:", flush=True)
        for d in stability["unstable_domains"]:
            seq = stability["domain_stability"][d]["classification_sequence"]
            print(f"  - {d}: {seq}", flush=True)


if __name__ == "__main__":
    main()
