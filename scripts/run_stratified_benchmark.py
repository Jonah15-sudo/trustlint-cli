"""Phase 5 — Stratified Real TLS Benchmark for Generalization Validation.

Creates the expanded benchmark dataset, runs repeated stratified holdout
evaluations, and generates a statistical summary report.

Usage:
    python scripts/run_stratified_benchmark.py

The script:
1. Defines ~130 domains across 11 categories (5+ per category where safe)
2. Probes all domains once and caches results
3. Creates 10 stratified train/holdout splits
4. Runs holdout evaluation on each split
5. Generates STRATIFIED_BENCHMARK_REPORT.md with summary statistics

Categories with insufficient safe public test domains are documented.
SPL Core is not modified. OFE remains HOLD_PENDING_REAL_DATA.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time as _time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.run_local_tls_validation import probe_domain
from scripts.run_real_tls_spl_decision_validation import (
    _resolve_classification,
    _make_pipeline,
    _run_pipeline_eval,
    _probe_result_to_evidence,
    _train_pipeline_with_labels,
    _compute_policy_conformance,
    _load_decision_expectations,
    CLASSIFICATION_TO_POLICY,
    POLICY_LABELS,
)

REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "local_real_validation")
STRATIFIED_DIR = os.path.join(REPORT_DIR, "stratified_runs")
DATASET_DIR = os.path.join(PROJECT_ROOT, "datasets")

SEED = 42

# ── Domain Definitions by Category ──────────────────────────────────────────

# VALID_TLS: Well-known public domains with valid TLS certificates.
# Reasonable to include ~60+ for solid baseline performance measurement.
VALID_TLS_DOMAINS: List[str] = [
    # Major tech platforms
    "google.com", "github.com", "gitlab.com", "python.org", "pypi.org",
    "docker.com", "mozilla.org", "stackoverflow.com", "cloudflare.com",
    "nginx.com", "apache.org", "kubernetes.io", "hashicorp.com",
    "digitalocean.com", "netlify.com", "atlassian.com", "stripe.com",
    "shopify.com", "wordpress.org", "medium.com",
    # Major internet companies
    "amazon.com", "microsoft.com", "apple.com", "linkedin.com",
    "netflix.com", "dropbox.com", "adobe.com", "oracle.com",
    "ibm.com", "intel.com", "cisco.com", "salesforce.com",
    # Education
    "mit.edu", "cmu.edu", "ox.ac.uk", "cam.ac.uk", "ethz.ch",
    "ucla.edu", "princeton.edu", "yale.edu", "columbia.edu",
    "cornell.edu", "uchicago.edu", "imperial.ac.uk",
    # Government (.gov)
    "nasa.gov", "nih.gov", "nist.gov", "noaa.gov", "usa.gov",
    "data.gov", "whitehouse.gov", "congress.gov",
    # Non-profit / standards
    "eff.org", "wikipedia.org", "archive.org", "w3.org", "ietf.org",
    "openssl.org", "gnu.org", "kernel.org", "debian.org", "ubuntu.com",
    "redhat.com", "postgresql.org", "sqlite.org",
    # Media
    "reuters.com", "bbc.com", "npr.org", "acm.org", "ieee.org",
    "science.org", "nature.com", "arxiv.org", "ssrn.com",
    # BadSSL valid variants
    "badssl.com", "sha256.badssl.com", "mozilla-intermediate.badssl.com",
    "mozilla-modern.badssl.com", "tls-v1-2.badssl.com",
    # Well-known researchers / other
    "caltech.edu", "stanford.edu", "harvard.edu", "berkeley.edu",
    "dns.google", "one.one.one.one", "quad9.net",
]

# EXPIRED_CERT: BadSSL provides 4 safe expired-cert test endpoints.
# Cannot reach 5 — no other safe public test sites known.
EXPIRED_CERT_DOMAINS: List[str] = [
    "expired.badssl.com", "sha384.badssl.com", "sha512.badssl.com",
    "1000-sans.badssl.com",
]

# SELF_SIGNED_CERT: Only 1 safe public test endpoint exists.
CANNOT_REACH_5_SELF_SIGNED = (
    "SELF_SIGNED_CERT has only 1 safe public test domain (self-signed.badssl.com). "
    "No other publicly safe self-signed cert test sites are known. "
    "Category limited to 1 sample."
)
SELF_SIGNED_CERT_DOMAINS: List[str] = ["self-signed.badssl.com"]

# WRONG_HOST_CERT: Only 1 safe public test endpoint exists.
CANNOT_REACH_5_WRONG_HOST = (
    "WRONG_HOST_CERT has only 1 safe public test domain (wrong.host.badssl.com). "
    "No other publicly safe wrong-host cert test sites are known. "
    "Category limited to 1 sample."
)
WRONG_HOST_CERT_DOMAINS: List[str] = ["wrong.host.badssl.com"]

# UNTRUSTED_CHAIN: 2 safe endpoints. incomplete-chain.badssl.com also maps here.
CANNOT_REACH_5_UNTRUSTED = (
    "UNTRUSTED_CHAIN has only 2 safe public test domains (untrusted-root.badssl.com, "
    "superfish.badssl.com). INCOMPLETE_CHAIN domains also map to UNTRUSTED_CHAIN "
    "at the probe level (chain trust ambiguity). Category limited to 2-3 samples."
)
UNTRUSTED_CHAIN_DOMAINS: List[str] = [
    "untrusted-root.badssl.com", "superfish.badssl.com",
]

# INCOMPLETE_CHAIN: Only 1 safe endpoint. Probe maps to UNTRUSTED_CHAIN.
CANNOT_REACH_5_INCOMPLETE = (
    "INCOMPLETE_CHAIN has only 1 safe public test domain. "
    "The local probe cannot distinguish INCOMPLETE_CHAIN from UNTRUSTED_CHAIN "
    "(documented chain trust ambiguity). Both map to SECURITY_RISK."
)
INCOMPLETE_CHAIN_DOMAINS: List[str] = ["incomplete-chain.badssl.com"]

# DNS_FAILURE: Can create many guaranteed-to-fail domains.
DNS_FAILURE_DOMAINS: List[str] = [
    "thissitedoesnotexistxyzabc99999.nonexistent",
    "jjf8d9a7sd6f5asdf.testing-reserved",
    "never-gonna-resolve-987654321.example.com",
    "qweryuiopasdfghjklzxcvbnm.test",
    "invalid-test-domain-00001.example.net",
]

# TLS_HANDSHAKE_FAILURE: BadSSL provides several weak-crypto endpoints.
TLS_HANDSHAKE_FAILURE_DOMAINS: List[str] = [
    "dh480.badssl.com", "dh512.badssl.com", "null.badssl.com",
    "rc4.badssl.com", "3des.badssl.com", "dh1024.badssl.com",
    "rc4-md5.badssl.com",
]

# CONNECTION_ERROR: Non-routable IPs and loopback addresses.
CONNECTION_ERROR_DOMAINS: List[str] = [
    "localhost", "127.0.0.1", "0.0.0.0", "192.0.2.1",
    "198.51.100.1", "100.64.0.1",
]

# TIMEOUT: Non-routable IPs that time out rather than refuse.
TIMEOUT_DOMAINS: List[str] = [
    "10.255.255.1", "203.0.113.1", "10.0.0.1",
    "172.16.0.1", "192.168.0.1",
]

# DEPRECATED_TLS: Servers that support TLS 1.0/1.1. Detection is best-effort.
# The probe may negotiate TLS 1.2+ even with servers that support 1.0.
DEPRECATED_TLS_DOMAINS: List[str] = [
    # Expected TLS 1.0; may be classified as VALID_TLS depending on negotiation
    "tls-v1-0.badssl.com",
    # Expected TLS 1.1; may be classified as VALID_TLS depending on negotiation
    "tls-v1-1.badssl.com",
]

# ── Domain Map: domain -> expected policy label ─────────────────────────────

EXPECTED_POLICY: Dict[str, str] = {}

for domain in VALID_TLS_DOMAINS:
    EXPECTED_POLICY[domain] = "ACCEPTABLE_TLS"

for domain in EXPIRED_CERT_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

for domain in SELF_SIGNED_CERT_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

for domain in WRONG_HOST_CERT_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

for domain in UNTRUSTED_CHAIN_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

for domain in INCOMPLETE_CHAIN_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

for domain in DNS_FAILURE_DOMAINS:
    EXPECTED_POLICY[domain] = "AVAILABILITY_RISK"

for domain in TLS_HANDSHAKE_FAILURE_DOMAINS:
    EXPECTED_POLICY[domain] = "AMBIGUOUS_FAILURE"

for domain in CONNECTION_ERROR_DOMAINS:
    EXPECTED_POLICY[domain] = "AVAILABILITY_RISK"

for domain in TIMEOUT_DOMAINS:
    EXPECTED_POLICY[domain] = "AVAILABILITY_RISK"

for domain in DEPRECATED_TLS_DOMAINS:
    EXPECTED_POLICY[domain] = "SECURITY_RISK"

ALL_DOMAINS: List[str] = list(EXPECTED_POLICY.keys())

CATEGORY_MAP: Dict[str, str] = {}
for domain, policy in EXPECTED_POLICY.items():
    if policy == "ACCEPTABLE_TLS":
        if domain in DEPRECATED_TLS_DOMAINS:
            CATEGORY_MAP[domain] = "DEPRECATED_TLS"
        else:
            CATEGORY_MAP[domain] = "VALID_TLS"
    elif policy == "SECURITY_RISK":
        if domain in EXPIRED_CERT_DOMAINS:
            CATEGORY_MAP[domain] = "EXPIRED_CERT"
        elif domain in SELF_SIGNED_CERT_DOMAINS:
            CATEGORY_MAP[domain] = "SELF_SIGNED_CERT"
        elif domain in WRONG_HOST_CERT_DOMAINS:
            CATEGORY_MAP[domain] = "WRONG_HOST_CERT"
        elif domain in UNTRUSTED_CHAIN_DOMAINS:
            CATEGORY_MAP[domain] = "UNTRUSTED_CHAIN"
        elif domain in INCOMPLETE_CHAIN_DOMAINS:
            CATEGORY_MAP[domain] = "INCOMPLETE_CHAIN"
        elif domain in DEPRECATED_TLS_DOMAINS:
            CATEGORY_MAP[domain] = "DEPRECATED_TLS"
        else:
            CATEGORY_MAP[domain] = "SECURITY_RISK"
    elif policy == "AVAILABILITY_RISK":
        if domain in DNS_FAILURE_DOMAINS:
            CATEGORY_MAP[domain] = "DNS_FAILURE"
        elif domain in CONNECTION_ERROR_DOMAINS:
            CATEGORY_MAP[domain] = "CONNECTION_ERROR"
        elif domain in TIMEOUT_DOMAINS:
            CATEGORY_MAP[domain] = "TIMEOUT"
        else:
            CATEGORY_MAP[domain] = "AVAILABILITY_RISK"
    elif policy == "AMBIGUOUS_FAILURE":
        CATEGORY_MAP[domain] = "TLS_HANDSHAKE_FAILURE"


CATEGORY_ORDER = [
    "VALID_TLS", "EXPIRED_CERT", "SELF_SIGNED_CERT", "WRONG_HOST_CERT",
    "UNTRUSTED_CHAIN", "INCOMPLETE_CHAIN", "DNS_FAILURE",
    "TLS_HANDSHAKE_FAILURE", "CONNECTION_ERROR", "TIMEOUT",
    "DEPRECATED_TLS",
]

CATEGORY_LIMITATIONS: Dict[str, str] = {
    "SELF_SIGNED_CERT": CANNOT_REACH_5_SELF_SIGNED,
    "WRONG_HOST_CERT": CANNOT_REACH_5_WRONG_HOST,
    "UNTRUSTED_CHAIN": CANNOT_REACH_5_UNTRUSTED,
    "INCOMPLETE_CHAIN": CANNOT_REACH_5_INCOMPLETE,
    "DEPRECATED_TLS": (
        "DEPRECATED_TLS has only 2 safe public test domains (tls-v1-0.badssl.com, "
        "tls-v1-1.badssl.com). The probe cannot reliably detect deprecated TLS versions "
        "because the default SSL context negotiates the highest mutually supported version. "
        "Both domains are classified as VALID_TLS by the current probe."
    ),
}


def _category_counts() -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for cat in CATEGORY_ORDER:
        count = sum(1 for d in ALL_DOMAINS if CATEGORY_MAP.get(d) == cat)
        if count:
            counts[cat] = count
    return counts


# ── Dataset file I/O ────────────────────────────────────────────────────────

def write_benchmark_files() -> str:
    """Write benchmark domain list and expectations file. Returns path to domain file."""
    os.makedirs(DATASET_DIR, exist_ok=True)

    categories: Dict[str, List[str]] = {}
    for domain in ALL_DOMAINS:
        cat = CATEGORY_MAP.get(domain, "UNKNOWN")
        categories.setdefault(cat, []).append(domain)

    # Write domains file
    domain_lines = [
        "# SPL v7.1 — Stratified Real TLS Benchmark Dataset",
        "# ==================================================",
        f"# Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"# Total domains: {len(ALL_DOMAINS)}",
        "# Purpose: Measure SPL generalization across stratified TLS categories.",
        "# Policy: No aggressive scanning. Rate-limited, single-connection probes only.",
        "#",
    ]
    for cat in CATEGORY_ORDER:
        domains = categories.get(cat, [])
        if domains:
            domain_lines.append(f"# === {cat} ({len(domains)}) ===")
            domain_lines.extend(domains)
            domain_lines.append("")

    domain_path = os.path.join(DATASET_DIR, "real_tls_benchmark_domains.txt")
    with open(domain_path, "w", encoding="utf-8") as f:
        f.write("\n".join(domain_lines))
    print(f"[Phase5] Wrote {domain_path} ({len(ALL_DOMAINS)} domains)")

    # Write expectations file
    decisions = []
    for domain in ALL_DOMAINS:
        decisions.append({
            "domain": domain,
            "expected_decision": EXPECTED_POLICY[domain],
            "category": CATEGORY_MAP.get(domain, "UNKNOWN"),
        })

    expectations = {
        "_metadata": {
            "description": "Benchmark policy expectations for stratified SPL validation",
            "version": "Phase 5",
            "total_domains": len(ALL_DOMAINS),
            "purpose": "Measure SPL policy conformance across stratified categories",
        },
        "decisions": decisions,
    }

    expectations_path = os.path.join(DATASET_DIR, "real_tls_benchmark_expectations.json")
    with open(expectations_path, "w", encoding="utf-8") as f:
        json.dump(expectations, f, indent=2)
    print(f"[Phase5] Wrote {expectations_path}")

    return domain_path


def probe_all_domains(
    domains: List[str],
    cache_path: str,
    force_reprobe: bool = False,
) -> List[Dict[str, Any]]:
    """Probe all domains once and cache results. Returns probe results list."""
    if not force_reprobe and os.path.isfile(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        cached_domains = {r["domain"] for r in cached}
        if all(d in cached_domains for d in domains):
            print(f"[Phase5] Loading {len(cached)} cached probe results from {cache_path}")
            return cached

    results: List[Dict[str, Any]] = []
    for idx, domain in enumerate(domains):
        print(f"  [{idx + 1}/{len(domains)}] {domain}...", end=" ", flush=True)
        try:
            result = probe_domain(domain)
            result["classification"] = _resolve_classification(result)
            results.append(result)
            print(f"{result.get('classification', 'UNKNOWN_SSL_ERROR')}", flush=True)
        except Exception as e:
            print(f"ERROR: {e}", flush=True)
            results.append({
                "domain": domain,
                "probe_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "resolved_ip": None,
                "dns_error": str(e),
                "tls": None,
                "overall_status": "probe_error",
                "classification": "UNKNOWN_SSL_ERROR",
            })
        _time.sleep(0.5)

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[Phase5] Cached {len(results)} probe results to {cache_path}")
    return results


def generate_stratified_splits(
    domains: List[str],
    n_splits: int = 10,
    holdout_ratio: float = 0.3,
) -> List[Tuple[List[str], List[str]]]:
    """Generate stratified train/holdout splits preserving category proportions."""
    # Group domains by category
    cat_domains: Dict[str, List[str]] = {}
    for d in domains:
        cat = CATEGORY_MAP.get(d, "UNKNOWN")
        cat_domains.setdefault(cat, []).append(d)

    # Categories with only 1 domain must always be in training set
    forced_train_cats: Dict[str, List[str]] = {}
    splittable_cats: Dict[str, List[str]] = {}
    for cat, dlist in cat_domains.items():
        if len(dlist) <= 1:
            forced_train_cats[cat] = dlist
        else:
            splittable_cats[cat] = dlist

    splits: List[Tuple[List[str], List[str]]] = []

    for split_idx in range(n_splits):
        train: List[str] = []
        holdout: List[str] = []

        # Use per-split seed for reproducible but diverse splits
        split_seed = SEED + split_idx
        rng = random.Random(split_seed)

        # Always include singleton categories in training
        for cat, dlist in forced_train_cats.items():
            train.extend(dlist)

        # Stratified sampling for splittable categories
        for cat, dlist in splittable_cats.items():
            shuffled = list(dlist)
            rng.shuffle(shuffled)
            n_holdout = max(1, round(len(shuffled) * holdout_ratio))
            # Ensure at least 1 training sample
            if len(shuffled) - n_holdout < 1:
                n_holdout = len(shuffled) - 1
            holdout.extend(shuffled[:n_holdout])
            train.extend(shuffled[n_holdout:])

        splits.append((train, holdout))

    return splits


def run_split_evaluation(
    train_domains: List[str],
    holdout_domains: List[str],
    probe_results: List[Dict[str, Any]],
    train_expectations: Dict[str, bool],
) -> Dict[str, Any]:
    """Run a single holdout evaluation and return structured results."""
    pipeline = _make_pipeline()

    # Build probe results for training domains
    pr_by_domain = {r["domain"]: r for r in probe_results}
    train_probes = [pr_by_domain[d] for d in train_domains if d in pr_by_domain]
    holdout_probes = [pr_by_domain[d] for d in holdout_domains if d in pr_by_domain]

    # Train
    _train_pipeline_with_labels(pipeline, train_probes, train_expectations)

    # Evaluate
    results = _run_pipeline_eval(pipeline, holdout_probes)

    # Score with holdout expectations
    holdout_expectations = {d: EXPECTED_POLICY[d] for d in holdout_domains if d in EXPECTED_POLICY}
    conformance = _compute_policy_conformance(results, holdout_expectations)

    # Category-level breakdown
    cat_correct: Dict[str, int] = {}
    cat_total: Dict[str, int] = {}
    for r in results:
        domain = r["domain"]
        cat = CATEGORY_MAP.get(domain, "UNKNOWN")
        cat_total[cat] = cat_total.get(cat, 0) + 1
        expected = EXPECTED_POLICY.get(domain, "UNKNOWN")
        if r.get("spl_risk_label") == expected:
            cat_correct[cat] = cat_correct.get(cat, 0) + 1

    cat_perf = {}
    for cat in CATEGORY_ORDER:
        total = cat_total.get(cat, 0)
        correct = cat_correct.get(cat, 0)
        if total > 0:
            cat_perf[cat] = {
                "total": total,
                "correct": correct,
                "conformance_pct": round(correct / total * 100, 1),
            }

    return {
        "train_size": len(train_domains),
        "holdout_size": len(holdout_domains),
        "conformance": conformance,
        "category_performance": cat_perf,
        "results": results,
    }


def build_train_expectations(
    train_domains: List[str],
    probe_results: List[Dict[str, Any]],
) -> Dict[str, bool]:
    """Build train expectations from expected policy: ACCEPTABLE_TLS -> False, else True."""
    expectations: Dict[str, bool] = {}
    pr_by_domain = {r["domain"]: r for r in probe_results}
    for d in train_domains:
        policy = EXPECTED_POLICY.get(d, "UNKNOWN")
        expectations[d] = policy != "ACCEPTABLE_TLS"
    return expectations


# ── Report Generation ───────────────────────────────────────────────────────


def _pct(n: int, total: int) -> str:
    return f"{round(n / max(total, 1) * 100, 1)}"


def generate_benchmark_report(
    all_results: List[Dict[str, Any]],
    domain_count: int,
    n_splits: int,
    category_counts: Dict[str, int],
    deprecated_tls_findings: str,
) -> str:
    """Generate the stratified benchmark report markdown."""
    conformances = [r["conformance"]["conformance_pct"] for r in all_results]
    vals = [float(r["conformance"]["conformance_pct"]) for r in all_results if r["conformance"]["conformance_pct"] is not None]

    mean_c = round(sum(vals) / len(vals), 1) if vals else 0.0
    min_c = round(min(vals), 1) if vals else 0.0
    max_c = round(max(vals), 1) if vals else 0.0
    variance = sum((v - mean_c) ** 2 for v in vals) / len(vals) if vals else 0.0
    std_dev = round(variance ** 0.5, 2)

    # Collect per-category stats across all runs
    cat_totals: Dict[str, List[int]] = defaultdict(list)
    cat_correct: Dict[str, List[int]] = defaultdict(list)
    for r in all_results:
        for cat, perf in r.get("category_performance", {}).items():
            cat_totals[cat].append(perf["total"])
            cat_correct[cat].append(perf["correct"])

    # Collect all mismatches across runs
    all_mismatches: List[Dict[str, Any]] = []
    for r in all_results:
        for m in r["conformance"].get("mismatches", []):
            all_mismatches.append(m)

    # Count mismatch frequency by domain
    mismatch_freq: Dict[str, int] = Counter(m["domain"] for m in all_mismatches)
    repeated_failures = {d: c for d, c in mismatch_freq.items() if c > n_splits * 0.3}

    # Low-confidence patterns
    all_low_conf: List[Dict[str, Any]] = []
    for r in all_results:
        for result in r.get("results", []):
            prob = result.get("spl_probability", 0.0)
            if prob < 0.5 and result.get("spl_decision", False):
                all_low_conf.append(result)

    low_conf_domains: Dict[str, int] = Counter(d["domain"] for d in all_low_conf)

    lines = [
        "# Stratified Real TLS Benchmark Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"Runner: `scripts/run_stratified_benchmark.py`",
        f"Total benchmark domains: {domain_count}",
        f"Number of stratified splits: {n_splits}",
        "",
        "---",
        "",
        "## Purpose",
        "",
        "Measure SPL generalization across stratified TLS categories using repeated",
        "holdout evaluations. This report provides preliminary evidence about whether",
        "the Phase 4 holdout result (94.4%) is stable across different train/holdout",
        "splits and larger, more balanced datasets.",
        "",
        "**No production readiness claims are made.**",
        "",
        "---",
        "",
        "## Category Distribution",
        "",
        "| Category | Count | Note |",
        "|---|---|---|",
    ]

    for cat in CATEGORY_ORDER:
        count = category_counts.get(cat, 0)
        if count:
            limitation = CATEGORY_LIMITATIONS.get(cat, "")
            note = "Insufficient safe public test domains" if limitation else ""
            lines.append(f"| {cat} | {count} | {note} |")

    # Add category limitation details
    has_limitations = any(cat in CATEGORY_LIMITATIONS for cat in category_counts)
    if has_limitations:
        lines.extend(["", "### Category Limitations", ""])
        for cat in CATEGORY_ORDER:
            if cat in category_counts and cat in CATEGORY_LIMITATIONS:
                lines.append(f"- **{cat}**: {CATEGORY_LIMITATIONS[cat]}")
                lines.append("")

    lines.extend([
        "",
        "---",
        "",
        "## Overall Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Number of runs | {n_splits} |",
        f"| Mean conformance | {mean_c}% |",
        f"| Min conformance | {min_c}% |",
        f"| Max conformance | {max_c}% |",
        f"| Standard deviation | {std_dev} |",
        f"| Variance | {round(variance, 2)} |",
        "",
        "**Interpretation**: The conformance across runs is reported below.",
        "This is preliminary evidence only. Small sample sizes in some categories",
        "mean these numbers should not be treated as statistically significant.",
        "",
        "---",
        "",
        "## Per-Run Results",
        "",
        "| Run | Train Size | Holdout Size | Conformance | Correct/Total |",
        "|---|---|---|---|---|",
    ])

    for i, r in enumerate(all_results):
        conf = r["conformance"]
        lines.append(
            f"| {i + 1} | {r['train_size']} | {r['holdout_size']} | "
            f"{conf['conformance_pct']}% | {conf['correct']}/{conf['total_with_results']} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Category-Level Conformance (Across All Runs)",
        "",
        "| Category | Total Samples (sum) | Mean Conformance | Min | Max |",
        "|---|---|---|---|---|",
    ])

    for cat in CATEGORY_ORDER:
        totals = cat_totals.get(cat)
        if totals:
            total_s = sum(totals)
            per_run_rates = []
            for i, r in enumerate(all_results):
                cat_perf = r.get("category_performance", {}).get(cat)
                if cat_perf and cat_perf["total"] > 0:
                    per_run_rates.append(cat_perf["conformance_pct"])
            mean_cat = round(sum(per_run_rates) / len(per_run_rates), 1) if per_run_rates else 0.0
            min_cat = round(min(per_run_rates), 1) if per_run_rates else 0.0
            max_cat = round(max(per_run_rates), 1) if per_run_rates else 0.0
            lines.append(f"| {cat} | {total_s} | {mean_cat}% | {min_cat}% | {max_cat}% |")

    # Mismatch patterns
    if all_mismatches:
        lines.extend([
            "",
            "---",
            "",
            "## Mismatch Patterns",
            "",
            f"Total mismatches across all runs: {len(all_mismatches)}",
            "",
            "### Repeated Failure Domains (>30% of runs)",
            "",
        ])
        if repeated_failures:
            lines.append("| Domain | Times Mismatched | Runs | Rate |")
            lines.append("|---|---|---|---|")
            for domain, count in sorted(repeated_failures.items(), key=lambda x: -x[1]):
                rate = round(count / n_splits * 100, 1)
                lines.append(f"| {domain} | {count} / {n_splits} | {rate}% |")
        else:
            lines.append("No domain mismatched in more than 30% of runs.")
            lines.append("")

        lines.extend([
            "### All Unique Mismatches",
            "",
            "| Domain | Expected | Classifications Seen |",
            "|---|---|---|",
        ])
        mismatch_domains: Dict[str, Dict[str, Any]] = {}
        for m in all_mismatches:
            d = m["domain"]
            if d not in mismatch_domains:
                mismatch_domains[d] = {
                    "expected": m["expected"],
                    "classifications": set(),
                    "actuals": set(),
                }
            mismatch_domains[d]["classifications"].add(m.get("classification", ""))
            mismatch_domains[d]["actuals"].add(m["actual"])

        for domain, info in sorted(mismatch_domains.items()):
            classifications = ", ".join(sorted(info["classifications"]))
            lines.append(f"| {domain} | {info['expected']} | {classifications} |")

    # Low-confidence patterns
    if all_low_conf:
        lines.extend([
            "",
            "---",
            "",
            "## Low-Confidence Risk Decisions",
            "",
            f"Total low-confidence risk decisions across all runs: {len(all_low_conf)}",
            "",
        ])
        if low_conf_domains:
            lines.append("| Domain | Times Low-Conf |")
            lines.append("|---|---|")
            for domain, count in sorted(low_conf_domains.items(), key=lambda x: -x[1])[:15]:
                lines.append(f"| {domain} | {count} |")

    # Deprecated TLS
    lines.extend([
        "",
        "---",
        "",
        "## Deprecated TLS Review",
        "",
        deprecated_tls_findings,
        "",
        "---",
        "",
        "## Limitations",
        "",
        "1. **Small sample sizes**: Categories with 1-2 samples (SELF_SIGNED_CERT,",
        "   WRONG_HOST_CERT, UNTRUSTED_CHAIN, INCOMPLETE_CHAIN) cannot produce",
        "   reliable per-category generalization estimates.",
        "2. **No ground-truth labels**: All labels are external expectations derived",
        "   from probe classification mapping, not ground truth.",
        "3. **No HSTS/CSP confirmation**: Headers are assumed absent (default False).",
        "4. **Chain trust ambiguity**: INCOMPLETE_CHAIN vs UNTRUSTED_CHAIN not",
        "   distinguishable at probe level.",
        "5. **Single IP per domain**: Only the first A record is probed.",
        "6. **No IPv6**: Probes use IPv4 only.",
        "7. **No CRL/OCSP checking**: Revocation is not verified.",
        "8. **Deprecated TLS detection**: Not guaranteed by the current probe.",
        "   The default SSL context may negotiate TLS 1.2+ even when the server",
        "   supports TLS 1.0, preventing deprecated TLS reclassification.",
        "9. **Limited split variety**: Stratified splits preserve category proportions",
        f"   but may not cover all possible train/holdout configurations.",
        "10. **No statistical significance**: The sample size (18 categories,",
        f"    {n_splits} runs) is insufficient for claims of statistical significance.",
        "",
        "_This report is for local evidence gathering only. No production claims are made._",
    ])

    return "\n".join(lines)


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    print("=" * 60)
    print("Phase 5 — Stratified Real TLS Benchmark")
    print("=" * 60)

    # ── Step 1: Write benchmark files ──────────────────────────────────────
    print("\n[Phase5] Step 1: Creating benchmark dataset...")
    benchmark_domain_path = write_benchmark_files()
    print(f"[Phase5] Benchmark dataset contains {len(ALL_DOMAINS)} domains.")

    cat_counts = _category_counts()
    print("[Phase5] Category counts:")
    for cat in CATEGORY_ORDER:
        count = cat_counts.get(cat, 0)
        if count:
            limitation = " [limited]" if cat in CATEGORY_LIMITATIONS else ""
            print(f"  {cat}: {count}{limitation}")

    # ── Step 2: Probe all domains once ────────────────────────────────────
    print("\n[Phase5] Step 2: Probing all benchmark domains (once, cached)...")
    cache_path = os.path.join(REPORT_DIR, "benchmark_probe_cache.json")
    probe_results = probe_all_domains(ALL_DOMAINS, cache_path, force_reprobe=False)
    print(f"[Phase5] Probed {len(probe_results)} domains.")

    # ── Step 3: Generate stratified splits ─────────────────────────────────
    print("\n[Phase5] Step 3: Generating stratified splits...")
    n_splits = 10
    splits = generate_stratified_splits(ALL_DOMAINS, n_splits=n_splits, holdout_ratio=0.3)
    print(f"[Phase5] Generated {len(splits)} stratified train/holdout splits.")

    # ── Step 4: Run repeated holdout evaluations ───────────────────────────
    print("\n[Phase5] Step 4: Running repeated holdout evaluations...")
    os.makedirs(STRATIFIED_DIR, exist_ok=True)

    all_run_results: List[Dict[str, Any]] = []

    for i, (train_domains, holdout_domains) in enumerate(splits):
        print(f"\n[Phase5] Run {i + 1}/{n_splits}:")
        print(f"  Train: {len(train_domains)} domains")
        print(f"  Holdout: {len(holdout_domains)} domains")

        train_expectations = build_train_expectations(train_domains, probe_results)
        result = run_split_evaluation(
            train_domains, holdout_domains, probe_results, train_expectations,
        )
        conf = result["conformance"]
        print(f"  Conformance: {conf['conformance_pct']}% ({conf['correct']}/{conf['total_with_results']})")

        # Save per-run result
        run_path = os.path.join(STRATIFIED_DIR, f"run_{i + 1:02d}.json")
        with open(run_path, "w", encoding="utf-8") as f:
            json.dump({
                "run": i + 1,
                "train_size": result["train_size"],
                "holdout_size": result["holdout_size"],
                "conformance": conf,
                "category_performance": result["category_performance"],
                "results": result["results"],
            }, f, indent=2, default=str)
        print(f"  Saved to {run_path}")

        all_run_results.append(result)

    # ── Step 5: Generate report ────────────────────────────────────────────
    print("\n[Phase5] Step 5: Generating statistical summary report...")

    deprecated_tls_findings = (
        "## Deprecated TLS Detection\n\n"
        "The probe relies on the default SSL context to negotiate TLS connections. "
        "When the system's OpenSSL library supports TLS 1.2+ (which all modern systems do), "
        "the handshake will succeed at the highest mutually supported version even when "
        "the server also supports TLS 1.0 or TLS 1.1.\n\n"
        "**Finding**: Deprecated TLS support detection is **not guaranteed** by the current "
        "probe. The `_resolve_classification()` function in "
        "`scripts/run_real_tls_spl_decision_validation.py` checks the `tls_version` field "
        "in the probe result, but if the handshake completed at TLS 1.2, the `tls_version` "
        "field reports TLSv1.2, not the server's full capability set.\n\n"
        "**Impact**: Domains that support only deprecated TLS versions AND where the system "
        "cannot negotiate a higher version (rare on modern systems) will be correctly "
        "reclassified. All others will appear as VALID_TLS.\n\n"
        "**Recommendation**: To reliably detect deprecated TLS support, the probe would "
        "need to attempt version-restricted handshakes (e.g., force TLS 1.0 only). This "
        "would require changes to `scripts/run_local_tls_validation.py`, not SPL Core.\n\n"
        "**Current behavior in this benchmark**: The `tls-v1-0.badssl.com` and "
        "`tls-v1-1.badssl.com` domains are expected to produce SECURITY_RISK but are "
        "classified as VALID_TLS by the probe. This is a known limitation."
    )

    report = generate_benchmark_report(
        all_run_results,
        len(ALL_DOMAINS),
        n_splits,
        cat_counts,
        deprecated_tls_findings,
    )

    report_path = os.path.join(REPORT_DIR, "STRATIFIED_BENCHMARK_REPORT.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[Phase5] Report written to {report_path}")

    # ── Summary ────────────────────────────────────────────────────────────
    confs = [r["conformance"]["conformance_pct"] for r in all_run_results]
    vals = [float(c) for c in confs if c is not None]
    mean_c = round(sum(vals) / len(vals), 1) if vals else 0.0
    min_c = round(min(vals), 1) if vals else 0.0
    max_c = round(max(vals), 1) if vals else 0.0
    variance = sum((v - mean_c) ** 2 for v in vals) / len(vals) if vals else 0.0
    std_dev = round(variance ** 0.5, 2)

    print(f"\n{'=' * 60}")
    print(f"Phase 5 Complete.")
    print(f"  Domains: {len(ALL_DOMAINS)}")
    print(f"  Runs: {n_splits}")
    print(f"  Mean conformance: {mean_c}%")
    print(f"  Min conformance: {min_c}%")
    print(f"  Max conformance: {max_c}%")
    print(f"  Std dev: {std_dev}")
    print(f"  Report: {report_path}")
    print(f"  SPL Core: untouched")
    print(f"  OFE status: HOLD_PENDING_REAL_DATA")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
