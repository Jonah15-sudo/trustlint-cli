"""Validation Evaluation Framework.

Compares SPL pipeline vs rule-based (adapter-only) baseline against
real TLS probe data with known expectations.

Computes: precision, recall, FPR, FNR, confusion matrix, accuracy per category.

Usage:
    python scripts/run_validation_evaluation.py [--benchmark] [--probe] [--output DIR]

Modes:
    --benchmark    Use cached benchmark probe results (fastest, recommended)
    --probe        Run live TLS probes (slower but freshest data)
    --output DIR   Output directory (default: reports/validation_evaluation)

Requires:
    - datasets/real_tls_benchmark_domains.txt
    - datasets/real_tls_benchmark_expectations.json
    - Cache from previous benchmark run (or --probe for live probes)
"""

from __future__ import annotations

import json
import os
import sys
import time as _time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from decision_orchestrator.policy import decide
from decision_orchestrator.schema import OrchestratorOutput
from tls_policy_adapter.risk_policy import classify_risk
from scripts.run_real_tls_spl_decision_validation import (
    _resolve_classification,
    _make_pipeline,
    _run_pipeline_eval,
    _probe_result_to_evidence,
    _compute_policy_conformance,
    _load_decision_expectations,
    CLASSIFICATION_TO_POLICY,
    POLICY_LABELS,
)
from scripts.run_stratified_benchmark import (
    ALL_DOMAINS,
    EXPECTED_POLICY,
    CATEGORY_MAP,
    CATEGORY_ORDER,
    CATEGORY_LIMITATIONS,
    _category_counts,
    probe_all_domains,
    write_benchmark_files,
)

REPORT_DIR = os.path.join(PROJECT_ROOT, "reports", "validation_evaluation")
DATASET_DIR = os.path.join(PROJECT_ROOT, "datasets")


def _pct(n: int, total: int) -> str:
    return f"{round(n / max(total, 1) * 100, 1)}"


def _safe_div(n: int, d: int) -> float:
    return n / max(d, 1)


def compute_baseline_decision(classification: str) -> str:
    """Compute the rule-based (adapter-only) decision for a classification.

    This mimics the DecisionOrchestrator with no SPL input.
    Uses the deterministic adapter mapping only.
    """
    try:
        evidence = classify_risk(classification)
    except KeyError:
        return "REVIEW"
    risk_cat = evidence.risk_category
    severity = evidence.severity
    action = evidence.action_hint

    if severity == "CRITICAL":
        return "DENY"
    if risk_cat == "SECURITY_RISK" and severity in ("HIGH", "CRITICAL"):
        return "REVIEW"
    if risk_cat == "AVAILABILITY_RISK":
        return "REVIEW"
    if risk_cat == "AMBIGUOUS_FAILURE":
        return "REVIEW"
    if risk_cat == "ACCEPTABLE_TLS":
        return "ALLOW"
    return "REVIEW"


def compute_baseline_is_risk(classification: str) -> bool:
    """Does the rule-based baseline consider this a risk?"""
    d = compute_baseline_decision(classification)
    return d != "ALLOW"


def compute_confusion_matrix(
    actual_risks: List[bool],
    predicted_risks: List[bool],
) -> Dict[str, Any]:
    tp = sum(1 for a, p in zip(actual_risks, predicted_risks) if a and p)
    tn = sum(1 for a, p in zip(actual_risks, predicted_risks) if not a and not p)
    fp = sum(1 for a, p in zip(actual_risks, predicted_risks) if not a and p)
    fn = sum(1 for a, p in zip(actual_risks, predicted_risks) if a and not p)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    f1 = _safe_div(2 * tp, 2 * tp + fp + fn)

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "n": tp + tn + fp + fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "accuracy": round(accuracy, 4),
        "f1_score": round(f1, 4),
    }


def run_evaluation(probe_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    pr_by_domain = {r["domain"]: r for r in probe_results}

    spl_pipeline = _make_pipeline()
    spl_results = _run_pipeline_eval(spl_pipeline, probe_results)
    spl_by_domain = {r["domain"]: r for r in spl_results}

    all_domains = [d for d in ALL_DOMAINS if d in pr_by_domain]
    all_domains.sort()

    ground_truth: List[bool] = []
    baseline_pred: List[bool] = []
    spl_pred: List[bool] = []
    decisions_baseline: List[Dict[str, Any]] = []
    decisions_spl: List[Dict[str, Any]] = []

    for domain in all_domains:
        pr = pr_by_domain[domain]
        classification = _resolve_classification(pr)
        expected_policy = EXPECTED_POLICY.get(domain, "UNKNOWN")
        actual_is_risk = expected_policy != "ACCEPTABLE_TLS"

        bl_is_risk = compute_baseline_is_risk(classification)

        sr = spl_by_domain.get(domain, {})
        spl_is_risk = sr.get("spl_decision", False)

        ground_truth.append(actual_is_risk)
        baseline_pred.append(bl_is_risk)
        spl_pred.append(spl_is_risk)

        decisions_baseline.append({
            "domain": domain,
            "classification": classification,
            "expected_policy": expected_policy,
            "actual_is_risk": actual_is_risk,
            "baseline_decision": "ALLOW" if not bl_is_risk else "DENY/REVIEW",
            "baseline_is_risk": bl_is_risk,
        })
        decisions_spl.append({
            "domain": domain,
            "classification": classification,
            "expected_policy": expected_policy,
            "actual_is_risk": actual_is_risk,
            "spl_decision": sr.get("spl_decision"),
            "spl_risk_label": sr.get("spl_risk_label", "UNKNOWN"),
            "spl_probability": sr.get("spl_probability", 0.0),
            "spl_is_risk": spl_is_risk,
        })

    baseline_cm = compute_confusion_matrix(ground_truth, baseline_pred)
    spl_cm = compute_confusion_matrix(ground_truth, spl_pred)

    metrics_delta = {}
    for metric in ["accuracy", "precision", "recall", "f1_score", "fpr", "fnr"]:
        a = spl_cm.get(metric, 0)
        b = baseline_cm.get(metric, 0)
        metrics_delta[metric] = {
            "baseline": b,
            "spl": a,
            "delta": round(a - b, 4),
            "baseline_wins": b > a,
            "spl_wins": a > b,
            "tie": a == b,
        }

    category_perf_baseline: Dict[str, Dict[str, Any]] = {}
    category_perf_spl: Dict[str, Dict[str, Any]] = {}
    for cat in CATEGORY_ORDER:
        cat_domains = [d for d in all_domains if CATEGORY_MAP.get(d) == cat]
        if not cat_domains:
            continue
        cat_gt = [ground_truth[i] for i, d in enumerate(all_domains) if CATEGORY_MAP.get(d) == cat]
        cat_bl = [baseline_pred[i] for i, d in enumerate(all_domains) if CATEGORY_MAP.get(d) == cat]
        cat_spl = [spl_pred[i] for i, d in enumerate(all_domains) if CATEGORY_MAP.get(d) == cat]
        category_perf_baseline[cat] = compute_confusion_matrix(cat_gt, cat_bl)
        category_perf_baseline[cat]["domain_count"] = len(cat_domains)
        category_perf_spl[cat] = compute_confusion_matrix(cat_gt, cat_spl)
        category_perf_spl[cat]["domain_count"] = len(cat_domains)

    mismatches: List[Dict[str, Any]] = []
    for i, d in enumerate(all_domains):
        if baseline_pred[i] != spl_pred[i]:
            mismatches.append({
                "domain": d,
                "classification": decisions_baseline[i]["classification"],
                "ground_truth": ground_truth[i],
                "baseline": baseline_pred[i],
                "spl": spl_pred[i],
                "spl_probability": decisions_spl[i]["spl_probability"],
                "spl_risk_label": decisions_spl[i]["spl_risk_label"],
            })

    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "total_domains": len(all_domains),
            "condition_baseline": "Rule-based (adapter-only) — deterministic classification mapping",
            "condition_spl": "SPL pipeline — OnlineCausalGraphLearner + evidence pipeline",
        },
        "confusion_matrix": {
            "baseline": baseline_cm,
            "spl": spl_cm,
        },
        "metrics_delta": metrics_delta,
        "category_performance": {
            "baseline": category_perf_baseline,
            "spl": category_perf_spl,
        },
        "mismatches": {
            "count": len(mismatches),
            "details": mismatches,
        },
        "decisions_baseline": decisions_baseline,
        "decisions_spl": decisions_spl,
    }


def generate_markdown_report(results: Dict[str, Any]) -> str:
    cm = results["confusion_matrix"]
    b_cm = cm["baseline"]
    s_cm = cm["spl"]
    md = results["metrics_delta"]
    cat_b = results["category_performance"]["baseline"]
    cat_s = results["category_performance"]["spl"]
    mismatches = results["mismatches"]

    lines = [
        "# SPL vs Rule-Based Baseline — Validation Evaluation Report",
        "",
        f"**Generated:** {results['metadata']['generated_at']}",
        f"**Total domains evaluated:** {results['metadata']['total_domains']}",
        f"**Baseline:** {results['metadata']['condition_baseline']}",
        f"**SPL:** {results['metadata']['condition_spl']}",
        "",
        "---",
        "",
        "## 1. Confusion Matrices",
        "",
        "### Baseline (Rule-Based)",
        "",
        f"| | Predicted Normal | Predicted Risk | |",
        "|---|---|---|---|",
        f"| **Actual Normal** | TN = {b_cm['tn']} | FP = {b_cm['fp']} | |",
        f"| **Actual Risk** | FN = {b_cm['fn']} | TP = {b_cm['tp']} | |",
        f"| | | **N = {b_cm['n']}** | |",
        "",
        f"- Accuracy: {_pct(b_cm['n'] * b_cm['accuracy'], b_cm['n'])}%",
        f"- Precision: {b_cm['precision']:.4f}",
        f"- Recall (TPR): {b_cm['recall']:.4f}",
        f"- Specificity (TNR): {b_cm['specificity']:.4f}",
        f"- FPR: {b_cm['fpr']:.4f}",
        f"- FNR: {b_cm['fnr']:.4f}",
        f"- F1: {b_cm['f1_score']:.4f}",
        "",
        "### SPL Pipeline",
        "",
        f"| | Predicted Normal | Predicted Risk | |",
        "|---|---|---|---|",
        f"| **Actual Normal** | TN = {s_cm['tn']} | FP = {s_cm['fp']} | |",
        f"| **Actual Risk** | FN = {s_cm['fn']} | TP = {s_cm['tp']} | |",
        f"| | | **N = {s_cm['n']}** | |",
        "",
        f"- Accuracy: {_pct(s_cm['n'] * s_cm['accuracy'], s_cm['n'])}%",
        f"- Precision: {s_cm['precision']:.4f}",
        f"- Recall (TPR): {s_cm['recall']:.4f}",
        f"- Specificity (TNR): {s_cm['specificity']:.4f}",
        f"- FPR: {s_cm['fpr']:.4f}",
        f"- FNR: {s_cm['fnr']:.4f}",
        f"- F1: {s_cm['f1_score']:.4f}",
        "",
        "---",
        "",
        "## 2. Metric Comparison (SPL vs Baseline)",
        "",
        "| Metric | Baseline | SPL | Δ | Winner |",
        "|---|---|---|---|---|",
    ]

    for metric in ["accuracy", "precision", "recall", "f1_score", "fpr", "fnr"]:
        d = md[metric]
        winner = "SPL" if d["spl_wins"] else ("Baseline" if d["baseline_wins"] else "Tie")
        lines.append(
            f"| {metric} | {d['baseline']:.4f} | {d['spl']:.4f} | {d['delta']:+.4f} | {winner} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Category-Level Performance",
        "",
        "| Category | Count | Baseline Accuracy | SPL Accuracy | Δ | Winner |",
        "|---|---|---|---|---|---|",
    ])

    for cat in CATEGORY_ORDER:
        if cat not in cat_b or cat not in cat_s:
            continue
        bc = cat_b[cat]
        sc = cat_s[cat]
        count = bc.get("domain_count", 0)
        ba = bc["accuracy"]
        sa = sc["accuracy"]
        delta = sa - ba
        winner = "SPL" if delta > 0 else ("Baseline" if delta < 0 else "Tie")
        lines.append(
            f"| {cat} | {count} | {_pct(count * ba, count)}% | {_pct(count * sa, count)}% | {delta:+.4f} | {winner} |"
        )

    lines.extend([
        "",
        "### Category Confusion Details",
        "",
        "| Category | Baseline TP/TN/FP/FN | SPL TP/TN/FP/FN |",
        "|---|---|---|",
    ])

    for cat in CATEGORY_ORDER:
        if cat not in cat_b or cat not in cat_s:
            continue
        bc = cat_b[cat]
        sc = cat_s[cat]
        lines.append(
            f"| {cat} | {bc['tp']}/{bc['tn']}/{bc['fp']}/{bc['fn']} | {sc['tp']}/{sc['tn']}/{sc['fp']}/{sc['fn']} |"
        )

    mismatches_list = mismatches.get("details", [])
    if mismatches_list:
        lines.extend([
            "",
            "---",
            "",
            "## 4. Decision Mismatches (Baseline ≠ SPL)",
            "",
            f"Domains where baseline and SPL disagree: **{len(mismatches_list)}**",
            "",
            "| Domain | Expected Risk | Baseline | SPL | SPL Prob | SPL Label |",
            "|---|---|---|---|---|---|",
        ])
        for m in mismatches_list[:30]:
            lines.append(
                f"| {m['domain']} | {m['ground_truth']} | {m['baseline']} | {m['spl']} | "
                f"{m['spl_probability']:.4f} | {m['spl_risk_label']} |"
            )
        if len(mismatches_list) > 30:
            lines.append(f"| ... and {len(mismatches_list) - 30} more |")

    lines.extend([
        "",
        "---",
        "",
        "## 5. Does SPL Provide Measurable Value Beyond Rule-Based Baseline?",
        "",
    ])

    accuracy_delta = md["accuracy"]["delta"]
    precision_delta = md["precision"]["delta"]
    recall_delta = md["recall"]["delta"]
    f1_delta = md["f1_score"]["delta"]
    fpr_delta = md["fpr"]["delta"]
    fnr_delta = md["fnr"]["delta"]
    baseline_wins = sum(1 for m in md.values() if m.get("baseline_wins"))
    spl_wins = sum(1 for m in md.values() if m.get("spl_wins"))
    ties = sum(1 for m in md.values() if m.get("tie"))

    if spl_wins > baseline_wins and accuracy_delta > 0:
        verdict = (
            "**LIMITED EVIDENCE OF IMPROVEMENT.** SPL shows marginal gains over "
            "the rule-based baseline in aggregate metrics, but differences are small "
            "and may not generalize to production traffic."
        )
    elif accuracy_delta > 0.01:
        verdict = (
            "**MEASURABLE IMPROVEMENT DETECTED.** SPL outperforms the rule-based "
            "baseline on this benchmark. However, the benchmark has known limitations "
            "(small sample size, category-derived labels, no real ground truth)."
        )
    elif accuracy_delta < -0.01:
        verdict = (
            "**NO MEASURABLE IMPROVEMENT.** SPL underperforms the rule-based baseline "
            "on this benchmark. The deterministic adapter rules are simpler and more "
            "accurate for the classification patterns in this dataset."
        )
    else:
        verdict = (
            "**INCONCLUSIVE.** SPL and the rule-based baseline produce nearly identical "
            "results. The test set may not expose scenarios where SPL's causal reasoning "
            "adds value."
        )

    findings = [
        f"- **Accuracy**: Baseline={md['accuracy']['baseline']:.4f}, SPL={md['accuracy']['spl']:.4f}, Δ={accuracy_delta:+.4f}",
        f"- **Precision**: Baseline={md['precision']['baseline']:.4f}, SPL={md['precision']['spl']:.4f}, Δ={precision_delta:+.4f}",
        f"- **Recall**: Baseline={md['recall']['baseline']:.4f}, SPL={md['recall']['spl']:.4f}, Δ={recall_delta:+.4f}",
        f"- **F1 Score**: Baseline={md['f1_score']['baseline']:.4f}, SPL={md['f1_score']['spl']:.4f}, Δ={f1_delta:+.4f}",
        f"- **FPR**: Baseline={md['fpr']['baseline']:.4f}, SPL={md['fpr']['spl']:.4f}, Δ={fpr_delta:+.4f}",
        f"- **FNR**: Baseline={md['fnr']['baseline']:.4f}, SPL={md['fnr']['spl']:.4f}, Δ={fnr_delta:+.4f}",
        f"- **Metrics where SPL wins**: {spl_wins}/{spl_wins + baseline_wins + ties}",
        f"- **Metrics where Baseline wins**: {baseline_wins}/{spl_wins + baseline_wins + ties}",
    ]

    lines.extend(findings)
    lines.extend(["", verdict, ""])

    limitations = [
        "",
        "### Caveats",
        "",
        "1. **Labels are category-derived, not ground truth.** Expected decisions are",
        "   assigned by domain category membership (e.g., all `.gov` domains → ACCEPTABLE_TLS).",
        "   Real TLS ground truth would require independent verification of each domain's",
        "   certificate chain, revocation status, and security posture.",
        "2. **No HSTS/CSP data.** All probe results report `hsts_present: false, csp_present: false`.",
        "   The rule-based baseline ignores these signals, but SPL includes them as features.",
        "   This may disadvantage SPL (missing expected features → lower confidence).",
        "3. **Small sample in edge categories.** SELF_SIGNED_CERT (1 domain), WRONG_HOST_CERT (1),",
        "   UNTRUSTED_CHAIN (2), INCOMPLETE_CHAIN (1), DEPRECATED_TLS (2) have insufficient samples",
        "   for reliable per-category measurement.",
        "4. **Deprecated TLS detection is unreliable.** The probe negotiates the highest",
        "   mutually supported TLS version, so TLS 1.0/1.1 servers appear as VALID_TLS.",
        "5. **Cold-start SPL pipeline.** No training data is provided — SPL runs in observation",
        "   mode with a cold-start causal graph. Performance would differ with training.",
        "6. **Benchmark is static.** Domain TLS configurations change over time (certificate",
        "   renewal, configuration changes). Results may not reproduce identically.",
    ]
    lines.extend(limitations)

    lines.extend([
        "",
        "---",
        "",
        "## 6. Recommendations",
        "",
        "1. **Collect real ground truth.** Independently verify certificate validity, chain trust,",
        "   revocation, and HSTS/CSP for a held-out set of domains. Use this as the evaluation",
        "   standard instead of category-derived expectations.",
        "2. **Expand the benchmark.** Add more domains to under-represented categories or",
        "   document the decision to exclude them.",
        "3. **Measure with training.** Rerun the evaluation with SPL trained on a separate",
        "   labeled dataset (proxy or real) to measure learning capacity.",
        "4. **Evaluate real-world drift.** Repeat the evaluation monthly to measure how",
        "   domain TLS configurations change over time.",
        "5. **Replace synthetic OFE signals.** The _generate_ofe_signals() modular-arithmetic",
        "   generator has no connection to real topology data. Audit whether OFE features",
        "   can be derived from real measurements or should be removed.",
        "",
        "_No SPL Core modifications were made by this runner. All feature development remains frozen._",
    ])

    return "\n".join(lines)


def main() -> None:
    use_live_probes = "--probe" in sys.argv
    output_dir = REPORT_DIR
    for i, a in enumerate(sys.argv):
        if a == "--output" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("Validation Evaluation Framework")
    print("=" * 60)
    print(f"Output: {output_dir}")
    print(f"Probe mode: {'live' if use_live_probes else 'cached'}")

    if use_live_probes:
        print("\n[Step 1] Writing benchmark dataset files...")
        domain_path = write_benchmark_files()

        print("\n[Step 2] Probing all benchmark domains...")
        cache_path = os.path.join(output_dir, "probe_cache.json")
        probe_results = probe_all_domains(ALL_DOMAINS, cache_path, force_reprobe=True)
    else:
        print("\n[Step 1] Loading cached probe results...")
        cache_path = os.path.join(PROJECT_ROOT, "reports", "local_real_validation", "benchmark_probe_cache.json")
        if not os.path.isfile(cache_path):
            print(f"Error: No cached probe results found at {cache_path}")
            print("Run with --probe first, or run: python scripts/run_stratified_benchmark.py")
            sys.exit(1)
        with open(cache_path, "r", encoding="utf-8") as f:
            probe_results = json.load(f)
        print(f"Loaded {len(probe_results)} cached probe results.")

    probe_by_domain = {r["domain"] for r in probe_results}
    available = [d for d in ALL_DOMAINS if d in probe_by_domain]
    print(f"Domains with probe results: {len(available)} / {len(ALL_DOMAINS)}")
    if not probe_results:
        print("Error: No probe results available.")
        sys.exit(1)

    print("\n[Step 3] Running evaluation...")
    t0 = _time.monotonic()
    results = run_evaluation(probe_results)
    elapsed = _time.monotonic() - t0

    print(f"\n  Evaluation complete in {elapsed:.1f}s")
    print(f"  Domains evaluated: {results['metadata']['total_domains']}")
    print(f"  Mismatches (baseline vs SPL): {results['mismatches']['count']}")

    cm = results["confusion_matrix"]
    print(f"\n  Baseline:  accuracy={cm['baseline']['accuracy']:.4f}, "
          f"precision={cm['baseline']['precision']:.4f}, "
          f"recall={cm['baseline']['recall']:.4f}")
    print(f"  SPL:       accuracy={cm['spl']['accuracy']:.4f}, "
          f"precision={cm['spl']['precision']:.4f}, "
          f"recall={cm['spl']['recall']:.4f}")

    print("\n[Step 4] Writing reports...")
    json_path = os.path.join(output_dir, "validation_evaluation_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"  JSON: {json_path}")

    md_path = os.path.join(output_dir, "VALIDATION_EVALUATION_REPORT.md")
    report = generate_markdown_report(results)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  Report: {md_path}")

    print(f"\n{'=' * 60}")
    print("Done. No SPL Core modifications were made.")
    print("All feature development remains frozen.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
