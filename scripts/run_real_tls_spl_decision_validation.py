"""Phase 4 — Real TLS -> SPL Decision Validation with Holdout Generalization.

Probes TLS domains, converts results to SPL-compatible EvidenceArtifacts,
runs through the SPL pipeline, and validates decisions against policy expectations.

Modes:
  observation      No training. Cold-start graph. No leakage. (default)
  proxy-trained    Train on probe results with proxy labels before evaluation.
  holdout          Train on separate training set, evaluate on holdout set.

Usage:
    python scripts/run_real_tls_spl_decision_validation.py <domain_file> [options]

Options:
    --mode {observation,proxy-trained,holdout}     Validation mode (default: observation)
    --expectations PATH                            Decision expectations JSON (optional)
    --train-domains FILE                           Domains to train on (holdout mode only)
    --train-expectations FILE                      Training labels JSON (holdout mode only, optional)
    --ofe                                          Enable OFE signal injection (observational only)

Examples:
    python scripts/run_real_tls_spl_decision_validation.py datasets/real_tls_mixed_domains.txt
    python scripts/run_real_tls_spl_decision_validation.py datasets/real_tls_mixed_domains.txt --mode proxy-trained --expectations datasets/real_tls_decision_expectations.json
    python scripts/run_real_tls_spl_decision_validation.py datasets/real_tls_holdout_domains.txt --mode holdout --train-domains datasets/real_tls_train_domains.txt --train-expectations datasets/real_tls_train_expectations.json --expectations datasets/real_tls_holdout_expectations.json
"""

from __future__ import annotations

import json
import os
import sys
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from spl_v7.causal import OnlineCausalGraphLearner
from spl_v7.frontier import FrontierExplorer
from spl_v7.kafka_pipeline import EvidencePipeline, MemoryKafkaAdapter, PipelineConfig
from spl_v7.schema import EvidenceArtifact, EvidenceTransportMeta
from spl_v7.verification import compute_artifact_hash

from experiments.dsl_helpers import build_experiment_dsl
from scripts.run_local_tls_validation import probe_domain, CLASSIFICATION_ORDER

REPORT_DIR = "reports/local_real_validation"
OFE_STATUS = "HOLD_PENDING_REAL_DATA"
OFE_SIGNAL_COUNT = 15
DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1"}
DEPRECATED_TLS_CLASSIFICATION = "DEPRECATED_TLS_VERSION"

POLICY_LABELS: Dict[str, str] = {
    "ACCEPTABLE_TLS": "TLS connection succeeded with valid certificate chain.",
    "SECURITY_RISK": "TLS failure indicates a security concern.",
    "AVAILABILITY_RISK": "Domain unreachable due to DNS/connection failure.",
    "AMBIGUOUS_FAILURE": "Failure mode could be security or availability.",
    "UNKNOWN": "Classification could not be determined.",
}

CLASSIFICATION_TO_POLICY: Dict[str, str] = {
    "VALID_TLS": "ACCEPTABLE_TLS",
    "DEPRECATED_TLS_VERSION": "SECURITY_RISK",
    "EXPIRED_CERT": "SECURITY_RISK",
    "SELF_SIGNED_CERT": "SECURITY_RISK",
    "WRONG_HOST_CERT": "SECURITY_RISK",
    "UNTRUSTED_CHAIN": "SECURITY_RISK",
    "INCOMPLETE_CHAIN": "SECURITY_RISK",
    "WEAK_SIGNATURE_ALGORITHM": "SECURITY_RISK",
    "WEAK_CIPHER_SUITE": "SECURITY_RISK",
    "STATIC_RSA_KEY_EXCHANGE": "SECURITY_RISK",
    "TLS_COMPRESSION_ENABLED": "SECURITY_RISK",
    "WILDCARD_CERTIFICATE": "SECURITY_RISK",
    "MISSING_OCSP_STAPLE": "SECURITY_RISK",
    "DNS_FAILURE": "AVAILABILITY_RISK",
    "CONNECTION_ERROR": "AVAILABILITY_RISK",
    "TIMEOUT": "AVAILABILITY_RISK",
    "TLS_HANDSHAKE_FAILURE": "AMBIGUOUS_FAILURE",
    "UNKNOWN_SSL_ERROR": "AMBIGUOUS_FAILURE",
}

CLASSIFICATION_IS_SECURITY: set[str] = {
    "DEPRECATED_TLS_VERSION", "EXPIRED_CERT", "SELF_SIGNED_CERT",
    "WRONG_HOST_CERT", "UNTRUSTED_CHAIN", "INCOMPLETE_CHAIN",
    "WEAK_SIGNATURE_ALGORITHM", "WEAK_CIPHER_SUITE",
    "STATIC_RSA_KEY_EXCHANGE", "TLS_COMPRESSION_ENABLED",
    "WILDCARD_CERTIFICATE", "MISSING_OCSP_STAPLE",
}

CLASSIFICATION_IS_AVAILABILITY: set[str] = {
    "DNS_FAILURE", "CONNECTION_ERROR", "TIMEOUT",
}

CLASSIFICATION_IS_AMBIGUOUS: set[str] = {
    "TLS_HANDSHAKE_FAILURE", "UNKNOWN_SSL_ERROR",
}


def _decision_to_risk_label(decision: bool, probability: float, classification: str) -> str:
    """Map SPL decision + probe classification to a policy risk label.

    This is a post-hoc mapping. SPL's native output is decision (bool) and
    causal_probability (float). The risk label adds policy context by
    interpreting the classification category alongside the SPL decision.
    """
    if not decision:
        return "ACCEPTABLE_TLS"
    if classification in CLASSIFICATION_IS_SECURITY:
        return "SECURITY_RISK"
    if classification in CLASSIFICATION_IS_AVAILABILITY:
        return "AVAILABILITY_RISK"
    if classification in CLASSIFICATION_IS_AMBIGUOUS:
        return "AMBIGUOUS_FAILURE"
    if probability >= 0.7:
        return "SECURITY_RISK"
    if probability >= 0.5:
        return "AMBIGUOUS_FAILURE"
    return "AVAILABILITY_RISK"


def _make_pipeline() -> EvidencePipeline:
    program = build_experiment_dsl()
    return EvidencePipeline(
        feature_program=program,
        causal_graph=OnlineCausalGraphLearner(
            independence_min_support=5.0,
            redundancy_threshold=0.85,
            source_min_support=2.0,
            min_corroborating_sources=2,
        ),
        config=PipelineConfig(backend="memory", emit_graph_snapshot=False),
        adapter=MemoryKafkaAdapter(),
    )


def _generate_ofe_signals(seed_offset: int = 0) -> List[EvidenceArtifact]:
    artifacts: List[EvidenceArtifact] = []
    for i in range(OFE_SIGNAL_COUNT):
        signals = {
            "contradiction_density": min(1.0, 0.3 + ((i + seed_offset) * 7 % 10) / 10.0),
            "topology_drift": min(1.0, 0.2 + ((i + seed_offset) * 13 % 10) / 10.0),
            "symbol_entropy": min(1.0, 0.4 + ((i + seed_offset) * 3 % 10) / 10.0),
            "pattern_frequency": min(1.0, 0.1 + ((i + seed_offset) * 5 % 10) / 10.0),
            "anomaly_score": min(1.0, 0.5 + ((i + seed_offset) * 11 % 10) / 10.0),
        }
        artifact = FrontierExplorer.wrap_structural_signals(
            signals, source="ofe", label=False,
        )
        artifacts.append(artifact)
    return artifacts


def _resolve_classification(probe_result: Dict[str, Any]) -> str:
    """Resolve the effective classification, handling deprecated TLS versions.

    The TLS probe classifies VALID_TLS when the handshake succeeds with any
    TLS version. If the version is TLS 1.0 or TLS 1.1, this is bumped to
    DEPRECATED_TLS_VERSION (which maps to SECURITY_RISK).

    This happens in the evidence adapter layer, not in SPL Core.
    """
    classification = probe_result.get("classification", "UNKNOWN_SSL_ERROR")
    if classification == "VALID_TLS":
        tls_info = probe_result.get("tls") or {}
        tls_version = (tls_info.get("tls_version") or "").strip().lower()
        if tls_version in {v.lower() for v in DEPRECATED_TLS_VERSIONS}:
            return DEPRECATED_TLS_CLASSIFICATION
    return classification


def _probe_result_to_evidence(
    probe_result: Dict[str, Any],
    classification: str,
    include_label: bool = False,
) -> EvidenceArtifact:
    domain = probe_result["domain"]
    tls_info = probe_result.get("tls") or {}

    is_valid = classification == "VALID_TLS"
    expiry_days = tls_info.get("cert_expiry_days")
    if expiry_days is None:
        expiry_days = 30 if is_valid else -1

    transport_status: str
    if classification == "DNS_FAILURE":
        transport_status = "error"
    elif classification == "TIMEOUT":
        transport_status = "timeout"
    elif classification in ("VALID_TLS", "DEPRECATED_TLS_VERSION", "WEAK_CIPHER_SUITE", "STATIC_RSA_KEY_EXCHANGE", "TLS_COMPRESSION_ENABLED", "WILDCARD_CERTIFICATE", "MISSING_OCSP_STAPLE") and not tls_info.get("error_category"):
        transport_status = "ok"
    else:
        transport_status = "error"

    latency_ms = tls_info.get("handshake_time_ms", 0.0) or 0.0

    data: Dict[str, Any] = {
        "valid": is_valid,
        "expiry_days": int(expiry_days) if expiry_days is not None else 0,
        "headers": {"hsts": False, "csp": False},
    }

    if include_label:
        data["label"] = not is_valid
        data["label_weight"] = 1.0

    artifact = EvidenceArtifact(
        source="real-tls",
        type="tls",
        data=data,
        transport_meta=EvidenceTransportMeta(
            status=transport_status,
            latency_ms=latency_ms,
            bytes_received=0,
            error_type=classification,
        ),
        tags=["real-tls-probe", classification, domain],
    )
    artifact.integrity.hash = compute_artifact_hash(artifact)
    return artifact


def _load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def _load_decision_expectations(path: str) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {entry["domain"]: entry["expected_decision"] for entry in data.get("decisions", [])}


def _load_train_expectations(path: str) -> Dict[str, bool]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {entry["domain"]: bool(entry["label"]) for entry in data.get("labels", [])}


def _compute_policy_conformance(
    results: List[Dict[str, Any]],
    expectations: Dict[str, str],
) -> Dict[str, Any]:
    result_map = {r["domain"]: r for r in results}
    correct = 0
    total = 0
    mismatches: List[Dict[str, Any]] = []
    by_policy: Dict[str, Dict[str, Any]] = {}

    for cat in POLICY_LABELS:
        by_policy[cat] = {"expected_count": 0, "correct": 0, "mismatches": []}

    for domain, expected_policy in expectations.items():
        if domain not in result_map:
            continue
        total += 1
        r = result_map[domain]
        actual_policy = r["spl_risk_label"]
        by_policy[expected_policy]["expected_count"] += 1
        if actual_policy == expected_policy:
            correct += 1
            by_policy[expected_policy]["correct"] += 1
        else:
            mismatches.append({
                "domain": domain,
                "expected": expected_policy,
                "actual": actual_policy,
                "classification": r["classification"],
                "confidence": r.get("causal_probability", 0.0),
                "decision": r.get("decision", False),
            })
            by_policy[expected_policy]["mismatches"].append({
                "domain": domain,
                "actual": actual_policy,
                "confidence": r.get("causal_probability", 0.0),
            })

    conformance_pct = round(correct / total * 100, 1) if total else 0.0
    per_policy: Dict[str, Dict[str, Any]] = {}
    for cat, info in by_policy.items():
        if info["expected_count"] > 0:
            cat_correct_pct = round(info["correct"] / info["expected_count"] * 100, 1)
        else:
            cat_correct_pct = 0.0
        per_policy[cat] = {
            "expected_count": info["expected_count"],
            "correct": info["correct"],
            "conformance_pct": cat_correct_pct,
            "mismatch_count": len(info["mismatches"]),
        }

    return {
        "total_expected": len(expectations),
        "total_with_results": total,
        "correct": correct,
        "conformance_pct": conformance_pct,
        "per_policy": per_policy,
        "mismatches": mismatches[:20],
        "missing_results": [d for d in expectations if d not in result_map],
    }


def _run_pipeline_eval(
    pipeline: EvidencePipeline,
    probe_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for pr in probe_results:
        classification = _resolve_classification(pr)
        artifact = _probe_result_to_evidence(pr, classification, include_label=False)
        pipeline.ingest(artifact.to_dict())
        r = pipeline.process_one(timeout=0.05)
        if r is None:
            r = {"causal_probability": 0.0, "decision": False, "features": {}, "numeric_features": {}}

        spl_decision = r.get("decision", False)
        spl_probability = r.get("causal_probability", 0.0)
        spl_features = r.get("features", {})
        spl_risk_label = _decision_to_risk_label(spl_decision, spl_probability, classification)

        weakness_flags: Dict[str, Any] = {}
        if isinstance(spl_features, dict):
            weakness_flags["http_error_flag"] = int(spl_features.get("http_error_flag", 0))
            weakness_flags["partial_flag"] = int(spl_features.get("partial_flag", 0))
            weakness_flags["hsts_missing"] = int(spl_features.get("hsts_missing", 0))
            weakness_flags["timeout_flag"] = int(spl_features.get("timeout_flag", 0))
            weakness_flags["surface_tension"] = round(float(spl_features.get("surface_tension", 0.0)), 4)

        results.append({
            "domain": pr["domain"],
            "classification": classification,
            "policy_from_classification": CLASSIFICATION_TO_POLICY.get(classification, "UNKNOWN"),
            "spl_decision": spl_decision,
            "spl_probability": round(spl_probability, 4),
            "spl_risk_label": spl_risk_label,
            "spl_features": spl_features,
            "weakness_flags": weakness_flags,
        })
    return results


def _train_pipeline(pipeline: EvidencePipeline, probe_results: List[Dict[str, Any]]) -> None:
    for pr in probe_results:
        classification = _resolve_classification(pr)
        artifact = _probe_result_to_evidence(pr, classification, include_label=True)
        pipeline.ingest(artifact.to_dict())
        pipeline.process_one(timeout=0.05)


def _train_pipeline_with_labels(
    pipeline: EvidencePipeline,
    probe_results: List[Dict[str, Any]],
    train_labels: Dict[str, bool],
) -> None:
    for pr in probe_results:
        domain = pr["domain"]
        classification = _resolve_classification(pr)
        artifact = _probe_result_to_evidence(pr, classification, include_label=False)
        if domain in train_labels:
            artifact.data["label"] = train_labels[domain]
        else:
            artifact.data["label"] = classification != "VALID_TLS"
        artifact.data["label_weight"] = 1.0
        pipeline.ingest(artifact.to_dict())
        pipeline.process_one(timeout=0.05)


def _probe_domain_list(domains: List[str], label: str = "domains") -> List[Dict[str, Any]]:
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
    return results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/run_real_tls_spl_decision_validation.py <domain_file> [options]")
        print("")
        print("  domain_file                Path to EVALUATION domains (one per line)")
        print("  --mode MODE                Validation mode: observation (default), proxy-trained, or holdout")
        print("  --expectations PATH        Decision expectations JSON for SCORING (optional)")
        print("  --train-domains FILE       Domains to TRAIN on (holdout mode only)")
        print("  --train-expectations FILE  Training labels JSON (holdout mode only, optional)")
        print("  --ofe                      Enable OFE signal injection (observational only)")
        sys.exit(1)

    domain_path = sys.argv[1]
    expectations_path: Optional[str] = None
    train_domains_path: Optional[str] = None
    train_expectations_path: Optional[str] = None
    mode = "observation"
    use_ofe = False

    i = 2
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--mode" and i + 1 < len(sys.argv):
            mode = sys.argv[i + 1].lower()
            if mode not in ("observation", "proxy-trained", "holdout"):
                print(f"Error: unknown mode '{mode}'. Use 'observation', 'proxy-trained', or 'holdout'.", flush=True)
                sys.exit(1)
            i += 2
        elif a == "--expectations" and i + 1 < len(sys.argv):
            expectations_path = sys.argv[i + 1]
            i += 2
        elif a == "--train-domains" and i + 1 < len(sys.argv):
            train_domains_path = sys.argv[i + 1]
            i += 2
        elif a == "--train-expectations" and i + 1 < len(sys.argv):
            train_expectations_path = sys.argv[i + 1]
            i += 2
        elif a == "--ofe":
            use_ofe = True
            i += 1
        else:
            i += 1

    if mode == "holdout" and not train_domains_path:
        print("Error: holdout mode requires --train-domains", flush=True)
        sys.exit(1)

    if train_domains_path and mode != "holdout":
        print("Warning: --train-domains ignored in non-holdout mode", flush=True)

    if not os.path.isfile(domain_path):
        print(f"Error: domain file not found: {domain_path}", flush=True)
        sys.exit(1)

    eval_domains = _load_domains(domain_path)
    expectations: Dict[str, str] = {}
    if expectations_path:
        if os.path.isfile(expectations_path):
            expectations = _load_decision_expectations(expectations_path)
            print(f"[SPLDecisionValidation] Loaded {len(expectations)} scoring expectations from {expectations_path}", flush=True)
        else:
            print(f"[SPLDecisionValidation] Warning: expectations file not found: {expectations_path}", flush=True)

    os.makedirs(REPORT_DIR, exist_ok=True)

    print(f"[SPLDecisionValidation] Mode: {mode}", flush=True)

    # ── Phase 1: Probe ───────────────────────────────────────────────
    train_probe_results: List[Dict[str, Any]] = []
    eval_probe_results: List[Dict[str, Any]] = []

    if mode == "holdout":
        if not os.path.isfile(train_domains_path):
            print(f"Error: train domains file not found: {train_domains_path}", flush=True)
            sys.exit(1)
        train_domains = _load_domains(train_domains_path)
        print(f"[SPLDecisionValidation] Probing {len(train_domains)} training domains...", flush=True)
        train_probe_results = _probe_domain_list(train_domains, "training")

        train_labels: Dict[str, bool] = {}
        if train_expectations_path:
            if os.path.isfile(train_expectations_path):
                train_labels = _load_train_expectations(train_expectations_path)
                print(f"[SPLDecisionValidation] Loaded {len(train_labels)} training labels from {train_expectations_path}", flush=True)
            else:
                print(f"[SPLDecisionValidation] Warning: train expectations not found: {train_expectations_path}", flush=True)

        print(f"[SPLDecisionValidation] Probing {len(eval_domains)} evaluation domains...", flush=True)
        eval_probe_results = _probe_domain_list(eval_domains, "evaluation")
    else:
        print(f"[SPLDecisionValidation] Probing {len(eval_domains)} domains...", flush=True)
        eval_probe_results = _probe_domain_list(eval_domains, "evaluation")

    # ── Phase 2: Build + optionally train pipeline ──────────────────
    pipeline = _make_pipeline()

    if mode == "observation":
        print(f"[SPLDecisionValidation] Observation mode — no training.", flush=True)
    elif mode == "proxy-trained":
        print(f"[SPLDecisionValidation] Training on {len(eval_probe_results)} probe results with proxy labels...", flush=True)
        _train_pipeline(pipeline, eval_probe_results)
        print(f"[SPLDecisionValidation] Training complete.", flush=True)
    elif mode == "holdout":
        print(f"[SPLDecisionValidation] Training on {len(train_probe_results)} training domains...", flush=True)
        if train_labels:
            _train_pipeline_with_labels(pipeline, train_probe_results, train_labels)
            print(f"[SPLDecisionValidation] Training complete (with external labels).", flush=True)
        else:
            _train_pipeline(pipeline, train_probe_results)
            print(f"[SPLDecisionValidation] Training complete (with proxy labels — no --train-expectations).", flush=True)

    # ── Phase 3: Evaluate ───────────────────────────────────────────
    print(f"[SPLDecisionValidation] Evaluating pipeline on {len(eval_probe_results)} domains...", flush=True)
    results = _run_pipeline_eval(pipeline, eval_probe_results)

    # ── Phase 4: Optional OFE comparison ─────────────────────────────
    ofe_results: Optional[List[Dict[str, Any]]] = None
    if use_ofe:
        print(f"[SPLDecisionValidation] Running OFE comparison...", flush=True)
        pipeline_ofe = _make_pipeline()
        if mode == "proxy-trained":
            _train_pipeline(pipeline_ofe, eval_probe_results)
        elif mode == "holdout":
            if train_labels:
                _train_pipeline_with_labels(pipeline_ofe, train_probe_results, train_labels)
            else:
                _train_pipeline(pipeline_ofe, train_probe_results)

        ofe_signals = _generate_ofe_signals(seed_offset=42)
        for signal in ofe_signals:
            pipeline_ofe.ingest(signal.to_dict())
            pipeline_ofe.process_one(timeout=0.05)

        ofe_results = _run_pipeline_eval(pipeline_ofe, eval_probe_results)

    # ── Phase 5: Score (expectations are ONLY used here, after decisions) ──
    conformance = None
    if expectations:
        conformance = _compute_policy_conformance(results, expectations)

    # ── Phase 6: Reports ─────────────────────────────────────────────
    train_set_info: Optional[Dict[str, Any]] = None
    if mode == "holdout":
        train_set_info = {
            "train_domains_path": os.path.abspath(train_domains_path),
            "train_domain_count": len(train_probe_results),
            "train_expectations_path": os.path.abspath(train_expectations_path) if train_expectations_path else None,
            "train_labels_loaded": len(train_labels) if mode == "holdout" and train_expectations_path else 0,
        }

    report_md = _build_report(
        domain_path, mode, results, conformance, ofe_results,
        expectations_path, train_set_info,
    )
    report_filename = f"SPL_DECISION_VALIDATION_REPORT_{mode}.md"
    report_path = os.path.join(REPORT_DIR, report_filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"[SPLDecisionValidation] Report written to {report_path}", flush=True)

    results_json = _build_results_json(
        domain_path, mode, eval_probe_results, results, conformance,
        ofe_results, expectations_path, train_set_info, train_probe_results if mode == "holdout" else None,
    )
    json_filename = f"spl_decision_validation_results_{mode}.json"
    json_path = os.path.join(REPORT_DIR, json_filename)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results_json, f, indent=2, default=str)
    print(f"[SPLDecisionValidation] JSON results written to {json_path}", flush=True)

    eval_valid = sum(1 for r in results if r["classification"] == "VALID_TLS")
    risks = sum(1 for r in results if r["spl_decision"])
    print(f"\n[SPLDecisionValidation] Done ({mode}). {len(results)} eval domains, {eval_valid} valid, {risks} risks detected.", flush=True)

    if conformance:
        print(f"[SPLDecisionValidation] Policy conformance: {conformance['conformance_pct']}% ({conformance['correct']}/{conformance['total_with_results']})", flush=True)


def _build_report(
    domain_path: str,
    mode: str,
    results: List[Dict[str, Any]],
    conformance: Optional[Dict[str, Any]],
    ofe_results: Optional[List[Dict[str, Any]]],
    expectations_path: Optional[str],
    train_set_info: Optional[Dict[str, Any]] = None,
) -> str:
    total = len(results)
    valid_tls = sum(1 for r in results if r["classification"] == "VALID_TLS")
    deprecated_tls = sum(1 for r in results if r["classification"] == "DEPRECATED_TLS_VERSION")
    risks = sum(1 for r in results if r["spl_decision"])
    acceptable = sum(1 for r in results if r["spl_risk_label"] == "ACCEPTABLE_TLS")
    security_risks = sum(1 for r in results if r["spl_risk_label"] == "SECURITY_RISK")
    availability_risks = sum(1 for r in results if r["spl_risk_label"] == "AVAILABILITY_RISK")
    ambiguous = sum(1 for r in results if r["spl_risk_label"] == "AMBIGUOUS_FAILURE")

    classification_counts: Dict[str, int] = {}
    for r in results:
        c = r["classification"]
        classification_counts[c] = classification_counts.get(c, 0) + 1

    if mode == "observation":
        mode_label = "Observation (cold-start graph, no training)"
        leakage_note = "No training leakage — decisions reflect cold-start graph prior only."
    elif mode == "proxy-trained":
        mode_label = "Proxy-Trained (trained on probe results with proxy labels)"
        leakage_note = "Trained on eval dataset — results show learning capacity, not generalization."
    elif mode == "holdout":
        mode_label = "Holdout (trained on separate training set, evaluated on unseen holdout)"
        train_count = train_set_info["train_domain_count"] if train_set_info else "N/A"
        leakage_note = f"Trained on {train_count} domains from a separate training set, evaluated on {total} unseen holdout domains."
    else:
        mode_label = mode
        leakage_note = ""

    lines = [
        "# Real TLS -> SPL Decision Validation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"Runner: `scripts/run_real_tls_spl_decision_validation.py`",
        f"Mode: **{mode_label}**",
        f"Eval domain list: `{domain_path}`",
    ]

    if train_set_info:
        lines.append(f"Train domain list: `{train_set_info['train_domains_path']}`")
        if train_set_info.get("train_labels_loaded", 0) > 0:
            lines.append(f"Training labels: `{train_set_info['train_expectations_path']}` ({train_set_info['train_labels_loaded']} labels)")

    if expectations_path:
        lines.append(f"Scoring expectations: `{expectations_path}`")

    lines.extend([
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Eval domains tested | {total} |",
    ])

    if train_set_info:
        lines.append(f"| Training domains | {train_set_info['train_domain_count']} |")

    lines.extend([
        f"| TLS valid | {valid_tls} |",
        f"| Deprecated TLS (TLS 1.0/1.1) | {deprecated_tls} |",
        f"| SPL decisions (ALLOW) | {acceptable} |",
        f"| SPL decisions (DENY — risk detected) | {risks} |",
        f"| Security risks | {security_risks} |",
        f"| Availability risks | {availability_risks} |",
        f"| Ambiguous | {ambiguous} |",
        f"| Leakage status | {leakage_note} |",
    ])

    if conformance:
        lines.append(f"| Policy conformance | {conformance['conformance_pct']}% |")
        lines.append(f"| Correctly conformant | {conformance['correct']}/{conformance['total_with_results']} |")

    lines.extend([
        "",
        "---",
        "",
        "## Classification Breakdown",
        "",
        "| Classification | Count | SPL Risk Label |",
        "|---|---|---|",
    ])

    for cat in (*CLASSIFICATION_ORDER, "DEPRECATED_TLS_VERSION"):
        count = classification_counts.get(cat, 0)
        if count:
            first_result = next((r for r in results if r["classification"] == cat), None)
            label = first_result["spl_risk_label"] if first_result else "N/A"
            lines.append(f"| {cat} | {count} | {label} |")

    lines.extend([
        "",
        "---",
        "",
        "## SPL Decision Distribution",
        "",
        "| Risk Label | Count | Percentage |",
        "|---|---|---|",
        f"| ACCEPTABLE_TLS | {acceptable} | {_pct(acceptable, total)}% |",
        f"| SECURITY_RISK | {security_risks} | {_pct(security_risks, total)}% |",
        f"| AVAILABILITY_RISK | {availability_risks} | {_pct(availability_risks, total)}% |",
        f"| AMBIGUOUS_FAILURE | {ambiguous} | {_pct(ambiguous, total)}% |",
    ])

    confidences = [r.get("spl_probability", 0.0) for r in results]
    high_conf = sum(1 for c in confidences if c >= 0.7)
    mod_conf = sum(1 for c in confidences if 0.5 <= c < 0.7)
    low_conf = sum(1 for c in confidences if c < 0.5)
    avg_conf = round(sum(confidences) / len(confidences), 4) if confidences else 0.0

    lines.extend([
        "",
        "## Confidence Distribution",
        "",
        "| Range | Count |",
        "|---|---|",
        f"| High (>= 0.7) | {high_conf} |",
        f"| Moderate (0.5-0.7) | {mod_conf} |",
        f"| Low (< 0.5) | {low_conf} |",
        f"| Average | {avg_conf} |",
    ])

    low_conf_domains = [r for r in results if r.get("spl_probability", 0.0) < 0.5 and r["spl_decision"]]
    if low_conf_domains:
        lines.extend([
            "",
            "### Low-Confidence Risk Decisions",
            "",
            "| Domain | Classification | Probability | Risk Label |",
            "|---|---|---|---|",
        ])
        for r in low_conf_domains[:10]:
            lines.append(f"| {r['domain']} | {r['classification']} | {r['spl_probability']} | {r['spl_risk_label']} |")

    weak_http_error = sum(1 for r in results if r.get("weakness_flags", {}).get("http_error_flag", 0))
    weak_partial = sum(1 for r in results if r.get("weakness_flags", {}).get("partial_flag", 0))
    weak_hsts = sum(1 for r in results if r.get("weakness_flags", {}).get("hsts_missing", 0))
    weak_timeout = sum(1 for r in results if r.get("weakness_flags", {}).get("timeout_flag", 0))

    lines.extend([
        "",
        "## Weakness Flags (from DSL features)",
        "",
        "| Flag | Triggered | Description |",
        "|---|---|---|",
        f"| http_error_flag | {weak_http_error} | Transport status was 'error' |",
        f"| partial_flag | {weak_partial} | Transport status was 'partial' |",
        f"| hsts_missing | {weak_hsts} | HSTS header absent (all default False) |",
        f"| timeout_flag | {weak_timeout} | Transport status was 'timeout' |",
    ])

    if deprecated_tls:
        dep_domains = [r for r in results if r["classification"] == "DEPRECATED_TLS_VERSION"]
        lines.extend([
            "",
            "## Deprecated TLS Version Handling",
            "",
            f"The following {deprecated_tls} domain(s) connected successfully but used a deprecated",
            "TLS version (TLS 1.0 or TLS 1.1). These are reclassified from VALID_TLS to",
            "DEPRECATED_TLS_VERSION at the evidence adapter layer, which maps to SECURITY_RISK.",
            "",
            "| Domain | Risk Label | Decision | Probability |",
            "|---|---|---|---|",
        ])
        for r in dep_domains:
            lines.append(f"| {r['domain']} | {r['spl_risk_label']} | {r['spl_decision']} | {r['spl_probability']} |")

    if conformance:
        lines.extend([
            "",
            "---",
            "",
            "## Policy Conformance Analysis",
            "",
            f"Overall conformance: **{conformance['conformance_pct']}%** ({conformance['correct']}/{conformance['total_with_results']})",
            "",
            "### Per-Policy Conformance",
            "",
            "| Policy | Expected | Correct | Conformance | Mismatches |",
            "|---|---|---|---|---|",
        ])

        for cat in ["ACCEPTABLE_TLS", "SECURITY_RISK", "AVAILABILITY_RISK", "AMBIGUOUS_FAILURE"]:
            info = conformance.get("per_policy", {}).get(cat)
            if info and info["expected_count"] > 0:
                lines.append(
                    f"| {cat} | {info['expected_count']} | {info['correct']} | "
                    f"{info['conformance_pct']}% | {info['mismatch_count']} |"
                )

        mismatches = conformance.get("mismatches", [])
        if mismatches:
            lines.extend([
                "",
                "### Mismatches",
                "",
                "| Domain | Expected | Actual | Classification | Confidence |",
                "|---|---|---|---|---|",
            ])
            for m in mismatches:
                lines.append(
                    f"| {m['domain']} | {m['expected']} | {m['actual']} | "
                    f"{m['classification']} | {m['confidence']} |"
                )

    if conformance and conformance.get("missing_results"):
        lines.extend(["", "### Missing Results (in expectations but not probed)", ""])
        for d in conformance["missing_results"]:
            lines.append(f"- {d}")

    if ofe_results:
        ofe_risks = sum(1 for r in ofe_results if r["spl_decision"])
        ofe_security = sum(1 for r in ofe_results if r["spl_risk_label"] == "SECURITY_RISK")
        ofe_acceptable = sum(1 for r in ofe_results if r["spl_risk_label"] == "ACCEPTABLE_TLS")
        ofe_ambiguous_c = sum(1 for r in ofe_results if r["spl_risk_label"] == "AMBIGUOUS_FAILURE")
        ofe_avail = sum(1 for r in ofe_results if r["spl_risk_label"] == "AVAILABILITY_RISK")

        decision_changes = 0
        r_map = {r["domain"]: r for r in results}
        for or_ in ofe_results:
            br = r_map.get(or_["domain"])
            if br and br["spl_decision"] != or_["spl_decision"]:
                decision_changes += 1

        lines.extend([
            "",
            "---",
            "",
            "## OFE Signal Comparison (Observational)",
            "",
            f"OFE Status: {OFE_STATUS}",
            "",
            "| Metric | Baseline | OFE |",
            "|---|---|---|",
            f"| Decisions (DENY) | {risks} | {ofe_risks} |",
            f"| Security risks | {security_risks} | {ofe_security} |",
            f"| Acceptable | {acceptable} | {ofe_acceptable} |",
            f"| Availability risks | {availability_risks} | {ofe_avail} |",
            f"| Ambiguous | {ambiguous} | {ofe_ambiguous_c} |",
            f"| Decision changes | — | {decision_changes} |",
        ])

        if decision_changes > 0:
            lines.extend(["", "### Domains with Changed Decisions", "", "| Domain | Baseline Decision | OFE Decision |", "|---|---|---|"])
            for or_ in ofe_results:
                br = r_map.get(or_["domain"])
                if br and br["spl_decision"] != or_["spl_decision"]:
                    lines.append(f"| {or_['domain']} | {br['spl_decision']} | {or_['spl_decision']} |")

        lines.extend([
            "",
            f"**Note**: OFE remains {OFE_STATUS}. These results are observational only.",
            "No signal was promoted by this runner.",
        ])

    lines.extend([
        "",
        "---",
        "",
        "## Known Limitations",
        "",
        "1. **No ground-truth labels** — SPL was trained on proxy or external labels, not real ground truth.",
        "2. **No HSTS/CSP confirmation** — headers are assumed absent (default False).",
        "3. **Chain trust ambiguity** — INCOMPLETE_CHAIN vs UNTRUSTED_CHAIN not distinguishable at probe level.",
        "4. **Single IP per domain** — only the first A record is probed.",
        "5. **No IPv6** — probes use IPv4 only.",
        "6. **No CRL/OCSP checking** — revocation is not verified.",
        "7. **Cold-start graph** — in observation mode, the OnlineCausalGraphLearner starts with no edges.",
        "8. **Proxy labels** — label=True for all non-VALID_TLS domains creates a strong bias.",
        "9. **OFE comparison** — OFE signals are synthetic structural signals, not derived from real TLS data.",
        "10. **TLS version probing** — deprecated TLS detection relies on the handshake succeeding with the default SSL context.",
        "11. **Holdout generalization** — limited by dataset size; some categories have only 1 sample and cannot be split.",
        "",
        "_This report is for local evidence gathering only. No production claims are made._",
    ])

    return "\n".join(lines)


def _build_results_json(
    domain_path: str,
    mode: str,
    eval_probe_results: List[Dict[str, Any]],
    results: List[Dict[str, Any]],
    conformance: Optional[Dict[str, Any]],
    ofe_results: Optional[List[Dict[str, Any]]],
    expectations_path: Optional[str],
    train_set_info: Optional[Dict[str, Any]] = None,
    train_probe_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "runner": "SPLDecisionValidationRunner",
        "mode": mode,
        "eval_domain_list": os.path.abspath(domain_path),
        "scoring_expectations": os.path.abspath(expectations_path) if expectations_path else None,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "note": f"Phase 4: Mode={mode}. No SPL Core modifications were made.",
        "ofe_status": OFE_STATUS,
    }

    if train_set_info:
        meta["train_domain_list"] = train_set_info["train_domains_path"]
        meta["train_expectations"] = train_set_info.get("train_expectations_path")

    return {
        "metadata": meta,
        "summary": {
            "eval_domains": len(results),
            "train_domains": train_set_info["train_domain_count"] if train_set_info else None,
            "valid_tls": sum(1 for r in results if r["classification"] == "VALID_TLS"),
            "deprecated_tls": sum(1 for r in results if r["classification"] == "DEPRECATED_TLS_VERSION"),
            "spl_risks_detected": sum(1 for r in results if r["spl_decision"]),
            "acceptable": sum(1 for r in results if r["spl_risk_label"] == "ACCEPTABLE_TLS"),
            "security_risks": sum(1 for r in results if r["spl_risk_label"] == "SECURITY_RISK"),
            "availability_risks": sum(1 for r in results if r["spl_risk_label"] == "AVAILABILITY_RISK"),
            "ambiguous": sum(1 for r in results if r["spl_risk_label"] == "AMBIGUOUS_FAILURE"),
        },
        "conformance": conformance,
        "results": results,
        "ofe_results": ofe_results,
    }


def _pct(n: int, total: int) -> str:
    return f"{round(n / max(total, 1) * 100, 1)}"


if __name__ == "__main__":
    main()
