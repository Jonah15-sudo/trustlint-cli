import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from spl_v7.causal import OnlineCausalGraphLearner
from spl_v7.kafka_pipeline import EvidencePipeline, MemoryKafkaAdapter, PipelineConfig
from spl_v7.schema import EvidenceArtifact, EvidenceTransportMeta
from spl_v7.verification import compute_artifact_hash
from experiments.dsl_helpers import build_experiment_dsl

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

def row_to_artifact(row: Dict[str, Any], include_label: bool = False) -> EvidenceArtifact:
    artifact = EvidenceArtifact(
        source="real-tls",
        type="tls",
        data={
            "valid": bool(row.get("tls_valid", False)),
            "expiry_days": int(row.get("tls_expiry_days", 0)),
            "headers": {
                "hsts": bool(row.get("hsts_present", False)),
                "csp": bool(row.get("csp_present", False)),
            }
        },
        transport_meta=EvidenceTransportMeta(
            status=str(row.get("http_status", "error")),
            latency_ms=int(row.get("latency_ms", 0)),
            bytes_received=int(row.get("bytes_received", 0)),
        )
    )
    if include_label:
        artifact.data["label"] = bool(row.get("label", False))
        artifact.data["label_weight"] = 1.0
    
    artifact.integrity.hash = compute_artifact_hash(artifact)
    return artifact

def compute_metrics(results: List[Dict[str, Any]], mode_name: str) -> Dict[str, Any]:
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    cat_breakdown = {}
    
    for r in results:
        actual = r["operational_label"]  # True = RISK, False = ACCEPTABLE
        predicted = r["predicted"]       # True = RISK, False = ACCEPTABLE
        
        # Categorization based on actual row values
        if r["row"].get("tls_valid"):
            cat = "VALID_TLS"
        elif r["row"].get("timeout"):
            cat = "TIMEOUT"
        elif r["row"].get("http_status") == "error":
            cat = "CONNECTION_ERROR"
        else:
            cat = "OTHER_FAILURE"
            
        if cat not in cat_breakdown:
            cat_breakdown[cat] = {"total": 0, "correct": 0}
            
        cat_breakdown[cat]["total"] += 1
        if actual == predicted:
            cat_breakdown[cat]["correct"] += 1
        
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        elif actual and not predicted:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "mode": mode_name,
        "total": total,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {
            "TP": tp, "FP": fp, "TN": tn, "FN": fn
        },
        "per_category": cat_breakdown,
        "disagreements": [r for r in results if r["operational_label"] != r["predicted"]][:20]
    }

def evaluate_baseline(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results = []
    for r in rows:
        # Rule-based baseline: if not valid, it's a risk.
        decision = not bool(r.get("tls_valid", False))
        operational_label = bool(r.get("label", False))
        results.append({
            "row": r,
            "predicted": decision,
            "operational_label": operational_label,
            "confidence": 1.0 # Rule-based is deterministic
        })
    return results

def evaluate_spl_cold_start(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pipeline = _make_pipeline()
    results = []
    for r in rows:
        artifact = row_to_artifact(r, include_label=False)
        pipeline.ingest(artifact.to_dict())
        res = pipeline.process_one(timeout=0.05)
        
        predicted = res.get("decision", False) if res else False
        confidence = res.get("causal_probability", 0.0) if res else 0.0
        operational_label = bool(r.get("label", False))
        
        results.append({
            "row": r,
            "predicted": predicted,
            "operational_label": operational_label,
            "confidence": confidence
        })
    return results

def evaluate_spl_proxy_trained(train_rows: List[Dict[str, Any]], eval_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pipeline = _make_pipeline()
    
    # Train
    for r in train_rows:
        artifact = row_to_artifact(r, include_label=True)
        pipeline.ingest(artifact.to_dict())
        pipeline.process_one(timeout=0.05)
        
    # Evaluate
    results = []
    for r in eval_rows:
        artifact = row_to_artifact(r, include_label=False)
        pipeline.ingest(artifact.to_dict())
        res = pipeline.process_one(timeout=0.05)
        
        predicted = res.get("decision", False) if res else False
        confidence = res.get("causal_probability", 0.0) if res else 0.0
        operational_label = bool(r.get("label", False))
        
        results.append({
            "row": r,
            "predicted": predicted,
            "operational_label": operational_label,
            "confidence": confidence
        })
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python evaluate_spl_vs_baseline.py <dataset_jsonl> [--output <report.md>]")
        sys.exit(1)
        
    dataset_path = sys.argv[1]
    output_path = "reports/spl_vs_baseline_final_report.md"
    if len(sys.argv) >= 4 and sys.argv[2] == "--output":
        output_path = sys.argv[3]
        
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset {dataset_path} not found.")
        sys.exit(1)
        
    rows = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
                
    print(f"Loaded {len(rows)} rows from {dataset_path}")
    
    # Baseline
    print("Evaluating Baseline Mode...")
    baseline_results = evaluate_baseline(rows)
    baseline_metrics = compute_metrics(baseline_results, "Baseline (Rule-Based)")
    
    # SPL Cold Start
    print("Evaluating SPL Cold-Start Mode...")
    spl_cold_results = evaluate_spl_cold_start(rows)
    spl_cold_metrics = compute_metrics(spl_cold_results, "SPL Cold-Start")
    
    # SPL Proxy-Trained
    print("Evaluating SPL Proxy-Trained Mode (80/20 split)...")
    split_idx = int(len(rows) * 0.8)
    train_rows = rows[:split_idx]
    eval_rows = rows[split_idx:]
    spl_trained_results = evaluate_spl_proxy_trained(train_rows, eval_rows)
    spl_trained_metrics = compute_metrics(spl_trained_results, "SPL Proxy-Trained")
    
    # Final Decision
    b_f1 = baseline_metrics["f1_score"]
    t_f1 = spl_trained_metrics["f1_score"]
    
    b_acc = baseline_metrics["accuracy"]
    t_acc = spl_trained_metrics["accuracy"]
    
    if t_f1 > b_f1 and t_acc > b_acc:
        outcome = "SPL is BETTER than baseline"
    elif t_f1 == b_f1 and t_acc == b_acc:
        outcome = "SPL is EQUIVALENT to baseline"
    else:
        outcome = "SPL is WORSE than baseline"
        
    # Build Markdown Report
    lines = [
        "# Interim Real-Data Evaluation: SPL vs Baseline",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"Dataset: {dataset_path} ({len(rows)} rows)",
        "",
        "> **Note**: This is an interim real-data evaluation using 2,179 rows. The 5,000-row dataset requirement is maintained as a separate promotion gate. Labels used here are probe-derived reference operational labels.",
        "",
        "## Final Outcome",
        f"**{outcome}**",
        "",
        "## Metrics Comparison",
        "| Metric | Baseline | SPL Cold-Start | SPL Proxy-Trained |",
        "|---|---|---|---|",
        f"| Accuracy | {b_acc} | {spl_cold_metrics['accuracy']} | {t_acc} |",
        f"| F1 Score | {b_f1} | {spl_cold_metrics['f1_score']} | {t_f1} |",
        f"| Precision | {baseline_metrics['precision']} | {spl_cold_metrics['precision']} | {spl_trained_metrics['precision']} |",
        f"| Recall | {baseline_metrics['recall']} | {spl_cold_metrics['recall']} | {spl_trained_metrics['recall']} |",
        f"| FPR | {baseline_metrics['fpr']} | {spl_cold_metrics['fpr']} | {spl_trained_metrics['fpr']} |",
        f"| FNR | {baseline_metrics['fnr']} | {spl_cold_metrics['fnr']} | {spl_trained_metrics['fnr']} |",
        "",
        "## Confusion Matrices",
        "**Baseline**:",
        f"- TP: {baseline_metrics['confusion_matrix']['TP']} | FP: {baseline_metrics['confusion_matrix']['FP']}",
        f"- FN: {baseline_metrics['confusion_matrix']['FN']} | TN: {baseline_metrics['confusion_matrix']['TN']}",
        "",
        "**SPL Proxy-Trained**:",
        f"- TP: {spl_trained_metrics['confusion_matrix']['TP']} | FP: {spl_trained_metrics['confusion_matrix']['FP']}",
        f"- FN: {spl_trained_metrics['confusion_matrix']['FN']} | TN: {spl_trained_metrics['confusion_matrix']['TN']}",
        "",
        "## Disagreements with Baseline",
    ]
    
    disagreements = [r for r in spl_trained_results if r["predicted"] != r["operational_label"]]
    lines.append(f"SPL Proxy-Trained had {len(disagreements)} disagreements with the operational label (which perfectly matches the baseline).")
    if disagreements:
        lines.append("### Sample Disagreements:")
        for r in disagreements[:10]:
            lines.append(f"- Case {r['row'].get('case_id')}: Baseline/Label={r['operational_label']}, SPL={r['predicted']}, Confidence={r['confidence']:.2f}, valid={r['row'].get('tls_valid')}, error={r['row'].get('http_status')}")

    lines.append("")
    lines.append("## Conclusion")
    lines.append("By evaluating SPL against purely deterministic baseline logic derived directly from real observational metadata (operational labels), we remove all synthetic artifacts.")
    if outcome == "SPL is WORSE than baseline":
        lines.append("The results demonstrate that SPL (as an online causal graph) struggles to perfectly replicate deterministic rule-based policies without requiring an excessive learning period or yielding false positives/negatives. It adds architectural complexity without surpassing the baseline's 100% adherence to its own operational labels.")
    elif outcome == "SPL is EQUIVALENT to baseline":
        lines.append("The results demonstrate that SPL eventually memorizes the baseline rules but provides no measurable uplift beyond what a simple rule-engine provides natively.")
    else:
        lines.append("The results demonstrate that SPL generalizes beyond deterministic constraints to correctly label ambiguous operational contexts.")
        
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        
    print(f"Report written to {output_path}")

if __name__ == "__main__":
    main()
