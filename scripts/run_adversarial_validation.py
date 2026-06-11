import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from spl_v7.causal import OnlineCausalGraphLearner
from spl_v7.kafka_pipeline import EvidencePipeline, MemoryKafkaAdapter, PipelineConfig
from experiments.dsl_helpers import build_experiment_dsl

from scripts.run_local_tls_validation import probe_domain
from scripts.run_real_tls_spl_decision_validation import _resolve_classification, _probe_result_to_evidence, CLASSIFICATION_TO_POLICY

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

def load_domains(path: str) -> List[str]:
    domains = []
    if not os.path.exists(path):
        return domains
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains

def main():
    padding_file = "datasets/padding_domains.txt"
    adversarial_file = "datasets/adversarial_tls_domains.txt"
    report_file = "reports/adversarial_validation_report.md"

    padding_domains = load_domains(padding_file)
    adv_domains = load_domains(adversarial_file)

    pipeline = _make_pipeline()

    # 1. Padding / Initialization
    print(f"Initializing SPL graph with {len(padding_domains)} padding domains...")
    for dom in padding_domains:
        try:
            res = probe_domain(dom)
            classification = _resolve_classification(res)
            artifact = _probe_result_to_evidence(res, classification, include_label=False)
            pipeline.ingest(artifact.to_dict())
            pipeline.process_one(timeout=0.1)
        except Exception as e:
            print(f"  Error on {dom}: {e}")
        time.sleep(0.1) # Rate limit

    # 2. Adversarial Probing
    print(f"Probing {len(adv_domains)} adversarial edge cases...")
    
    results = []
    
    for dom in adv_domains:
        try:
            res = probe_domain(dom)
            classification = _resolve_classification(res)
            
            # Baseline deterministic rule: 
            baseline_is_risk = (classification != "VALID_TLS")
            baseline_category = CLASSIFICATION_TO_POLICY.get(classification, "UNKNOWN")
            
            # SPL evaluation (untrained)
            artifact = _probe_result_to_evidence(res, classification, include_label=False)
            pipeline.ingest(artifact.to_dict())
            spl_res = pipeline.process_one(timeout=0.1)
            
            spl_decision = spl_res.get("decision", False) if spl_res else False
            spl_conf = spl_res.get("causal_probability", 0.0) if spl_res else 0.0
            spl_features = spl_res.get("features", {}) if spl_res else {}
            
            results.append({
                "domain": dom,
                "classification": classification,
                "baseline_is_risk": baseline_is_risk,
                "baseline_category": baseline_category,
                "spl_is_risk": spl_decision,
                "spl_confidence": spl_conf,
                "spl_features": spl_features,
                "error_str": (res.get("tls") or {}).get("error", res.get("dns_error", ""))
            })
            
        except Exception as e:
            print(f"  Error on {dom}: {e}")
        time.sleep(0.5)

    # 3. Analyze Disagreements & Generate Report
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    lines = [
        "# Adversarial Validation Study",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        "",
        "## Summary",
        f"- **Padding domains used**: {len(padding_domains)} (for stabilizing graph)",
        f"- **Adversarial domains tested**: {len(results)}",
        "",
        "## Disagreements / Value Add Analysis",
        ""
    ]
    
    disagreements = []
    agreements = []
    
    for r in results:
        if r["baseline_is_risk"] != r["spl_is_risk"]:
            disagreements.append(r)
        else:
            agreements.append(r)
            
    if not disagreements:
        lines.append("SPL agreed with the baseline on EVERY adversarial edge case.")
        lines.append("SPL did not contribute any unique structural signals that overturned the baseline's deterministic logic.")
    else:
        lines.append(f"Found {len(disagreements)} cases where SPL disagreed with the Baseline.")
        lines.append("")
        for d in disagreements:
            lines.append(f"### Domain: `{d['domain']}`")
            lines.append(f"- **Classification**: {d['classification']}")
            lines.append(f"- **Error details**: {d['error_str']}")
            lines.append(f"- **Baseline Decision**: {'RISK' if d['baseline_is_risk'] else 'ACCEPTABLE'} ({d['baseline_category']})")
            lines.append(f"- **SPL Decision**: {'RISK' if d['spl_is_risk'] else 'ACCEPTABLE'} (Confidence: {d['spl_confidence']:.2f})")
            lines.append(f"- **SPL Extracted Features**: `{json.dumps(d['spl_features'])}`")
            lines.append("")
            lines.append("**Analysis**: ")
            lines.append(f"Baseline chose {'RISK' if d['baseline_is_risk'] else 'ACCEPTABLE'} because of rule: classification is {d['classification']}.")
            # Just generate placeholders for the manual analysis portion
            lines.append("SPL relied on: [See features above]")
            lines.append("Did SPL discover genuinely new information? [Manual Review Required]")
            lines.append("")
            
    lines.append("## Agreed Cases")
    lines.append("In these cases, SPL and the Baseline reached the exact same conclusion.")
    lines.append("| Domain | Classification | Baseline/SPL Decision | SPL Confidence |")
    lines.append("|---|---|---|---|")
    for a in agreements:
        decision_str = "RISK" if a["baseline_is_risk"] else "ACCEPTABLE"
        lines.append(f"| {a['domain']} | {a['classification']} | {decision_str} | {a['spl_confidence']:.2f} |")

    lines.append("")
    lines.append("## Final Conclusion")
    lines.append("*(To be filled after manual review of disagreements)*")
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        
    print(f"Report written to {report_file}")
    print(f"Found {len(disagreements)} disagreements.")

if __name__ == "__main__":
    main()
