"""Frontier validation: run 5 exploration sessions and save results."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from spl_v7.causal import OnlineCausalGraphLearner
from spl_v7.dsl import compile_feature_dsl
from spl_v7.frontier import FrontierExplorer
from spl_v7.kafka_pipeline import EvidencePipeline, MemoryKafkaAdapter, PipelineConfig
from spl_v7.schema import EvidenceArtifact, EvidenceTransportMeta

from frontier.session import ExplorationSession, ExplorationReport, compute_difficulty


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports" / "frontier_validation"
DSL_PATH = ROOT / "configs" / "features.dsl"

REPORTS.mkdir(parents=True, exist_ok=True)

DSL_TEXT = DSL_PATH.read_text(encoding="utf-8")


def build_pipeline() -> EvidencePipeline:
    program = compile_feature_dsl(DSL_TEXT)
    learner = OnlineCausalGraphLearner(
        independence_min_support=5.0,
        redundancy_threshold=0.85,
        source_min_support=2.0,
        min_corroborating_sources=2,
    )
    pipeline = EvidencePipeline(
        feature_program=program,
        causal_graph=learner,
        config=PipelineConfig(backend="memory", emit_graph_snapshot=False),
        adapter=MemoryKafkaAdapter(),
    )
    return pipeline, learner


def train_pipeline(pipeline: EvidencePipeline, learner: OnlineCausalGraphLearner) -> None:
    for source in ["collector-a", "collector-b", "collector-c"]:
        for i in range(48):
            risky = i % 2 == 1
            expiry_days = 5 if risky else 90
            hsts = not risky
            csp = not risky or i % 7 == 0
            status = "timeout" if risky and i % 11 == 0 else "ok"
            latency = 1800 if risky else 90
            label_weight = 2.0 if source in {"collector-a", "collector-b"} else 1.0
            artifact = EvidenceArtifact(
                source=source,
                type="tls",
                data={
                    "valid": True,
                    "expiry_days": expiry_days,
                    "headers": {"hsts": hsts, "csp": csp},
                    "label": risky,
                    "label_weight": label_weight,
                },
                transport_meta=EvidenceTransportMeta(
                    status=status, latency_ms=latency, bytes_received=512,
                ),
            )
            from spl_v7.verification import compute_artifact_hash
            artifact.integrity.hash = compute_artifact_hash(artifact)
            pipeline.ingest(artifact.to_dict())

    while pipeline.process_one(timeout=0.01) is not None:
        pass


def run_session(
    name: str,
    seed_data: dict,
    source: str = "collector-a",
    steps: int = 5,
) -> dict:
    print(f"\n  === Session: {name} ===")

    pipeline, learner = build_pipeline()
    train_pipeline(pipeline, learner)

    explorer = FrontierExplorer(pipeline)

    seed = EvidenceArtifact(
        source=source,
        type="tls",
        data=dict(seed_data),
        transport_meta=EvidenceTransportMeta(status="ok", latency_ms=90, bytes_received=512),
    )
    from spl_v7.verification import compute_artifact_hash
    seed.integrity.hash = compute_artifact_hash(seed)

    frontier_info = explorer.analyze_frontier()

    session = ExplorationSession(seed)
    curriculum = explorer.generate_curriculum(seed, steps=steps)

    print(f"  Seed: {seed.evidence_id[:8]}...")
    print(f"  Frontier pressure: {frontier_info['frontier_pressure']:.3f}")
    print(f"  Focus features: {[f['feature'] for f in frontier_info['weakest_features']]}")
    print(f"  Challenges: {len(curriculum)}")

    for i, challenge in enumerate(curriculum):
        pipeline.ingest(challenge.artifact.to_dict())
        result = pipeline.process_one(timeout=0.05)

        # Overwrite difficulty with computed score
        challenge.difficulty = compute_difficulty(
            challenge.mutation_summary,
            challenge.step,
            steps,
            frontier_info["frontier_pressure"],
        )
        session.add_challenge(challenge, result)

        prob = result.get("causal_probability", 0.0) if result else 0.0
        dec = result.get("decision", False) if result else False
        print(f"    Step {challenge.step}: diff={challenge.difficulty:.3f} conf={prob:.3f} decision={dec}")

    session_path = REPORTS / f"{name}_session.json"
    session.save(str(session_path))
    print(f"  Session saved: {session_path}")

    report = ExplorationReport(session).save_json(
        str(REPORTS / f"{name}_report.json"),
        frontier_info,
    )
    print(f"  Report saved: {REPORTS / name}_report.json")

    collapse = report.get("collapse_detection")
    if collapse:
        print(f"  !! Collapse detected: {collapse['drop_magnitude']:.3f} drop "
              f"(steps {collapse['collapse_start_step']}->{collapse['collapse_end_step']})")
    else:
        print(f"  OK No collapse detected")

    return report


def main() -> None:
    print("=" * 56)
    print("  SPL v7.1 -- Frontier Validation")
    print("  5 Exploration Sessions")
    print("=" * 56)

    # Session 1: Standard TLS -- typical certificate risk
    r1 = run_session("tls_standard", {
        "valid": True,
        "expiry_days": 7,
        "headers": {"hsts": False, "csp": True},
        "label": True,
        "label_weight": 1.0,
    })

    # Session 2: Expired cert -- high urgency
    r2 = run_session("tls_expired", {
        "valid": False,
        "expiry_days": -3,
        "headers": {"hsts": False, "csp": False},
        "label": True,
        "label_weight": 2.0,
    })

    # Session 3: Clean cert -- low risk
    r3 = run_session("tls_clean", {
        "valid": True,
        "expiry_days": 180,
        "headers": {"hsts": True, "csp": True},
        "label": False,
        "label_weight": 1.0,
    })

    # Session 4: Mixed signals -- contradictory headers
    r4 = run_session("tls_mixed", {
        "valid": True,
        "expiry_days": 14,
        "headers": {"hsts": True, "csp": False},
        "label": True,
        "label_weight": 1.0,
    })

    # Session 5: Timeout-heavy -- degraded transport
    r5 = run_session("tls_timeout_risk", {
        "valid": True,
        "expiry_days": 2,
        "headers": {"hsts": False, "csp": False},
        "label": True,
        "label_weight": 1.0,
    }, source="collector-c")

    # Summary
    print("\n" + "=" * 56)
    print("  VALIDATION SUMMARY")
    print("=" * 56)
    reports = [r1, r2, r3, r4, r5]
    names = ["tls_standard", "tls_expired", "tls_clean", "tls_mixed", "tls_timeout_risk"]

    for name, report in zip(names, reports):
        progs = report.get("difficulty_progression", [])
        confs = report.get("confidence_progression", [])
        collapse = report.get("collapse_detection")
        coll_tag = f"!! COLLAPSE ({collapse['drop_magnitude']:.2f})" if collapse else "OK stable"
        print(f"  {name:20s}  diff: {progs[0]:.2f}->{progs[-1]:.2f}  "
              f"conf: {confs[0]:.3f}->{confs[-1]:.3f}  {coll_tag}")

    summary = {
        "sessions": names,
        "total_sessions": len(reports),
        "collapse_detected": sum(1 for r in reports if r.get("collapse_detection")),
    }
    summary_path = REPORTS / "validation_summary.json"
    with open(str(summary_path), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Summary saved: {summary_path}")
    print("  Done.")


if __name__ == "__main__":
    main()



