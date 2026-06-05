"""Schema for the Decision Orchestration Policy.

Defines input/output types for the orchestrator that combines adapter
risk evidence with auxiliary signals into a transparent final decision.
"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional, TypedDict

FinalDecision = Literal["ALLOW", "REVIEW", "DENY"]
FinalRisk = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
DecisionSource = Literal["ADAPTER", "ADAPTER_FALLBACK"]


class OrchestratorInput(TypedDict, total=False):
    """All input fields consumed by the orchestrator.

    Adapter evidence fields must be provided. Weakness and auxiliary signals are optional.
    """

    domain: str
    classification: str
    adapter_risk_category: str
    adapter_severity: str
    adapter_action_hint: str
    auxiliary_decision: Optional[bool]
    auxiliary_confidence: float
    auxiliary_policy_label: Optional[str]
    weakness_flags: Optional[List[str]]
    auxiliary_signals: Optional[Dict[str, float]]
    expected_policy: Optional[str]
    probe_limited: bool


class OrchestratorOutput(TypedDict, total=False):
    """The orchestrator's final structured output.

    All fields are populated after orchestration.
    """

    domain: str
    classification: str
    expected_policy: Optional[str]
    final_decision: str
    final_risk: str
    primary_reason: str
    supporting_reasons: List[str]
    decision_source: str
    fallback_used: bool
    confidence_source: str
    is_exact_match: bool
    is_safe_mismatch: bool
    is_unsafe_mismatch: bool
    is_over_blocking: bool
    auxiliary_decision: Optional[bool]
    auxiliary_confidence: float
    auxiliary_policy_label: Optional[str]
    adapter_risk_category: str
    adapter_severity: str
    adapter_action_hint: str
    auxiliary_observed: bool


SEVERITY_ORDER: List[str] = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_RANK: Dict[str, int] = {
    sev: idx for idx, sev in enumerate(SEVERITY_ORDER)
}

OperatingProfile = Literal["conservative", "balanced", "strict"]
