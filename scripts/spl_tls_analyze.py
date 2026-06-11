"""TrustLint - TLS/domain risk analysis CLI with structured reports.

Pipeline: TLS probe -> Policy Adapter -> Decision Orchestrator -> report.

Usage:
    trustlint example.com
    trustlint example.com --profile balanced
    trustlint domains.txt --profile strict --json-out report.json
    trustlint domains.txt --profile conservative --markdown-out report.md

Exit codes:
    0 = all domains ALLOW
    1 = one or more REVIEW (no DENY)
    2 = one or more DENY
    3 = probe/runtime error
    4 = invalid arguments
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.run_local_tls_validation import probe_domain
from scripts.error_codes import (
    ErrorCode,
    format_error_for_log,
    format_error_message,
    get_error_code,
)
from tls_policy_adapter import classify_risk, RISK_MAP
from tls_policy_adapter.classifications import (
    DEPRECATED_TLS_VERSIONS,
    DEPRECATED_TLS_CLASSIFICATION,
    is_deprecated_tls_version,
)
from decision_orchestrator import decide, OperatingProfile

__version__ = "1.0.0"  # Must match pyproject.toml
TOOL_NAME = "trustlint"

# ── Structured Logging Setup ──────────────────────────────────────────────
logger = logging.getLogger("trustlint")
_DOMAIN_RE = re.compile(r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _write_atomic(filepath: str, content: str) -> None:
    """Write content to file atomically (write-to-temp-then-rename)."""
    import tempfile
    dir_name = os.path.dirname(filepath) or "."
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=dir_name, delete=False
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        os.replace(tmp_path, filepath)
    except Exception as e:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def _progress_indicator(current: int, total: int, domain: str, quiet: bool = False) -> None:
    """Print progress indicator for batch processing."""
    if quiet:
        return
    if total <= 1:
        return
    # Show progress for batches > 1 domain
    pct = (current / total) * 100
    print(f"[{current}/{total}] ({pct:.0f}%) Analyzing {domain}...", flush=True)


def setup_logging(verbose: bool = False) -> None:
    """Configure structured logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    formatter = logging.Formatter(
        "[%(name)s] %(levelname)s: %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)


def validate_domain_name(domain: str) -> Tuple[bool, str]:
    """Validate a domain name format.
    
    Returns (is_valid, error_message).
    """
    if not domain or len(domain) > 253:
        return False, "Domain is empty or exceeds 253 characters"
    if not _DOMAIN_RE.match(domain):
        return False, f"Invalid domain format: {domain!r}"
    return True, ""


# DEPRECATED_TLS_VERSIONS and DEPRECATED_TLS_CLASSIFICATION imported from
# tls_policy_adapter.classifications (single source of truth).

_RECOMMENDED_ACTIONS: Dict[str, str] = {
    "VALID_TLS": "No action required.",
    "REVOKED_CERT": "Certificate is revoked — do not trust this connection. Replace the certificate immediately.",
    "EXPIRED_CERT": "Renew or replace the certificate immediately.",
    "SELF_SIGNED_CERT": "Use a certificate issued by a trusted CA unless this is an internal-only system.",
    "WRONG_HOST_CERT": "Replace certificate with one matching the requested hostname.",
    "UNTRUSTED_CHAIN": "Fix the certificate chain — ensure all intermediate certificates are installed on the server.",
    "INCOMPLETE_CHAIN": "Install all missing intermediate certificates on the server.",
    "DNS_FAILURE": "Check DNS records and resolver availability for this domain.",
    "CONNECTION_ERROR": "Check network availability and firewall rules for the target server.",
    "TIMEOUT": "Check network availability, firewall, or server responsiveness. The connection timed out.",
    "TLS_HANDSHAKE_FAILURE": "Check TLS configuration and supported protocol/cipher settings on the server.",
    "DEPRECATED_TLS_VERSION": "Disable deprecated TLS protocols (TLS 1.0/1.1) and require TLS 1.2+ or TLS 1.3.",
    "WEAK_SIGNATURE_ALGORITHM": "Replace certificate signed with a weak algorithm (e.g., SHA-1) with one using a strong algorithm (SHA-256 or better).",
    "WEAK_CIPHER_SUITE": "Disable weak cipher suites (RC4, 3DES, NULL, EXPORT) on the server and configure strong ciphers only (TLS 1.2+ AEAD ciphers).",
    "STATIC_RSA_KEY_EXCHANGE": "Reconfigure server to use ephemeral Diffie-Hellman (DHE or ECDHE) key exchange for forward secrecy.",
    "TLS_COMPRESSION_ENABLED": "Disable TLS compression on the server to mitigate CRIME attack vulnerability.",
    "WILDCARD_CERTIFICATE": "Consider using a non-wildcard certificate to reduce the risk of subdomain impersonation.",
    "MISSING_OCSP_STAPLE": "Enable OCSP stapling on the server to improve revocation checking performance and privacy.",
    "OCSP_UNREACHABLE": "OCSP responder could not be reached — unable to confirm revocation status. Investigate network connectivity to the OCSP responder.",
    "UNKNOWN_SSL_ERROR": "Investigate SSL error details manually — the specific cause could not be determined by automated probing.",
}


def _get_recommended_action(classification: str, final_decision: str) -> str:
    if final_decision == "ALLOW":
        return _RECOMMENDED_ACTIONS.get("VALID_TLS", "No action required.")
    return _RECOMMENDED_ACTIONS.get(classification, "Review the domain manually — no specific automated recommendation available.")


def _get_probe_warnings(
    probe_result: Dict[str, Any],
    classification: str,
) -> List[str]:
    warnings: List[str] = []
    tls_info = probe_result.get("tls") or {}

    if classification == "DNS_FAILURE" and probe_result.get("dns_error"):
        warnings.append(f"DNS resolution failed: {probe_result['dns_error']}")
    if classification == "DEPRECATED_TLS_VERSION":
        ver = tls_info.get("tls_version", "unknown")
        warnings.append(f"Deprecated TLS version detected via secondary probe — server allows TLS 1.0 or 1.1 (primary negotiated {ver}).")
    if classification == "VALID_TLS":
        ver = tls_info.get("tls_version", "")
    if tls_info.get("cert_is_expired"):
        warnings.append("Certificate is expired according to the probe.")
    if tls_info.get("cert_chain_complete") is False:
        warnings.append("Certificate chain is incomplete.")
    if tls_info.get("deprecated_tls_check") == "unavailable_on_platform":
        warnings.append("Deprecated TLS check unavailable: TLSv1_1 not supported by local OpenSSL build.")
    return warnings


def resolve_classification(probe_result: Dict[str, Any]) -> str:
    """Resolve effective classification, detecting deprecated TLS versions."""
    classification = probe_result.get("classification", "UNKNOWN_SSL_ERROR")
    if classification == "VALID_TLS":
        tls_info = probe_result.get("tls") or {}
        tls_version = (tls_info.get("tls_version") or "").strip().lower()
        if tls_version in DEPRECATED_TLS_VERSIONS:
            return DEPRECATED_TLS_CLASSIFICATION
    return classification


def load_domains_from_file(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                domains.append(stripped)
    return domains


def resolve_targets(target: str) -> List[str]:
    if os.path.isfile(target):
        return load_domains_from_file(target)
    return [target.strip()]


def _build_evidence_artifact(domain: str, probe_result: Dict[str, Any]) -> Dict[str, Any]:
    tls_info = probe_result.get("tls") or {}
    classification = probe_result.get("classification", "")
    cert_not_expired = tls_info.get("cert_is_expired") is not True
    chain_complete = tls_info.get("cert_chain_complete") is not False
    if classification in ("TIMEOUT",):
        status = "timeout"
    elif classification in ("CONNECTION_ERROR", "DNS_FAILURE"):
        status = "error"
    elif classification in ("TLS_HANDSHAKE_FAILURE",):
        status = "partial"
    else:
        status = "ok"

    return {
        "evidence_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": f"tls_probe:{domain}",
        "type": "tls_certificate",
        "data": {
            "valid": cert_not_expired and chain_complete,
            "expiry_days": tls_info.get("cert_expiry_days", 0) or 0,
            "headers": {
                "hsts": None,
                "csp": None,
                "hsts_checked": False,
                "csp_checked": False,
            },
        },
        "transport_meta": {
            "status": status,
            "latency_ms": float(tls_info.get("handshake_time_ms", 0) or 0),
        },
        "tags": [],
        "version": "v7",
    }


def analyze_domain(
    domain: str,
    profile: OperatingProfile = "balanced",
    timeout: float = 10.0,
    ca_store: str = "platform",
    spl_pipeline: Any = None,
) -> Dict[str, Any]:
    """Run full analysis pipeline on a single domain.

    When *spl_pipeline* is provided (an ``EvidencePipeline`` instance), the
    TLS probe result is wrapped as an SPL v7 EvidenceArtifact and processed
    through the pipeline to produce a real *causal_probability* confidence.

    Returns a nested dict with tls_probe, policy_adapter, spl, final sub-objects.
    """
    raw = probe_domain(domain, ca_store=ca_store, timeout=timeout)

    classification = resolve_classification(raw)
    tls_info = raw.get("tls") or {}
    warnings = _get_probe_warnings(raw, classification)

    if tls_info.get("ocsp_error"):
        warnings.append(f"OCSP: {tls_info['ocsp_error']}")
    if tls_info.get("ocsp_status") == "revoked":
        warnings.append("Certificate is revoked according to OCSP check.")
    if tls_info.get("ocsp_status") == "unreachable":
        warnings.append("OCSP responder unreachable — revocation status not confirmed.")
    is_probe_limited = len(warnings) > 0

    try:
        evidence = classify_risk(classification)
    except KeyError:
        evidence = classify_risk("UNKNOWN_SSL_ERROR")

    spl_decision: Optional[bool] = None
    spl_confidence: float = 0.0
    spl_policy_label: Optional[str] = None
    weakness_flags: List[str] = []

    if spl_pipeline is not None:
        try:
            artifact = _build_evidence_artifact(domain, raw)
            spl_pipeline.ingest(artifact)
            result = spl_pipeline.process_one()
            if result is not None:
                spl_decision = bool(result["decision"])
                spl_confidence = float(result["causal_probability"])
                spl_policy_label = "ALLOW" if not spl_decision else "DENY"
                weakness_flags = []
            else:
                weakness_flags = ["pipeline_process_failed"]
        except Exception as e:
            logger.debug("SPL pipeline error for %s: %s", domain, e)
            weakness_flags = ["pipeline_error"]

    out = decide(
        adapter_risk_category=evidence.risk_category,
        adapter_severity=evidence.severity,
        adapter_action_hint=evidence.action_hint,
        spl_decision=spl_decision,
        spl_confidence=spl_confidence,
        classification=classification,
        spl_policy_label=spl_policy_label,
        profile=profile,
        probe_limited=is_probe_limited,
    )

    recommended_action = _get_recommended_action(classification, out["final_decision"])

    return {
        "domain": domain,
        "profile": profile,
        "ca_store": ca_store,
        "spl_active": spl_pipeline is not None,
        "probe_timestamp": raw.get("probe_timestamp", ""),
        "tls_probe": {
            "classification": classification,
            "raw_classification": raw.get("classification", ""),
            "tls_version": tls_info.get("tls_version"),
            "expiry_days": tls_info.get("cert_expiry_days"),
            "resolved_ip": raw.get("resolved_ip"),
            "cert_is_expired": tls_info.get("cert_is_expired"),
            "chain_complete": tls_info.get("cert_chain_complete"),
            "handshake_time_ms": tls_info.get("handshake_time_ms"),
            "ocsp_performed": tls_info.get("ocsp_performed", False),
            "ocsp_stapled": tls_info.get("ocsp_stapled", False),
            "ocsp_status": tls_info.get("ocsp_status"),
            "ocsp_error": tls_info.get("ocsp_error"),
            "ocsp_responder_url": tls_info.get("ocsp_responder_url"),
            "deprecated_tls_check": tls_info.get("deprecated_tls_check"),
            "deprecated_tls_detected": tls_info.get("deprecated_tls_detected", False),
            "warnings": warnings,
            "is_probe_limited": is_probe_limited,
        },
        "policy_adapter": {
            "risk_category": evidence.risk_category,
            "severity": evidence.severity,
            "failure_family": evidence.failure_family,
            "reason": evidence.policy_reason,
            "action_hint": evidence.action_hint,
        },
        "spl": {
            "decision": out.get("spl_decision"),
            "confidence": out.get("spl_confidence"),
            "confidence_source": out.get("confidence_source", "UNAVAILABLE"),
            "weakness_flags": weakness_flags,
        },
        "final": {
            "decision": out["final_decision"],
            "risk": out["final_risk"],
            "source": out["decision_source"],
            "fallback_used": out.get("fallback_used", False),
            "primary_reason": out["primary_reason"],
            "supporting_reasons": out["supporting_reasons"],
            "recommended_action": recommended_action,
            "limitations": warnings,
        },
        "ofe_observed": out.get("ofe_observed", False),
    }


# ── Public Python API ──────────────────────────────────────────────────────
# These functions provide a clean Python API for programmatic usage.
# They maintain backward compatibility with the CLI.


def analyze(
    domain: str,
    profile: OperatingProfile = "balanced",
    timeout: float = 10.0,
    ca_store: str = "platform",
) -> Dict[str, Any]:
    """Analyze a single domain and return structured results.

    This is the primary Python API for single-domain analysis.
    Results format is identical to CLI output.

    Args:
        domain: Domain name to analyze.
        profile: Decision operating profile ("balanced", "conservative", "strict").
        timeout: Probe timeout in seconds.
        ca_store: CA trust store to use ("platform" or "certifi").

    Returns:
        Dict with domain, profile, tls_probe, policy_adapter, spl, final sub-objects.

    Raises:
        ValueError: If domain is invalid.
        ConnectionError: If DNS resolution or connection fails.
    """
    valid, err_msg = validate_domain_name(domain)
    if not valid:
        raise ValueError(f"Invalid domain: {err_msg}")
    return analyze_domain(
        domain,
        profile=profile,
        timeout=timeout,
        ca_store=ca_store,
    )


def analyze_batch(
    domains: List[str],
    profile: OperatingProfile = "balanced",
    timeout: float = 10.0,
    ca_store: str = "platform",
    max_workers: int = 1,
) -> Dict[str, Any]:
    """Analyze multiple domains and return batch results.

    This is the primary Python API for batch analysis.
    Results format includes summary statistics.

    Args:
        domains: List of domain names to analyze.
        profile: Decision operating profile.
        timeout: Probe timeout per domain in seconds.
        ca_store: CA trust store to use.
        max_workers: Number of concurrent workers (currently only 1 supported).

    Returns:
        Dict with results, errors, summary sub-objects.
    """
    if not domains:
        return {
            "results": [],
            "errors": [],
            "summary": {
                "total_domains": 0,
                "success": 0,
                "failed": 0,
                "skipped": 0,
            },
        }

    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for domain in domains:
        try:
            r = analyze(
                domain,
                profile=profile,
                timeout=timeout,
                ca_store=ca_store,
            )
            results.append(r)
        except Exception as e:
            error_code = get_error_code(e)
            errors.append({
                "domain": domain,
                "error_code": error_code.value,
                "error_message": str(e),
                "error_description": error_code.name,
            })

    summary = {
        "total_domains": len(domains),
        "success": len(results),
        "failed": len(errors),
        "skipped": 0,
        "highest_risk": "NONE",
    }

    # Determine highest risk
    risk_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    highest_idx = 0
    for r in results:
        risk = r["final"]["risk"]
        if risk in risk_order:
            idx = risk_order.index(risk)
            if idx > highest_idx:
                highest_idx = idx
    summary["highest_risk"] = risk_order[highest_idx]

    return {
        "results": results,
        "errors": errors,
        "summary": summary,
    }


def get_version() -> str:
    """Return the current TrustLint version string."""
    return __version__


def get_classifications() -> List[str]:
    """Return list of all valid classification strings."""
    from tls_policy_adapter.classifications import ALL_CLASSIFICATIONS
    return list(ALL_CLASSIFICATIONS)


def compute_exit_code(results: List[Dict[str, Any]]) -> int:
    has_deny = any(r["final"]["decision"] == "DENY" for r in results)
    has_review = any(r["final"]["decision"] == "REVIEW" for r in results)
    if has_deny:
        return 2
    if has_review:
        return 1
    return 0


def compute_summary(results: List[Dict[str, Any]], errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Compute batch summary statistics.

    Args:
        results: List of domain analysis results.
        errors: Optional list of error messages from failed domains.
    """
    total = len(results)
    allow_count = sum(1 for r in results if r["final"]["decision"] == "ALLOW")
    review_count = sum(1 for r in results if r["final"]["decision"] == "REVIEW")
    deny_count = sum(1 for r in results if r["final"]["decision"] == "DENY")
    probe_limited = sum(1 for r in results if r["tls_probe"]["is_probe_limited"])
    fallback_count = sum(1 for r in results if r["final"].get("fallback_used", False))
    errors_count = sum(1 for r in results if r["tls_probe"]["classification"] == "UNKNOWN_SSL_ERROR")
    risk_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    highest_idx = 0
    for r in results:
        risk = r["final"]["risk"]
        if risk in risk_order:
            idx = risk_order.index(risk)
            if idx > highest_idx:
                highest_idx = idx
    highest_risk = risk_order[highest_idx]

    summary: Dict[str, Any] = {
        "total_domains": total,
        "allow": allow_count,
        "review": review_count,
        "deny": deny_count,
        "fallback": fallback_count,
        "probe_limited": probe_limited,
        "probe_errors": errors_count,
        "highest_risk": highest_risk,
    }

    # Include error details if provided
    if errors:
        summary["failed_domains"] = len(errors)
        summary["error_details"] = errors

    return summary


def _format_section_line(label: str, value: str, indent: int = 2) -> str:
    return f"{' ' * indent}{label}: {value}"


def _format_structured_domain(r: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    f = r["final"]
    tp = r["tls_probe"]
    pa = r["policy_adapter"]
    sp = r["spl"]

    spl_active = r.get("spl_active", False)
    lines.append("=" * 60)
    lines.append(f"  DOMAIN: {r['domain']}")
    lines.append(f"  Profile: {r['profile']}")
    lines.append(f"  SPL Core: {'Active' if spl_active else 'Inactive'}")
    lines.append(f"  Final Decision: {f['decision']}")
    lines.append(f"  Final Risk: {f['risk']}")
    lines.append(f"  Decision Source: {f['source']}")
    lines.append("=" * 60)
    lines.append("")

    lines.append("  [TLS Probe]")
    lines.append(_format_section_line("Classification", tp["classification"]))
    lines.append(_format_section_line("CA Store", r.get("ca_store", "platform")))
    if tp.get("tls_version"):
        lines.append(_format_section_line("TLS Version", tp["tls_version"]))
    if tp.get("expiry_days") is not None:
        lines.append(_format_section_line("Certificate Expiry Days", str(tp["expiry_days"])))
    if tp.get("resolved_ip"):
        lines.append(_format_section_line("Resolved IP", tp["resolved_ip"]))
    if tp.get("chain_complete") is not None:
        lines.append(_format_section_line("Chain Status", "Complete" if tp["chain_complete"] else "Incomplete"))
    lines.append(_format_section_line("OCSP Status", tp.get("ocsp_status") or "N/A"))
    if tp.get("ocsp_performed"):
        lines.append(_format_section_line("OCSP Stapled", "Yes" if tp.get("ocsp_stapled") else "No"))
    if tp.get("ocsp_error"):
        lines.append(_format_section_line("OCSP Error", tp["ocsp_error"]))
    dep_tls = tp.get("deprecated_tls_check", "N/A")
    lines.append(_format_section_line("Deprecated TLS Check", dep_tls))
    if tp.get("deprecated_tls_detected"):
        lines.append(_format_section_line("Deprecated TLS Detected", "Yes"))
    if tp["warnings"]:
        lines.append(_format_section_line("Probe Warnings", "; ".join(tp["warnings"])))
    lines.append("")

    lines.append("  [Policy Adapter]")
    lines.append(_format_section_line("Risk Category", pa["risk_category"]))
    lines.append(_format_section_line("Severity", pa["severity"]))
    lines.append(_format_section_line("Failure Family", pa["failure_family"]))
    lines.append(_format_section_line("Policy Reason", pa["reason"]))
    lines.append(_format_section_line("Action Hint", pa["action_hint"]))
    lines.append("")

    lines.append("  [SPL]")
    if sp["decision"] is None:
        lines.append(_format_section_line("Decision", "N/A (adapter-only mode)"))
    else:
        lines.append(_format_section_line("Decision", "DENY" if sp["decision"] else "ALLOW"))
        if sp["confidence"] is not None:
            lines.append(_format_section_line("Confidence", f"{sp['confidence']:.2f}"))
    lines.append(_format_section_line("Confidence Source", sp.get("confidence_source", "UNAVAILABLE")))
    if sp["weakness_flags"]:
        lines.append(_format_section_line("Weakness Flags", ", ".join(sp["weakness_flags"])))
    else:
        lines.append(_format_section_line("Weakness Flags", "None"))
    lines.append("")

    lines.append("  [Decision Reasoning]")
    if f.get("fallback_used"):
        lines.append(_format_section_line("Fallback Used", "Yes — SPL unavailable, adapter-based fallback policy applied"))
    lines.append(_format_section_line("Primary Reason", f["primary_reason"]))
    if f["supporting_reasons"]:
        lines.append("    Supporting Reasons:")
        for sr in f["supporting_reasons"]:
            lines.append(f"      - {sr}")
    lines.append("")

    lines.append("  [Recommended Action]")
    lines.append(f"    {f['recommended_action']}")
    lines.append("")

    if f["limitations"]:
        lines.append("  [Limitations]")
        for lim in f["limitations"]:
            lines.append(f"    - {lim}")
        lines.append("")

    return lines


def format_structured_text(result: Dict[str, Any]) -> str:
    return "\n".join(_format_structured_domain(result))


def format_batch_summary(results: List[Dict[str, Any]], errors: Optional[List[str]] = None) -> str:
    summary = compute_summary(results, errors)
    lines = [
        "",
        "=" * 60,
        "  BATCH SUMMARY",
        "=" * 60,
        f"  Total domains:      {summary['total_domains']}",
        f"  ALLOW:              {summary['allow']}",
        f"  REVIEW:             {summary['review']}",
        f"  DENY:               {summary['deny']}",
        f"  Fallback ALLOW:     {summary['fallback']}",
        f"  Highest risk:       {summary['highest_risk']}",
        f"  Probe-limited:      {summary['probe_limited']}",
        f"  Probe errors:       {summary['probe_errors']}",
        "",
    ]

    deny_domains = [r for r in results if r["final"]["decision"] == "DENY"]
    review_domains = [r for r in results if r["final"]["decision"] == "REVIEW"]
    limited_domains = [r for r in results if r["tls_probe"]["is_probe_limited"]]
    fallback_domains = [r for r in results if r["final"].get("fallback_used")]

    if deny_domains:
        lines.append("  Domains Requiring Immediate Action (DENY):")
        for r in deny_domains:
            lines.append(f"    - {r['domain']}: {r['final']['recommended_action']}")
        lines.append("")

    if review_domains:
        lines.append("  Domains Requiring Manual Review (REVIEW):")
        for r in review_domains:
            lines.append(f"    - {r['domain']}: {r['final']['risk']} risk — {r['tls_probe']['classification']}")
        lines.append("")

    if fallback_domains:
        lines.append("  Domains Allowed via Fallback (adapter-based policy, not SPL confidence):")
        for r in fallback_domains:
            lines.append(f"    - {r['domain']}")
        lines.append("")

    if limited_domains:
        lines.append("  Domains with Probe Limitations:")
        for r in limited_domains:
            warns = "; ".join(r["tls_probe"]["warnings"])
            lines.append(f"    - {r['domain']}: {warns}")
        lines.append("")

    if errors:
        lines.append("  Failed Domains:")
        for err in errors:
            lines.append(f"    {err}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_json_output(results: List[Dict[str, Any]], profile: str) -> str:
    spl_active = any(r.get("spl_active", False) for r in results)
    output = {
        "metadata": {
            "tool": "trustlint",
            "profile": profile,
            "spl_active": spl_active,
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "scope": "local-only",
            "production_ready": False,
        },
        "ca_store": results[0].get("ca_store", "platform") if results else "platform",
        "summary": compute_summary(results),
        "results": results,
    }
    return json.dumps(output, indent=2, default=str)


def format_markdown_output(results: List[Dict[str, Any]], profile: str) -> str:
    summary = compute_summary(results)
    lines: List[str] = [
        "# TLS Risk Analysis Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}Z",
        f"**Tool:** `TrustLint v{__version__}`",
        f"**Profile:** `{profile}`",
        f"**CA Store:** `{results[0].get('ca_store', 'platform') if results else 'platform'}`",
        f"**Domains analyzed:** {summary['total_domains']}",
        "",
        "> **Not production ready.** For local evidence gathering only.",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        "|---|---|",
        f"| Total domains | {summary['total_domains']} |",
        f"| ALLOW | {summary['allow']} |",
        f"| REVIEW | {summary['review']} |",
        f"| DENY | {summary['deny']} |",
        f"| Fallback ALLOW (adapter policy) | {summary['fallback']} |",
        f"| Highest risk level | {summary['highest_risk']} |",
        f"| Probe-limited | {summary['probe_limited']} |",
        f"| Probe errors | {summary['probe_errors']} |",
        "",
        "---",
        "",
    ]

    deny_domains = [r for r in results if r["final"]["decision"] == "DENY"]
    review_domains = [r for r in results if r["final"]["decision"] == "REVIEW"]
    limited_domains = [r for r in results if r["tls_probe"]["is_probe_limited"]]
    fallback_domains = [r for r in results if r["final"].get("fallback_used")]

    if deny_domains:
        lines.extend([
            "## Domains Requiring Immediate Action",
            "",
            "| Domain | Risk | Classification | Recommended Action |",
            "|---|---|---|---|",
        ])
        for r in deny_domains:
            lines.append(
                f"| {r['domain']} | {r['final']['risk']} | {r['tls_probe']['classification']} | "
                f"{r['final']['recommended_action']} |"
            )
            lines.append("")

    if review_domains:
        lines.extend([
            "## Domains Requiring Manual Review",
            "",
            "| Domain | Risk | Classification | Reason |",
            "|---|---|---|---|",
        ])
        for r in review_domains:
            lines.append(
                f"| {r['domain']} | {r['final']['risk']} | {r['tls_probe']['classification']} | "
                f"{r['final']['primary_reason']} |"
            )
        lines.append("")

    if fallback_domains:
        lines.extend([
            "## Domains Allowed via Fallback (Not SPL Confidence)",
            "",
            "The following domains were ALLOW'd by the adapter-based fallback policy because",
            "SPL confidence was unavailable and the probe results were clean (balanced profile).",
            "",
            "This is a deterministic adapter-policy decision, not an ML-based confidence score.",
            "",
            "| Domain |",
            "|---|",
        ])
        for r in fallback_domains:
            lines.append(f"| {r['domain']} |")
        lines.append("")

    if limited_domains:
        lines.extend([
            "## Probe Limitations",
            "",
            "| Domain | Limitation |",
            "|---|---|",
        ])
        for r in limited_domains:
            warns = "; ".join(r["tls_probe"]["warnings"])
            lines.append(f"| {r['domain']} | {warns} |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## Full Per-Domain Results",
        "",
        "| Domain | Classification | TLS | Adapter Risk | Severity | Decision | Recommended Action |",
        "|---|---|---|---|---|---|---|",
    ])
    for r in results:
        tp = r["tls_probe"]
        pa = r["policy_adapter"]
        f = r["final"]
        tls_ver = tp.get("tls_version") or "-"
        action = f["recommended_action"]
        lines.append(
            f"| {r['domain']} | {tp['classification']} | {tls_ver} | "
            f"{pa['risk_category']} | {pa['severity']} | **{f['decision']}** | {action} |"
        )
    lines.append("")

    spl_active = any(r.get("spl_active", False) for r in results)
    spl_note = (
        "SPL Core active — evidence pipeline is running (in-memory, untrained)."
        if spl_active else
        "Adapter-only mode — no SPL pipeline was run."
    )

    lines.extend([
        "---",
        "",
        "## Notes",
        "",
        "1. SPL Core is not modified.",
        "2. OFE remains HOLD_PENDING_REAL_DATA (observational only).",
        f"3. {spl_note}",
        "4. Deprecated TLS detection is not guaranteed (OpenSSL negotiates highest version).",
        "5. Probe limitations propagate through all decisions.",
        "6. Fallback ALLOW (balanced profile) is a deterministic adapter-based policy, not SPL confidence.",
        "7. No production readiness is claimed.",
        "",
        f"_Report generated by TrustLint v{__version__}._",
    ])

    return "\n".join(lines)


def _run_health_check() -> int:
    """Run a comprehensive self-diagnostic health check and exit.

    Checks:
    1. Python version >= 3.10
    2. SSL/OpenSSL availability
    3. DNS resolution
    4. Core package imports
    5. Config directory
    6. Dataset directory
    7. Canonical classifications module
    8. Classification count consistency
    9. Deprecated TLS version set consistency
    """
    import ssl
    import socket
    
    checks_passed = 0
    checks_failed = 0
    
    # 1. Python version check
    py_version = sys.version_info
    logger.info("Python %d.%d.%d", py_version.major, py_version.minor, py_version.micro)
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 10):
        logger.error("Python >= 3.10 required, found %d.%d", py_version.major, py_version.minor)
        checks_failed += 1
    else:
        checks_passed += 1
    
    # 2. SSL module check
    try:
        ssl_context = ssl.create_default_context()
        logger.info("SSL context: OK (OpenSSL %s)", ssl.OPENSSL_VERSION)
        checks_passed += 1
    except Exception as e:
        logger.error("SSL context creation failed: %s", e)
        checks_failed += 1
    
    # 3. DNS resolution check (localhost)
    try:
        socket.getaddrinfo("localhost", 443)
        logger.info("DNS resolution: OK")
        checks_passed += 1
    except Exception as e:
        logger.warning("DNS resolution failed for localhost: %s", e)
        checks_failed += 1
    
    # 4. Package imports check
    try:
        from tls_policy_adapter import classify_risk
        from decision_orchestrator import decide
        logger.info("Core imports: OK")
        checks_passed += 1
    except ImportError as e:
        logger.error("Core import failed: %s", e)
        checks_failed += 1
    
    # 5. Config path check
    config_path = os.path.join(PROJECT_ROOT, "configs")
    if os.path.isdir(config_path):
        logger.info("Config directory: OK (%s)", config_path)
        checks_passed += 1
    else:
        logger.warning("Config directory not found: %s", config_path)
        checks_failed += 1
    
    # 6. Dataset path check
    datasets_path = os.path.join(PROJECT_ROOT, "datasets")
    if os.path.isdir(datasets_path):
        logger.info("Datasets directory: OK (%s)", datasets_path)
        checks_passed += 1
    else:
        logger.warning("Datasets directory not found: %s", datasets_path)
        checks_failed += 1

    # 7. Canonical classifications module check
    try:
        from tls_policy_adapter.classifications import (
            ALL_CLASSIFICATIONS,
            DEPRECATED_TLS_VERSIONS,
            CLASSIFICATION_SEVERITY,
            CLASSIFICATION_RISK_CATEGORY,
        )
        logger.info("Classifications module: OK (%d classifications)", len(ALL_CLASSIFICATIONS))
        checks_passed += 1
    except ImportError as e:
        logger.error("Classifications module import failed: %s", e)
        checks_failed += 1

    # 8. Classification count consistency check
    try:
        from tls_policy_adapter.classifications import ALL_CLASSIFICATIONS
        from tls_policy_adapter.schema import RISK_MAP
        if len(ALL_CLASSIFICATIONS) == len(RISK_MAP):
            logger.info("Classification consistency: OK (%d == %d)",
                        len(ALL_CLASSIFICATIONS), len(RISK_MAP))
            checks_passed += 1
        else:
            logger.error("Classification count mismatch: classifications=%d, risk_map=%d",
                         len(ALL_CLASSIFICATIONS), len(RISK_MAP))
            checks_failed += 1
    except Exception as e:
        logger.error("Classification consistency check failed: %s", e)
        checks_failed += 1

    # 9. Deprecated TLS version set check
    try:
        from tls_policy_adapter.classifications import DEPRECATED_TLS_VERSIONS
        if len(DEPRECATED_TLS_VERSIONS) >= 3:
            logger.info("Deprecated TLS versions: OK (%d entries)", len(DEPRECATED_TLS_VERSIONS))
            checks_passed += 1
        else:
            logger.error("Deprecated TLS version set too small: %d entries",
                         len(DEPRECATED_TLS_VERSIONS))
            checks_failed += 1
    except Exception as e:
        logger.error("Deprecated TLS version check failed: %s", e)
        checks_failed += 1
    
    logger.info("Health check: %d passed, %d failed", checks_passed, checks_failed)
    return 0 if checks_failed == 0 else 1


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TrustLint - TLS/domain risk analysis CLI with structured reports",
        epilog="Exit codes: 0=ALLOW 1=REVIEW 2=DENY 3=error 4=invalid args",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Domain name or path to file with domains (one per line)",
    )
    parser.add_argument(
        "--profile",
        choices=["conservative", "balanced", "strict"],
        default="balanced",
        help="Decision operating profile (default: balanced)",
    )
    parser.add_argument(
        "--json-out",
        metavar="FILE",
        default=None,
        help="Write JSON output to file",
    )
    parser.add_argument(
        "--markdown-out",
        metavar="FILE",
        default=None,
        help="Write Markdown report to file",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Probe timeout per domain in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-domain console output; only show batch summary and errors",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed SPL reasoning in console output",
    )
    parser.add_argument(
        "--spl-unsafe",
        action="store_true",
        help="[UNSAFE/EXPERIMENTAL] Enable SPL Core observation mode - "
             "runs the SPL v7 evidence pipeline (in-memory, "
             "untrained) to produce ML-based confidence scores. "
             "SPL has 28 percent accuracy on real data. Use at your own risk.",
    )
    parser.add_argument(
        "--ca-store",
        choices=["platform", "certifi"],
        default="platform",
        help="CA trust store to use for TLS verification (default: platform). "
             "Use 'certifi' to load Mozilla's CA bundle (install certifi first).",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Run self-diagnostic health check and exit",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print tool version and exit",
    )
    parser.add_argument(
        "--list-classifications",
        action="store_true",
        help="Print all registered TLS classifications with their risk mapping and exit",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of concurrent workers for batch scans (default: 1). "
             "Higher values may improve throughput but risk rate limiting.",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Minimum delay between probes in seconds (default: 0). "
             "Use to avoid server rate limits during batch scans.",
    )
    return parser.parse_args(argv)


def _create_spl_pipeline() -> Any:
    """Build an SPL v7 EvidencePipeline with the project's feature DSL."""
    from spl_v7.dsl import FeatureDSLProgram
    from spl_v7.kafka_pipeline import EvidencePipeline

    dsl_path = os.path.join(PROJECT_ROOT, "configs", "features.dsl")
    if not os.path.isfile(dsl_path):
        raise FileNotFoundError(f"Feature DSL not found at {dsl_path}")

    with open(dsl_path, "r", encoding="utf-8") as f:
        dsl_text = f.read()

    program = FeatureDSLProgram.from_text(dsl_text)
    return EvidencePipeline(feature_program=program)


def _print_version() -> int:
    """Print the tool version and exit with code 0."""
    print(f"{TOOL_NAME} {__version__}")
    return 0


def _print_classifications() -> int:
    """Print all registered TLS classifications with their risk mapping."""
    print(f"{TOOL_NAME} {__version__}")
    print(f"Registered TLS classifications: {len(RISK_MAP)}")
    print()
    header = f"{'CLASSIFICATION':<32} {'SEVERITY':<10} {'RISK CATEGORY':<22} {'ACTION HINT'}"
    print(header)
    print("-" * len(header))
    for name in sorted(RISK_MAP.keys()):
        ev = RISK_MAP[name]
        print(f"{name:<32} {ev.severity:<10} {ev.risk_category:<22} {ev.action_hint}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(verbose=args.verbose)

    # ── Utility modes (must run before logging setup is too aggressive) ──
    if args.version:
        return _print_version()
    if args.list_classifications:
        return _print_classifications()

    # ── Health check mode ────────────────────────────────────────────────
    if args.health:
        return _run_health_check()

    # ── Input validation ─────────────────────────────────────────────────
    if args.target is None:
        logger.error("No target specified. Use --health for diagnostics or provide a domain/file.")
        return 4

    if args.timeout <= 0:
        logger.error("--timeout must be positive")
        return 4

    profile: OperatingProfile = args.profile
    ca_store: str = args.ca_store

    # ── CA store validation ──────────────────────────────────────────────
    if ca_store == "certifi":
        try:
            import certifi
            certifi.where()
        except ImportError:
            logger.error("--ca-store certifi requires certifi package. "
                         "Install with: pip install trustlint[ca-store]")
            return 4

    # ── SPL pipeline setup ───────────────────────────────────────────────
    spl_pipeline = None
    if args.spl_unsafe:
        logger.warning("SPL is unvalidated and experimental. "
                       "Accuracy on real data: 28%%. Use at your own risk.")
        try:
            spl_pipeline = _create_spl_pipeline()
        except Exception as e:
            logger.error("Failed to initialize SPL pipeline: %s", e)
            return 4

    # ── Resolve targets ──────────────────────────────────────────────────
    try:
        domains = resolve_targets(args.target)
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        return 4
    except Exception as e:
        logger.error("Cannot read target: %s", e)
        return 4

    if not domains:
        logger.error("No domains to analyze")
        return 4

    # ── Domain name validation ───────────────────────────────────────────
    validated_domains: List[str] = []
    for domain in domains:
        valid, err_msg = validate_domain_name(domain)
        if not valid:
            logger.warning("Skipping invalid domain: %s", err_msg)
        else:
            validated_domains.append(domain)
    domains = validated_domains

    if not domains:
        logger.error("No valid domains to analyze")
        return 4

    # ── Run analysis ─────────────────────────────────────────────────────
    import time as _time_mod
    spl_label = " with SPL Core active" if spl_pipeline else ""
    total_domains = len(domains)
    rate_limit = getattr(args, 'rate_limit', 0.0) or 0.0
    logger.info("Analyzing %d domain(s) with profile '%s'%s (timeout=%ss, rate-limit=%.1fs)",
                total_domains, profile, spl_label, args.timeout, rate_limit)

    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    skipped: int = 0
    _probe_start = _time_mod.monotonic()

    for idx, domain in enumerate(domains, 1):
        _progress_indicator(idx, total_domains, domain, quiet=args.quiet)
        try:
            r = analyze_domain(
                domain, profile=profile, timeout=args.timeout,
                ca_store=ca_store, spl_pipeline=spl_pipeline,
            )
            results.append(r)
            if not args.quiet:
                print(format_structured_text(r))
        except Exception as e:
            error_code = get_error_code(e)
            error_msg = format_error_message(domain, error_code, str(e))
            errors.append(error_msg)
            logger.error("Domain '%s' failed: %s", domain, e)

        # Rate limiting between probes
        if rate_limit > 0 and idx < total_domains:
            elapsed = _time_mod.monotonic() - _probe_start
            if elapsed < rate_limit:
                _time_mod.sleep(rate_limit - elapsed)
            _probe_start = _time_mod.monotonic()

    if errors:
        logger.warning("%d domain(s) had errors", len(errors))
        if not results:
            return 3

    if not args.quiet and len(results) > 1:
        print(format_batch_summary(results, errors))

    # ── Write outputs (atomic writes) ────────────────────────────────────
    if args.json_out:
        json_str = format_json_output(results, profile)
        _write_atomic(args.json_out, json_str)
        logger.info("JSON written to %s", args.json_out)

    if args.markdown_out:
        md_str = format_markdown_output(results, profile)
        _write_atomic(args.markdown_out, md_str)
        logger.info("Markdown written to %s", args.markdown_out)

    # ── Final summary with metrics ───────────────────────────────────────
    if not args.quiet:
        skipped = total_domains - len(results) - len(errors)
        summary_parts = [
            f"\n[Analysis Complete] ",
            f"{len(results)} succeeded, ",
            f"{len(errors)} failed, ",
            f"{skipped} skipped",
        ]
        if errors:
            summary_parts.append(f" ({len(errors)} error(s))")
        print("".join(summary_parts))

    return compute_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
