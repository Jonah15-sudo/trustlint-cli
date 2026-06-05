"""TrustLint CLI — TLS risk analysis with structured reports.

Pipeline: TLS probe -> Policy Adapter -> Decision Orchestrator -> report.

Usage:
    spl-tls-analyze example.com
    spl-tls-analyze example.com --profile balanced
    spl-tls-analyze domains.txt --profile strict --json-out report.json
    spl-tls-analyze domains.txt --profile conservative --markdown-out report.md

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
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.run_local_tls_validation import probe_domain
from tls_policy_adapter import classify_risk
from decision_orchestrator import decide, OperatingProfile

DEPRECATED_TLS_VERSIONS = {"tlsv1", "tlsv1.0", "tlsv1.1"}
DEPRECATED_TLS_CLASSIFICATION = "DEPRECATED_TLS_VERSION"

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
                "hsts": False,
                "csp": False,
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
) -> Dict[str, Any]:
    """Run full analysis pipeline on a single domain.

    Returns a nested dict with tls_probe, policy_adapter, final sub-objects.
    """
    import scripts.run_local_tls_validation as probe_mod
    original_timeout = probe_mod.PROBE_TIMEOUT
    probe_mod.PROBE_TIMEOUT = timeout

    try:
        raw = probe_domain(domain, ca_store=ca_store)
    finally:
        probe_mod.PROBE_TIMEOUT = original_timeout

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

    out = decide(
        adapter_risk_category=evidence.risk_category,
        adapter_severity=evidence.severity,
        adapter_action_hint=evidence.action_hint,
        classification=classification,
        profile=profile,
        probe_limited=is_probe_limited,
    )

    recommended_action = _get_recommended_action(classification, out["final_decision"])

    return {
        "domain": domain,
        "profile": profile,
        "ca_store": ca_store,
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
    }


def compute_exit_code(results: List[Dict[str, Any]]) -> int:
    has_deny = any(r["final"]["decision"] == "DENY" for r in results)
    has_review = any(r["final"]["decision"] == "REVIEW" for r in results)
    if has_deny:
        return 2
    if has_review:
        return 1
    return 0


def compute_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(results)
    allow_count = sum(1 for r in results if r["final"]["decision"] == "ALLOW")
    review_count = sum(1 for r in results if r["final"]["decision"] == "REVIEW")
    deny_count = sum(1 for r in results if r["final"]["decision"] == "DENY")
    probe_limited = sum(1 for r in results if r["tls_probe"]["is_probe_limited"])
    fallback_count = sum(1 for r in results if r["final"].get("fallback_used", False))
    errors = sum(1 for r in results if r["tls_probe"]["classification"] == "UNKNOWN_SSL_ERROR")
    risk_order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    highest_idx = 0
    for r in results:
        risk = r["final"]["risk"]
        if risk in risk_order:
            idx = risk_order.index(risk)
            if idx > highest_idx:
                highest_idx = idx
    highest_risk = risk_order[highest_idx]

    return {
        "total_domains": total,
        "allow": allow_count,
        "review": review_count,
        "deny": deny_count,
        "fallback": fallback_count,
        "probe_limited": probe_limited,
        "probe_errors": errors,
        "highest_risk": highest_risk,
    }


def _format_section_line(label: str, value: str, indent: int = 2) -> str:
    return f"{' ' * indent}{label}: {value}"


def _format_structured_domain(r: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    f = r["final"]
    tp = r["tls_probe"]
    pa = r["policy_adapter"]

    lines.append("=" * 60)
    lines.append(f"  DOMAIN: {r['domain']}")
    lines.append(f"  Profile: {r['profile']}")
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

    lines.append("  [Decision Reasoning]")
    if f.get("fallback_used"):
        lines.append(_format_section_line("Fallback Used", "Yes — adapter-based fallback policy applied"))
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


def format_batch_summary(results: List[Dict[str, Any]]) -> str:
    summary = compute_summary(results)
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
        lines.append("  Domains Allowed via Fallback (adapter-based policy):")
        for r in fallback_domains:
            lines.append(f"    - {r['domain']}")
        lines.append("")

    if limited_domains:
        lines.append("  Domains with Probe Limitations:")
        for r in limited_domains:
            warns = "; ".join(r["tls_probe"]["warnings"])
            lines.append(f"    - {r['domain']}: {warns}")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_json_output(results: List[Dict[str, Any]], profile: str) -> str:
    output = {
        "metadata": {
            "tool": "spl_tls_analyze",
            "profile": profile,
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
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
        f"**Tool:** TrustLint CLI",
        f"**Profile:** `{profile}`",
        f"**CA Store:** `{results[0].get('ca_store', 'platform') if results else 'platform'}`",
        f"**Domains analyzed:** {summary['total_domains']}",
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
            "## Domains Allowed via Fallback (Adapter Policy)",
            "",
            "The following domains were ALLOW'd by the adapter-based fallback policy because",
            "the probe results were clean and the profile is balanced.",
            "",
            "This is a deterministic adapter-policy decision.",
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

    lines.extend([
        "---",
        "",
        "## Notes",
        "",
        "1. Deprecated TLS detection is not guaranteed (OpenSSL negotiates highest version).",
        "2. Probe limitations propagate through all decisions.",
        "3. Fallback ALLOW (balanced profile) is a deterministic adapter-based policy.",
        "",
        "_Report generated by TrustLint CLI._",
    ])

    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="spl_tls_analyze — Local TLS/domain risk analysis CLI with structured reports",
        epilog="Exit codes: 0=ALLOW 1=REVIEW 2=DENY 3=error 4=invalid args",
    )
    parser.add_argument(
        "target",
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
        help="Show detailed reasoning in console output",
    )
    parser.add_argument(
        "--ca-store",
        choices=["platform", "certifi"],
        default="platform",
        help="CA trust store to use for TLS verification (default: platform). "
             "Use 'certifi' to load Mozilla's CA bundle (install certifi first).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.timeout <= 0:
        print("Error: --timeout must be positive", file=sys.stderr)
        return 4

    profile: OperatingProfile = args.profile
    ca_store: str = args.ca_store

    if ca_store == "certifi":
        try:
            import certifi
            certifi.where()
        except ImportError:
            print("Error: --ca-store certifi requires certifi package. "
                  "Install with: pip install spl-tls-analyze[ca-store]", file=sys.stderr)
            return 4

    try:
        domains = resolve_targets(args.target)
    except FileNotFoundError as e:
        print(f"Error: file not found — {e}", file=sys.stderr)
        return 4
    except Exception as e:
        print(f"Error: cannot read target — {e}", file=sys.stderr)
        return 4

    if not domains:
        print("Error: no domains to analyze", file=sys.stderr)
        return 4

    if not args.quiet:
        print(f"[spl_tls_analyze] Analyzing {len(domains)} domain(s) with profile '{profile}'"
              f" (timeout={args.timeout}s)", file=sys.stderr)

    results: List[Dict[str, Any]] = []
    errors: List[str] = []

    for domain in domains:
        try:
            r = analyze_domain(
                domain, profile=profile, timeout=args.timeout,
                ca_store=ca_store,
            )
            results.append(r)
            if not args.quiet:
                print(format_structured_text(r), file=sys.stderr if args.quiet else sys.stdout)
        except Exception as e:
            errors.append(f"  {domain}: ERROR — {e}")
            print(f"  {domain}: ERROR — {e}", file=sys.stderr)

    if errors:
        print(f"[spl_tls_analyze] {len(errors)} domain(s) had errors", file=sys.stderr)
        if not results:
            return 3

    if not args.quiet and len(results) > 1:
        print(format_batch_summary(results), file=sys.stderr if args.quiet else sys.stdout)

    if args.json_out:
        json_str = format_json_output(results, profile)
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(json_str)
        print(f"[spl_tls_analyze] JSON written to {args.json_out}", file=sys.stderr)

    if args.markdown_out:
        md_str = format_markdown_output(results, profile)
        with open(args.markdown_out, "w", encoding="utf-8") as f:
            f.write(md_str)
        print(f"[spl_tls_analyze] Markdown written to {args.markdown_out}", file=sys.stderr)

    return compute_exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
