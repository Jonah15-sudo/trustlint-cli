from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time as _time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from scripts.ocsp_checker import check_ocsp

PROBE_TIMEOUT = 10.0
RATE_LIMIT_SECONDS = 1.0
DEFAULT_PORT = 443
REPORT_DIR = "reports/local_real_validation"

CLASSIFICATION = {
    "VALID_TLS": "valid",
    "REVOKED_CERT": "cert_revoked",
    "DNS_FAILURE": "dns_failure",
    "TLS_HANDSHAKE_FAILURE": "tls_handshake_failure",
    "EXPIRED_CERT": "cert_expired",
    "SELF_SIGNED_CERT": "self_signed_cert",
    "WRONG_HOST_CERT": "wrong_host_cert",
    "UNTRUSTED_CHAIN": "untrusted_chain",
    "INCOMPLETE_CHAIN": "incomplete_chain",
    "WEAK_SIGNATURE_ALGORITHM": "weak_signature",
    "WEAK_CIPHER_SUITE": "weak_cipher",
    "STATIC_RSA_KEY_EXCHANGE": "static_rsa",
    "TLS_COMPRESSION_ENABLED": "compression_enabled",
    "WILDCARD_CERTIFICATE": "wildcard_cert",
    "MISSING_OCSP_STAPLE": "missing_ocsp_staple",
    "CONNECTION_ERROR": "connection_error",
    "TIMEOUT": "timeout",
    "OCSP_UNREACHABLE": "ocsp_unreachable",
    "UNKNOWN_SSL_ERROR": "unknown_ssl_error",
}

CLASSIFICATION_ORDER = [
    "VALID_TLS", "REVOKED_CERT", "DNS_FAILURE", "TIMEOUT",
    "CONNECTION_ERROR", "TLS_HANDSHAKE_FAILURE", "EXPIRED_CERT",
    "SELF_SIGNED_CERT", "WRONG_HOST_CERT", "UNTRUSTED_CHAIN",
    "INCOMPLETE_CHAIN", "WEAK_SIGNATURE_ALGORITHM",
    "WEAK_CIPHER_SUITE", "STATIC_RSA_KEY_EXCHANGE",
    "TLS_COMPRESSION_ENABLED", "WILDCARD_CERTIFICATE", "MISSING_OCSP_STAPLE",
    "OCSP_UNREACHABLE", "UNKNOWN_SSL_ERROR",
]

EXPECTED_LABELS_FILE = "datasets/real_tls_mixed_expected.json"


def _resolve_domain(domain: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        addrs = socket.getaddrinfo(domain, DEFAULT_PORT, socket.AF_INET, socket.SOCK_STREAM)
        if addrs:
            return addrs[0][4][0], None
        return None, "no address records"
    except socket.gaierror as e:
        return None, f"DNS resolution failed: {e}"
    except OSError as e:
        return None, f"socket error: {e}"


def _classify_ssl_error(err_msg: str, chain_length: Optional[int] = None) -> str:
    msg_lower = err_msg.lower()
    if "expired" in msg_lower:
        return "EXPIRED_CERT"
    if "self-signed certificate in certificate chain" in msg_lower:
        return "UNTRUSTED_CHAIN"
    if "self-signed" in msg_lower or "self signed" in msg_lower:
        return "SELF_SIGNED_CERT"
    if "hostname mismatch" in msg_lower or "doesn't match" in msg_lower:
        return "WRONG_HOST_CERT"
    if "dns" in msg_lower and ("record" in msg_lower or "name" in msg_lower or "match" in msg_lower):
        return "WRONG_HOST_CERT"
    if "too weak" in msg_lower or "digest algorithm" in msg_lower:
        return "WEAK_SIGNATURE_ALGORITHM"
    if "unable to get local issuer certificate" in msg_lower:
        if chain_length is not None and chain_length <= 1:
            return "INCOMPLETE_CHAIN"
        return "UNTRUSTED_CHAIN"
    if "certificate verify failed" in msg_lower:
        if "unable" in msg_lower:
            if chain_length is not None and chain_length <= 1:
                return "INCOMPLETE_CHAIN"
            return "UNTRUSTED_CHAIN"
        return "UNKNOWN_SSL_ERROR"
    if "bad dh value" in msg_lower or "dh key too small" in msg_lower:
        return "TLS_HANDSHAKE_FAILURE"
    if "sslv3" in msg_lower or "tlsv1" in msg_lower:
        return "TLS_HANDSHAKE_FAILURE"
    if "handshake" in msg_lower or "protocol" in msg_lower:
        return "TLS_HANDSHAKE_FAILURE"
    if "cipher" in msg_lower or "key" in msg_lower:
        return "TLS_HANDSHAKE_FAILURE"
    if "no shared cipher" in msg_lower:
        return "TLS_HANDSHAKE_FAILURE"
    return "UNKNOWN_SSL_ERROR"


def _create_tls_context(ca_store: str = "platform") -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    if ca_store == "certifi":
        try:
            import certifi
            context.load_verify_locations(cafile=certifi.where())
        except ImportError:
            pass
    context.load_default_certs()
    return context


def _check_deprecated_tls(domain: str, ip: str, ca_store: str = "platform") -> bool:
    """Attempt a TLS 1.1 connection to detect deprecated protocol support.

    Returns True if the server accepted a TLS 1.1 handshake (meaning it
    still supports a deprecated version). Returns False if the connection
    failed or the server rejected TLS 1.1. Returns False if ``TLSv1_1``
    is not available at runtime (the caller should check the
    ``deprecated_tls_check`` field to distinguish).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca_store == "certifi":
            try:
                import certifi
                ctx.load_verify_locations(cafile=certifi.where())
            except ImportError:
                pass
        ctx.load_default_certs()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    except (AttributeError, ValueError):
        return False

    try:
        with socket.create_connection((ip, DEFAULT_PORT), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                pass
        return True
    except (ssl.SSLError, socket.timeout, OSError):
        return False


def _determine_chain_subtype(domain: str, ip: str) -> str:
    """Determine chain subtype for UNTRUSTED_CHAIN findings.

    Makes a secondary connection with CERT_NONE to dump the certificate chain
    and classify the root cause into one of:
      - missing_intermediate
      - enterprise_ca
      - government_ca
      - untrusted_root
    """
    subtype = "unknown"
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, DEFAULT_PORT), timeout=PROBE_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                try:
                    chain = tls.get_verified_chain()
                    if chain:
                        chain_len = len(chain)
                        if chain_len <= 1:
                            subtype = "missing_intermediate"
                        else:
                            issuer_org = ""
                            try:
                                cert = tls.getpeercert()
                                if cert:
                                    issuer = dict(x[0] for x in cert.get("issuer", []))
                                    issuer_org = (issuer.get("organizationName") or "").lower()
                            except Exception:
                                pass
                            gov_patterns = {"government", "federal", "state", "national",
                                            "gouvernement", "minister", "administration",
                                            "dirigeants", "public"}
                            enterprise_patterns = {"zscaler", "corporate", "internal", "enterprise",
                                                    "inc.", "ltd", "limited", "llc"}
                            if any(p in issuer_org for p in gov_patterns):
                                subtype = "government_ca"
                            elif any(p in issuer_org for p in enterprise_patterns):
                                subtype = "enterprise_ca"
                            else:
                                subtype = "untrusted_root"
                except (AttributeError, ValueError):
                    subtype = "missing_intermediate"
    except Exception:
        subtype = "unknown"
    return subtype


def _attempt_tls_handshake(domain: str, ip: str, ca_store: str = "platform") -> Dict[str, Any]:
    context = _create_tls_context(ca_store)

    info: Dict[str, Any] = {
        "domain": domain,
        "ip": ip,
        "port": DEFAULT_PORT,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_serial": None,
        "cert_not_before": None,
        "cert_not_after": None,
        "cert_expiry_days": None,
        "cert_is_expired": None,
        "cert_is_self_signed": None,
        "cert_chain_length": None,
        "cert_chain_complete": None,
        "handshake_time_ms": None,
        "error": None,
        "error_category": None,
        "ocsp_performed": False,
        "ocsp_stapled": False,
        "ocsp_status": None,
        "ocsp_error": None,
        "ocsp_responder_url": None,
        "deprecated_tls_check": None,
        "deprecated_tls_detected": False,
        "cipher_name": None,
        "cipher_bits": None,
        "compression": None,
        "wildcard_cert": False,
        "subject_alt_names": [],
    }

    t0 = _time.monotonic()
    try:
        with socket.create_connection((ip, DEFAULT_PORT), timeout=PROBE_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)

                ver = tls.version()
                info["tls_version"] = ver

                cert = tls.getpeercert()
                if cert:
                    info["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["cert_serial"] = cert.get("serialNumber")

                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    info["cert_not_before"] = nb
                    info["cert_not_after"] = na

                    if na:
                        try:
                            expiry = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            info["cert_expiry_days"] = (expiry - now).days
                            info["cert_is_expired"] = now > expiry
                        except ValueError:
                            pass

                try:
                    chain = tls.get_verified_chain()
                    if chain:
                        info["cert_chain_length"] = len(chain)
                        info["cert_chain_complete"] = True
                except (AttributeError, ValueError):
                    info["cert_chain_complete"] = True

                if info.get("cert_chain_length") == 1 and info.get("cert_chain_complete"):
                    info["cert_is_self_signed"] = True

                ocsp_result = check_ocsp(tls, domain)
                info["ocsp_performed"] = ocsp_result.get("ocsp_performed", False)
                info["ocsp_stapled"] = ocsp_result.get("ocsp_stapled", False)
                info["ocsp_status"] = ocsp_result.get("ocsp_status")
                info["ocsp_error"] = ocsp_result.get("ocsp_error")
                info["ocsp_responder_url"] = ocsp_result.get("ocsp_responder_url")

                cipher_result = tls.cipher()
                if cipher_result:
                    info["cipher_name"] = cipher_result[0]
                    info["cipher_bits"] = cipher_result[2]

                try:
                    comp = tls.compression()
                    info["compression"] = comp
                except Exception:
                    pass

                peer_cert = tls.getpeercert()
                if peer_cert:
                    sans = peer_cert.get("subjectAltName", [])
                    dns_names = [san[1] for san in sans if san[0] == "DNS"]
                    info["subject_alt_names"] = dns_names
                    info["wildcard_cert"] = any(
                        n.startswith("*.") for n in dns_names
                    )

                if info.get("cert_is_expired"):
                    info["error"] = "certificate has expired"
                    info["error_category"] = "EXPIRED_CERT"

    except ssl.SSLCertVerificationError as e:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        info["error"] = str(e)
        info["error_category"] = _classify_ssl_error(str(e), info.get("cert_chain_length"))
        if info["error_category"] in ("UNTRUSTED_CHAIN", "INCOMPLETE_CHAIN"):
            info["chain_subtype"] = _determine_chain_subtype(domain, ip)
    except ssl.SSLError as e:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        info["error"] = str(e)
        info["error_category"] = _classify_ssl_error(str(e))
    except socket.timeout:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        info["error"] = f"connection timed out after {PROBE_TIMEOUT}s"
        info["error_category"] = "TIMEOUT"
    except ConnectionRefusedError as e:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        info["error"] = str(e)
        info["error_category"] = "CONNECTION_ERROR"
    except ConnectionResetError as e:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        info["error"] = str(e)
        info["error_category"] = "CONNECTION_ERROR"
    except OSError as e:
        info["handshake_time_ms"] = round((_time.monotonic() - t0) * 1000, 1)
        err_str = str(e)
        if "refused" in err_str.lower():
            info["error_category"] = "CONNECTION_ERROR"
        elif "reset" in err_str.lower():
            info["error_category"] = "CONNECTION_ERROR"
        elif "timed out" in err_str.lower():
            info["error_category"] = "TIMEOUT"
        else:
            info["error_category"] = "CONNECTION_ERROR"
        info["error"] = err_str

    return info


def probe_domain(domain: str, ca_store: str = "platform") -> Dict[str, Any]:
    domain = domain.strip().lower()
    result: Dict[str, Any] = {
        "domain": domain,
        "probe_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "resolved_ip": None,
        "dns_error": None,
        "tls": None,
        "overall_status": None,
        "classification": None,
        "ca_store": ca_store,
    }

    ip, dns_err = _resolve_domain(domain)
    if dns_err:
        result["dns_error"] = dns_err
        result["overall_status"] = "dns_failure"
        result["classification"] = "DNS_FAILURE"
        return result

    result["resolved_ip"] = ip
    tls_info = _attempt_tls_handshake(domain, ip, ca_store=ca_store)
    result["tls"] = tls_info

    if tls_info["error_category"]:
        result["classification"] = tls_info["error_category"]
        result["overall_status"] = CLASSIFICATION.get(tls_info["error_category"], tls_info["error_category"])
    elif tls_info.get("cert_is_expired"):
        result["classification"] = "EXPIRED_CERT"
        result["overall_status"] = "cert_expired"
    elif tls_info.get("cert_is_self_signed"):
        result["classification"] = "SELF_SIGNED_CERT"
        result["overall_status"] = "self_signed_cert"
    else:
        result["classification"] = "VALID_TLS"
        result["overall_status"] = "valid"

    if result["classification"] == "VALID_TLS":
        try:
            ctx_dep = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_dep.check_hostname = True
            ctx_dep.verify_mode = ssl.CERT_REQUIRED
            if ca_store == "certifi":
                try:
                    import certifi
                    ctx_dep.load_verify_locations(cafile=certifi.where())
                except ImportError:
                    pass
            ctx_dep.load_default_certs()
            ctx_dep.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx_dep.maximum_version = ssl.TLSVersion.TLSv1_1
            try:
                with socket.create_connection((ip, DEFAULT_PORT), timeout=PROBE_TIMEOUT) as sock:
                    with ctx_dep.wrap_socket(sock, server_hostname=domain):
                        pass
                tls_info["deprecated_tls_detected"] = True
                tls_info["deprecated_tls_check"] = "supported"
                result["classification"] = "DEPRECATED_TLS_VERSION"
                result["overall_status"] = "tls_deprecated"
            except (ssl.SSLError, socket.timeout, OSError):
                tls_info["deprecated_tls_detected"] = False
                tls_info["deprecated_tls_check"] = "supported"
        except (AttributeError, ValueError):
            tls_info["deprecated_tls_detected"] = False
            tls_info["deprecated_tls_check"] = "unavailable_on_platform"

    if result["classification"] == "VALID_TLS":
        cipher_name = (tls_info.get("cipher_name") or "").upper()
        weak_patterns = ["RC4", "3DES", "NULL", "EXP", "DES"]
        if any(w in cipher_name for w in weak_patterns):
            result["classification"] = "WEAK_CIPHER_SUITE"
            result["overall_status"] = "weak_cipher"
        elif "RSA" in cipher_name and "DHE" not in cipher_name and "ECDHE" not in cipher_name:
            result["classification"] = "STATIC_RSA_KEY_EXCHANGE"
            result["overall_status"] = "static_rsa"
        elif tls_info.get("compression"):
            result["classification"] = "TLS_COMPRESSION_ENABLED"
            result["overall_status"] = "compression_enabled"
        elif tls_info.get("wildcard_cert"):
            result["classification"] = "WILDCARD_CERTIFICATE"
            result["overall_status"] = "wildcard_cert"
        elif not tls_info.get("ocsp_stapled"):
            result["classification"] = "MISSING_OCSP_STAPLE"
            result["overall_status"] = "missing_ocsp_staple"

    ocsp_status = tls_info.get("ocsp_status")
    if ocsp_status == "revoked":
        result["classification"] = "REVOKED_CERT"
        result["overall_status"] = "cert_revoked"
    elif ocsp_status == "unreachable" and result["classification"] == "VALID_TLS":
        result["classification"] = "OCSP_UNREACHABLE"
        result["overall_status"] = "ocsp_unreachable"

    return result


def _load_domains(path: str) -> List[str]:
    domains: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


def _load_expected_labels(path: str) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {entry["domain"]: entry["expected_category"] for entry in data.get("expected", [])}


def _compute_accuracy(results: List[Dict[str, Any]], expected: Dict[str, str]) -> Dict[str, Any]:
    confusion: Dict[str, Dict[str, int]] = {}
    for cat in CLASSIFICATION_ORDER:
        confusion[cat] = {c: 0 for c in CLASSIFICATION_ORDER}

    correct = 0
    total = 0
    false_positives: Dict[str, int] = {c: 0 for c in CLASSIFICATION_ORDER}
    false_negatives: Dict[str, int] = {c: 0 for c in CLASSIFICATION_ORDER}
    unknown_expected: List[str] = []
    missing_results: List[str] = []

    result_map = {r["domain"]: r for r in results}

    for domain, exp_cat in expected.items():
        if domain not in result_map:
            missing_results.append(domain)
            continue
        total += 1
        actual = result_map[domain].get("classification", "UNKNOWN_SSL_ERROR")
        if actual not in confusion:
            confusion[actual] = {c: 0 for c in CLASSIFICATION_ORDER}
        if actual == exp_cat:
            correct += 1
        confusion[exp_cat][actual] = confusion[exp_cat].get(actual, 0) + 1

    for exp_cat in CLASSIFICATION_ORDER:
        for actual_cat in CLASSIFICATION_ORDER:
            val = confusion.get(exp_cat, {}).get(actual_cat, 0)
            if exp_cat != actual_cat and val > 0:
                false_negatives[exp_cat] = false_negatives.get(exp_cat, 0) + val
                false_positives[actual_cat] = false_positives.get(actual_cat, 0) + val

    misc_examples: List[Dict[str, Any]] = []
    for domain in expected:
        r = result_map.get(domain)
        if not r:
            continue
        exp = expected[domain]
        actual = r.get("classification", "UNKNOWN_SSL_ERROR")
        if exp != actual:
            misc_examples.append({
                "domain": domain,
                "expected": exp,
                "actual": actual,
                "error": (r.get("tls") or {}).get("error", r.get("dns_error", "")),
            })

    accuracy_pct = round(correct / total * 100, 1) if total else 0.0

    per_category: Dict[str, Dict[str, Any]] = {}
    for cat in CLASSIFICATION_ORDER:
        exp_count = sum(1 for d, e in expected.items() if e == cat and d in result_map)
        if exp_count == 0:
            continue
        cat_correct = confusion.get(cat, {}).get(cat, 0)
        cat_accuracy = round(cat_correct / exp_count * 100, 1)
        per_category[cat] = {
            "expected_count": exp_count,
            "correct": cat_correct,
            "accuracy_pct": cat_accuracy,
            "false_negatives": false_negatives.get(cat, 0),
            "false_positives": false_positives.get(cat, 0),
        }

    return {
        "total_expected": len(expected),
        "total_with_results": total,
        "correct": correct,
        "accuracy_pct": accuracy_pct,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "per_category": per_category,
        "misclassified_examples": misc_examples[:20],
        "unknown_expected": unknown_expected,
        "missing_results": missing_results,
    }


def _build_seed_report(results: List[Dict[str, Any]], elapsed: float) -> str:
    total = len(results)
    success = sum(1 for r in results if r.get("classification") == "VALID_TLS")
    failure = total - success

    status_counts: Dict[str, int] = {}
    for r in results:
        c = r.get("classification", "UNKNOWN_SSL_ERROR")
        status_counts[c] = status_counts.get(c, 0) + 1

    expiry_info: List[str] = []
    for r in results:
        tls = r.get("tls")
        if tls and tls.get("cert_not_after"):
            days = tls.get("cert_expiry_days")
            label = "expired" if tls.get("cert_is_expired") else f"{days} days remaining"
            expiry_info.append(f"  - {r['domain']}: expires {tls['cert_not_after']} ({label})")

    cert_chain_issues = sum(
        1 for r in results
        if r.get("classification") in ("UNTRUSTED_CHAIN", "INCOMPLETE_CHAIN")
    )

    tls_versions: Dict[str, int] = {}
    for r in results:
        tls = r.get("tls")
        if tls and tls.get("tls_version"):
            v = tls["tls_version"]
            tls_versions[v] = tls_versions.get(v, 0) + 1

    lines = [
        "# Real Data Local Validation — Evidence Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        f"Runner: `scripts/run_local_tls_validation.py`",
        f"Dataset: `datasets/real_tls_seed_domains.txt`",
        f"Duration: {elapsed:.1f}s",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Domains tested | {total} |",
        f"| Success (TLS valid) | {success} |",
        f"| Failure (any error) | {failure} |",
        f"| Cert chain issues | {cert_chain_issues} |",
        f"| Avg probe time per domain | {elapsed / max(total, 1):.1f}s |",
        "",
        "## TLS Validity Findings",
        "",
        "| Classification | Count |",
        "|---|---|",
    ]

    for cat in CLASSIFICATION_ORDER:
        count = status_counts.get(cat, 0)
        if count:
            lines.append(f"| {cat} | {count} |")

    lines.extend([
        "",
        "### TLS Version Distribution",
        "",
    ])
    for ver, count in sorted(tls_versions.items()):
        lines.append(f"- {ver}: {count} domains")
    lines.append("")

    lines.extend([
        "## Certificate Expiry Findings",
        "",
        *expiry_info,
        "",
    ])

    lines.extend([
        "## Known Limitations",
        "",
        "1. **No persistent cert store** — probes are ephemeral; OCSP responses are not cached.",
        "2. **No HSTS/CSP header parsing** — the probe focuses on TLS certificate validity only.",
        "3. **No label generation** — results are observational; no ground-truth labels are produced.",
        "4. **Single IP per domain** — only one A record is probed (first resolved).",
        "5. **No IPv6** — probes use IPv4 only.",
        "6. **No SNI sensitivity testing** — only the domain name is used as SNI.",
        f"7. **Rate limited** — {RATE_LIMIT_SECONDS}s delay between probes to avoid aggressive scanning.",
        f"8. **Timeout** — each connection has a {PROBE_TIMEOUT}s hard limit.",
        "9. **OCSP best-effort** — revocation is checked when the AIA OCSP responder is reachable.",
        "10. **Seed dataset** — manually curated; user should review and extend `datasets/real_tls_seed_domains.txt`.",

        "## Additional Analysis",
        "",
        "The local probe runner does not generate ground-truth labels automatically.",
        "To perform detailed comparison, collect real TLS probe results into a JSONL/CSV dataset",
        "matching the format defined in `docs/REAL_TLS_DATA_CONTRACT.md` and run:",
        "",
        "```",
        "python -m experiments.real_validation_runner <dataset> 1 --verbose",
        "```",
        "",
        "Probe results are observational and do not include `label` or `label_weight` fields.",
        "",
        "## Correctly Handled Failure Examples",
        "",
    ])

    handled_ok = [
        r for r in results
        if r.get("classification") not in ("VALID_TLS", None)
        and r.get("classification") != "UNKNOWN_SSL_ERROR"
    ][:10]
    if handled_ok:
        for r in handled_ok:
            tls = r.get("tls") or {}
            err = tls.get("error", r.get("dns_error", "N/A"))
            lines.append(f"- **{r['domain']}** classified as `{r['classification']}` — {err[:100]}")
    else:
        lines.append("No failure cases to report.")

    lines.extend([
        "",
        "## Known Limitations",
        "",
         "1. **No persistent cert store** — probes are ephemeral; OCSP responses are not cached.",
         "2. **No HSTS/CSP header parsing** — the probe focuses on TLS certificate validity only.",
         "3. **No label generation** — results are observational; no ground-truth labels are produced.",
         "4. **Single IP per domain** — only one A record is probed (first resolved).",
         "5. **No IPv6** — probes use IPv4 only.",
         "6. **No SNI sensitivity testing** — only the domain name is used as SNI.",
         f"7. **Rate limited** — {RATE_LIMIT_SECONDS}s delay between probes to avoid aggressive scanning.",
         f"8. **Timeout** — each connection has a {PROBE_TIMEOUT}s hard limit.",
         "9. **OCSP best-effort** — revocation is checked when the AIA OCSP responder is reachable.",
         "10. **Expected labels** — manually curated; may differ from actual server configuration.",
         "11. **Zero-budget** — no VPS, domain, Let's Encrypt, or cloud services required.",
         "12. **badssl.com** domains may change their TLS configuration over time.",
        "",
        "---",
        "",
        "_This report is for local evidence gathering only. No production claims are made._",
    ])
    return "\n".join(lines)


def _results_to_jsonl(results: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for r in results:
        lines.append(json.dumps(r, default=str))
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/run_local_tls_validation.py <domain_list> [options]")
        print("")
        print("  domain_list      Path to text file with one domain per line (# for comments)")
        print("  --timeout N      Connection timeout in seconds (default: 10)")
        print("  --rate N         Delay between probes in seconds (default: 1.0)")
        print("  --expected PATH  Path to expected labels JSON (enables accuracy report)")
        sys.exit(1)

    dataset_path = sys.argv[1]
    expected_path = None

    global PROBE_TIMEOUT, RATE_LIMIT_SECONDS

    i = 2
    while i < len(sys.argv):
        a = sys.argv[i]
        if a == "--timeout" and i + 1 < len(sys.argv):
            PROBE_TIMEOUT = float(sys.argv[i + 1])
            i += 2
        elif a == "--rate" and i + 1 < len(sys.argv):
            RATE_LIMIT_SECONDS = float(sys.argv[i + 1])
            i += 2
        elif a == "--expected" and i + 1 < len(sys.argv):
            expected_path = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not os.path.isfile(dataset_path):
        print(f"Error: domain list not found: {dataset_path}", flush=True)
        sys.exit(1)

    domains = _load_domains(dataset_path)
    print(f"[LocalTLSProbe] Loaded {len(domains)} domains from {dataset_path}", flush=True)
    print(f"[LocalTLSProbe] Timeout={PROBE_TIMEOUT}s  Rate={RATE_LIMIT_SECONDS}s", flush=True)

    if expected_path:
        if os.path.isfile(expected_path):
            print(f"[LocalTLSProbe] Expected labels: {expected_path}", flush=True)
        else:
            print(f"[LocalTLSProbe] Warning: expected labels not found: {expected_path}", flush=True)
            expected_path = None

    os.makedirs(REPORT_DIR, exist_ok=True)

    results: List[Dict[str, Any]] = []
    t_start = _time.monotonic()

    for i, domain in enumerate(domains):
        print(f"[{i + 1}/{len(domains)}] Probing {domain}...", end=" ", flush=True)
        try:
            result = probe_domain(domain)
            results.append(result)
            classification = result.get("classification", "UNKNOWN_SSL_ERROR")
            tls = result.get("tls") or {}
            err = tls.get("error") or result.get("dns_error") or classification
            if classification == "VALID_TLS":
                print(f"OK  ({tls.get('handshake_time_ms', 0)}ms)", flush=True)
            else:
                print(f"{classification} ({err})", flush=True)
        except Exception as e:
            print(f"ERROR ({e})", flush=True)
            results.append({
                "domain": domain,
                "probe_timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "resolved_ip": None,
                "dns_error": str(e),
                "tls": None,
                "overall_status": "probe_error",
                "classification": "UNKNOWN_SSL_ERROR",
            })

        if i < len(domains) - 1:
            _time.sleep(RATE_LIMIT_SECONDS)

    elapsed = _time.monotonic() - t_start

    is_mixed = "mixed" in os.path.basename(dataset_path).lower()

    if is_mixed and expected_path:
        expected = _load_expected_labels(expected_path)
        accuracy = _compute_accuracy(results, expected)
        report_md = _build_mixed_report(results, elapsed, accuracy)

        accuracy_path = os.path.join(REPORT_DIR, "classification_accuracy.json")
        with open(accuracy_path, "w", encoding="utf-8") as f:
            accuracy_json = {
                "dataset": dataset_path,
                "expected_labels": expected_path,
                "accuracy_pct": accuracy["accuracy_pct"],
                "correct": accuracy["correct"],
                "total": accuracy["total_with_results"],
                "per_category": accuracy["per_category"],
                "misclassified": len(accuracy["misclassified_examples"]),
            }
            json.dump(accuracy_json, f, indent=2)
        print(f"\n[LocalTLSProbe] Classification accuracy written to {accuracy_path}", flush=True)
        report_filename = "MIXED_TLS_VALIDATION_REPORT.md"
    elif is_mixed:
        report_md = _build_mixed_report(results, elapsed)
        report_filename = "MIXED_TLS_VALIDATION_REPORT.md"
    else:
        report_md = _build_seed_report(results, elapsed)
        report_filename = "REAL_DATA_LOCAL_REPORT.md"

    report_path = os.path.join(REPORT_DIR, report_filename)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"[LocalTLSProbe] Report written to {report_path}", flush=True)

    json_path = os.path.join(REPORT_DIR, "tls_probe_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[LocalTLSProbe] JSON results written to {json_path}", flush=True)

    jsonl_path = os.path.join(REPORT_DIR, "tls_probe_results.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        f.write(_results_to_jsonl(results))
    print(f"[LocalTLSProbe] JSONL results written to {jsonl_path}", flush=True)

    valid_count = sum(1 for r in results if r.get("classification") == "VALID_TLS")
    print(f"\n[LocalTLSProbe] Done. {len(results)} domains, {valid_count} VALID_TLS, "
          f"{len(results) - valid_count} problem ({elapsed:.1f}s)", flush=True)

    if is_mixed and expected_path:
        print(f"[LocalTLSProbe] Accuracy: {accuracy['accuracy_pct']}% "
              f"({accuracy['correct']}/{accuracy['total_with_results']})", flush=True)


if __name__ == "__main__":
    main()
