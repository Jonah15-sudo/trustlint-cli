# TrustLint CLI

Fast, zero-dependency TLS risk analysis with OCSP revocation detection and structured decisions.

Probes domains for TLS certificate validity, checks OCSP revocation, detects deprecated protocols (TLS 1.0/1.1), and produces ALLOW/REVIEW/DENY decisions across 20 risk categories with 5 severity levels. 3 operating profiles. JSON + Markdown structured output.

Beta software. Use for TLS risk assessment and CI guardrails; not a complete security audit.

## Install

```bash
pip install spl-tls-analyze
```

## Quickstart

```bash
# Analyze a single domain
spl-tls-analyze example.com

# Batch analysis with strict profile, JSON output
spl-tls-analyze domains.txt --profile strict --json-out report.json

# Markdown report with conservative profile
spl-tls-analyze domains.txt --profile conservative --markdown-out report.md
```

## What It Detects

| Category | Severity | Real-World Example |
|----------|:--------:|--------------------|
| VALID_TLS | NONE | google.com |
| DEPRECATED_TLS_VERSION | HIGH | tls-v1-1.badssl.com |
| REVOKED_CERT | CRITICAL | revoked.badssl.com |
| EXPIRED_CERT | HIGH | expired.badssl.com |
| SELF_SIGNED_CERT | HIGH | self-signed.badssl.com |
| WRONG_HOST_CERT | CRITICAL | wrong.host.badssl.com |
| UNTRUSTED_CHAIN | HIGH | untrusted-root.badssl.com |
| INCOMPLETE_CHAIN | HIGH | incomplete-chain.badssl.com |
| WEAK_SIGNATURE_ALGORITHM | HIGH | sha1-intermediate.badssl.com |
| WEAK_CIPHER_SUITE | HIGH | rc4.badssl.com |
| STATIC_RSA_KEY_EXCHANGE | MEDIUM | dh2048.badssl.com |
| TLS_COMPRESSION_ENABLED | MEDIUM | (extinct in modern TLS) |
| WILDCARD_CERTIFICATE | LOW | badssl.com |
| MISSING_OCSP_STAPLE | LOW | github.com |
| DNS_FAILURE | MEDIUM | nonexistent.example.com |
| CONNECTION_ERROR | MEDIUM | unreachable host |
| TIMEOUT | MEDIUM | unresponsive server |
| TLS_HANDSHAKE_FAILURE | MEDIUM | dh480.badssl.com |
| OCSP_UNREACHABLE | MEDIUM | revoked.badssl.com |
| UNKNOWN_SSL_ERROR | LOW | sha1-intermediate.badssl.com |

## Profiles

| Profile | ALLOW Threshold | HIGH Security | Deprecated TLS | Fallback ALLOW | Use Case |
|---------|:-:|:-:|:-:|:-:|----------|
| **balanced** (default) | — | REVIEW | REVIEW | Clean VALID_TLS | General-purpose scanning |
| **conservative** | — | REVIEW | REVIEW | Never | High-sensitivity |
| **strict** | — | DENY | DENY | Never | Security-critical CI |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All domains ALLOW |
| 1 | One or more REVIEW (no DENY) |
| 2 | One or more DENY |
| 3 | All domains errored |
| 4 | Invalid arguments |

## Output Example

```json
{
  "domain": "expired.badssl.com",
  "final": {
    "decision": "DENY",
    "risk": "HIGH",
    "primary_reason": "Security risk (strict profile): RENEW_OR_DENY for EXPIRED_CERT",
    "recommended_action": "Renew or replace the certificate immediately."
  },
  "tls_probe": {
    "classification": "EXPIRED_CERT",
    "tls_version": null,
    "cert_is_expired": true,
    "resolved_ip": "104.154.89.93"
  }
}
```

## TrustLint Audits

TrustLint commercial TLS audit reports are available for teams, freelancers, and web agencies that want a clear, client-ready review of their domains. See [`docs/COMMERCIAL_AUDITS.md`](docs/COMMERCIAL_AUDITS.md) and [`examples/sample_tls_audit_report.md`](examples/sample_tls_audit_report.md).

## Development

```bash
python -m pytest tests/ -q
python -m build
```

## License

MIT
