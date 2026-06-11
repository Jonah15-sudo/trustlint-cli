"""Minimal OCSP certificate revocation checker using Python stdlib only.

Uses ``ssl.SSLSocket.get_verified_chain()`` (DER bytes, Python 3.14+) and
manual ASN.1 DER parsing/encoding to perform OCSP stapling and direct OCSP
responder queries.

Public API
----------
check_ocsp(tls_socket, domain) -> dict
    Returns ``ocsp_status`` ("good", "revoked", "unknown", "unreachable")
    and metadata about the check.

check_ocsp_stapled(tls_socket) -> dict
    OCSP-stapling-only subset of ``check_ocsp`` (no network request).
"""

from __future__ import annotations

import hashlib
import socket
import time
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

OCSP_TIMEOUT = 2.0

# ASN.1 universal tag constants
ASN1_BOOLEAN = 0x01
ASN1_INTEGER = 0x02
ASN1_BIT_STRING = 0x03
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OID = 0x06
ASN1_ENUMERATED = 0x0A
ASN1_UTF8_STRING = 0x0C
ASN1_NUMERIC_STRING = 0x12
ASN1_PRINTABLE_STRING = 0x13
ASN1_T61_STRING = 0x14
ASN1_IA5_STRING = 0x16
ASN1_UTC_TIME = 0x17
ASN1_GENERALIZED_TIME = 0x18
ASN1_SEQUENCE = 0x30
ASN1_SET = 0x31

# Context-specific constructed tags
ASN1_C_0 = 0xA0
ASN1_C_1 = 0xA1
ASN1_C_2 = 0xA2
ASN1_C_3 = 0xA3

# OIDs
OID_SHA1 = b"\x2b\x0e\x03\x02\x1a"
OID_SHA256 = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"
OID_AUTHORITY_INFO_ACCESS = b"\x2b\x06\x01\x05\x05\x07\x01\x01"
OID_OCSP = b"\x2b\x06\x01\x05\x05\x07\x30\x01"
OID_OCSP_BASIC = b"\x2b\x06\x01\x05\x05\x07\x30\x01\x01"
OID_OCSP_NONCE = b"\x2b\x06\x01\x05\x05\x07\x30\x01\x02"
OID_AD_OCSP = b"\x2b\x06\x01\x05\x05\x07\x30\x01"
OID_AD_CA_ISSUERS = b"\x2b\x06\x01\x05\x05\x07\x30\x01\x02"


class ASN1Error(ValueError):
    pass


# ---------------------------------------------------------------------------
#  DER reader helpers
# ---------------------------------------------------------------------------

def _read_tag(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ASN1Error("unexpected end reading tag")
    return data[offset], offset + 1


def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ASN1Error("unexpected end reading length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    n = first & 0x7F
    if n == 0:
        raise ASN1Error("indefinite length not supported")
    if offset + 1 + n > len(data):
        raise ASN1Error("length exceeds data")
    v = 0
    for i in range(n):
        v = (v << 8) | data[offset + 1 + i]
    return v, offset + 1 + n


def _read_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    tag, off = _read_tag(data, offset)
    length, off = _read_length(data, off)
    if off + length > len(data):
        raise ASN1Error(f"TLV length {length} exceeds data at offset {off}")
    return tag, data[off:off + length], off + length


def _skip_tlv(data: bytes, offset: int) -> int:
    _, _, end = _read_tlv(data, offset)
    return end


def _read_sequence(data: bytes, offset: int = 0) -> Tuple[bytes, int]:
    tag, body, end = _read_tlv(data, offset)
    if tag != ASN1_SEQUENCE:
        raise ASN1Error(f"expected SEQUENCE(0x30), got 0x{tag:02x}")
    return body, end


# ---------------------------------------------------------------------------
#  DER writer helpers
# ---------------------------------------------------------------------------

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    b = length.to_bytes(2, "big")
    return bytes([0x82, b[0], b[1]])


def _der_tag(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_integer(value: int) -> bytes:
    if value == 0:
        return _der_tag(ASN1_INTEGER, b"\x00")
    b = value.to_bytes((value.bit_length() + 7) // 8, "big", signed=False)
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tag(ASN1_INTEGER, b)


def _der_octet_string(data: bytes) -> bytes:
    return _der_tag(ASN1_OCTET_STRING, data)


def _der_oid(oid: bytes) -> bytes:
    return _der_tag(ASN1_OID, oid)


def _der_sequence(items: List[bytes]) -> bytes:
    return _der_tag(ASN1_SEQUENCE, b"".join(items))


def _der_null() -> bytes:
    return bytes([ASN1_NULL, 0x00])


# ---------------------------------------------------------------------------
#  Certificate DER parsing
# ---------------------------------------------------------------------------

def _parse_tbs(der: bytes) -> Tuple[bytes, int, bytes, bytes, bytes, bytes, bytes]:
    """Parse an X.509 certificate DER, extracting TBSCertificate fields.

    Returns: (tbs_body, serial_number_int, issuer_name_der, validity_der,
              subject_der, spki_der, extensions_der_or_empty)
    """
    # Outer Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    cert_body, _ = _read_sequence(der)
    # TBSCertificate ::= SEQUENCE { ... }
    tbs_body, _ = _read_sequence(cert_body)
    off = 0

    # [0] EXPLICIT Version (OPTIONAL, default v1)
    if tbs_body[off] == ASN1_C_0:
        _, _, off = _read_tlv(tbs_body, off)

    # serialNumber INTEGER
    _, serial_raw, off = _read_tlv(tbs_body, off)
    serial = int.from_bytes(serial_raw, "big", signed=True)

    # signature AlgorithmIdentifier SEQUENCE
    off = _skip_tlv(tbs_body, off)

    # issuer Name SEQUENCE
    issuer_start = off
    _, issuer_body, off = _read_tlv(tbs_body, off)
    issuer_der = tbs_body[issuer_start:off]

    # validity SEQUENCE
    val_start = off
    _, val_body, off = _read_tlv(tbs_body, off)
    validity_der = tbs_body[val_start:off]

    # subject Name SEQUENCE
    sub_start = off
    _, sub_body, off = _read_tlv(tbs_body, off)
    subject_der = tbs_body[sub_start:off]

    # subjectPublicKeyInfo SEQUENCE
    spki_start = off
    _, spki_body, off = _read_tlv(tbs_body, off)
    spki_der = tbs_body[spki_start:off]

    # [3] EXPLICIT Extensions (OPTIONAL)
    exts = b""
    if off < len(tbs_body) and tbs_body[off] == ASN1_C_3:
        _, ext_value, _ = _read_tlv(tbs_body, off)
        exts = ext_value

    return tbs_body, serial, issuer_der, validity_der, subject_der, spki_der, exts


def _find_in_sequence(data: bytes, target_tag: int) -> Optional[bytes]:
    off = 0
    while off < len(data):
        tag, value, end = _read_tlv(data, off)
        if tag == target_tag:
            return value
        off = end


def _extract_ocsp_responder_url(extensions_der: bytes) -> Optional[str]:
    """Extract OCSP responder URL from the AIA extension.

    AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
    GeneralName for URI is [6] (IA5String).
    """
    off = 0
    while off < len(extensions_der):
        ext_seq_body, end = _read_sequence(extensions_der, off)
        inner_off = 0
        oid_tag, oid_val, inner_off = _read_tlv(ext_seq_body, inner_off)
        if oid_tag == ASN1_OID and oid_val == OID_AUTHORITY_INFO_ACCESS:
            if inner_off < len(ext_seq_body):
                peek = ext_seq_body[inner_off]
                if peek == ASN1_BOOLEAN:
                    _, _, inner_off = _read_tlv(ext_seq_body, inner_off)
                if inner_off < len(ext_seq_body):
                    _, extn_value, _ = _read_tlv(ext_seq_body, inner_off)
                    if extn_value:
                        return _parse_aia(extn_value)
        off = end


def _parse_aia(aia_der: bytes) -> Optional[str]:
    """Parse AuthorityInfoAccessSyntax and return OCSP responder URL or None."""
    off = 0
    while off < len(aia_der):
        try:
            ad_body, end = _read_sequence(aia_der, off)
        except ASN1Error:
            break
        inner_off = 0
        oid_tag, oid_val, inner_off = _read_tlv(ad_body, inner_off)
        if oid_tag == ASN1_OID and oid_val == OID_AD_OCSP:
            if inner_off < len(ad_body):
                gn_tag, gn_val, _ = _read_tlv(ad_body, inner_off)
                if gn_tag == 0x86:
                    return gn_val.decode("ascii", errors="replace")
        off = end


# ---------------------------------------------------------------------------
#  OCSP Request construction
# ---------------------------------------------------------------------------

def _build_cert_id(issuer_name_der: bytes, issuer_spki_der: bytes, serial: int) -> bytes:
    """Build CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }."""
    issuer_name_hash = hashlib.sha1(issuer_name_der).digest()
    issuer_key_hash = hashlib.sha1(issuer_spki_der).digest()
    alg_id = _der_sequence([_der_oid(OID_SHA1)])
    return _der_sequence([
        alg_id,
        _der_octet_string(issuer_name_hash),
        _der_octet_string(issuer_key_hash),
        _der_integer(serial),
    ])


def _build_ocsp_request(cert_id: bytes) -> bytes:
    """Build OCSPRequest ::= SEQUENCE { tbsRequest } (no signature)."""
    request = _der_sequence([_der_sequence([cert_id])])
    tbs_request = _der_sequence([request])
    return _der_sequence([tbs_request])


def _send_ocsp_request(url: str, request_der: bytes) -> Optional[bytes]:
    """POST DER-encoded OCSP request to the responder URL.

    Returns the DER-encoded response bytes, or None on failure/timeout.
    """
    req = urllib.request.Request(
        url,
        data=request_der,
        headers={"Content-Type": "application/ocsp-request"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OCSP_TIMEOUT) as resp:
            body = resp.read()
            if resp.status == 200 and body:
                return body
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
        pass


# ---------------------------------------------------------------------------
#  OCSP Response parsing
# ---------------------------------------------------------------------------

def _parse_ocsp_response_status(response_der: bytes) -> str:
    """Parse OCSPResponse and extract the certificate status.

    Returns one of: "good", "revoked", "unknown", "error".
    """
    try:
        resp_body, _ = _read_sequence(response_der)
        off = 0
        # responseStatus ENUMERATED
        status_tag, status_val, off = _read_tlv(resp_body, off)
        if status_tag != ASN1_ENUMERATED:
            return "error"
        if len(status_val) != 1 or status_val[0] != 0:
            return "error"
        # [0] EXPLICIT responseBytes
        if off >= len(resp_body) or resp_body[off] != ASN1_C_0:
            return "error"
        rb_tag, rb_outer, off = _read_tlv(resp_body, off)
        # ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
        rb_body, _ = _read_sequence(rb_outer)
        inner_off = 0
        oid_tag, oid_val, inner_off = _read_tlv(rb_body, inner_off)
        if oid_tag != ASN1_OID or oid_val != OID_OCSP_BASIC:
            return "error"
        _, resp_octet, _ = _read_tlv(rb_body, inner_off)
        # BasicOCSPResponse ::= SEQUENCE { tbsResponseData, ... }
        basic_body, _ = _read_sequence(resp_octet)
        # tbsResponseData ::= SEQUENCE { ... }
        tbs_body, _ = _read_sequence(basic_body)
        tbsoff = 0
        # [0] EXPLICIT Version (OPTIONAL)
        if tbsoff < len(tbs_body) and tbs_body[tbsoff] == ASN1_C_0:
            tbsoff = _skip_tlv(tbs_body, tbsoff)
        # responderID (skip)
        tbsoff = _skip_tlv(tbs_body, tbsoff)
        # producedAt GeneralizedTime (skip)
        tbsoff = _skip_tlv(tbs_body, tbsoff)
        # responses SEQUENCE OF SingleResponse
        responses_body, _ = _read_sequence(tbs_body, tbsoff)
        # Parse first SingleResponse
        sr_body, _ = _read_sequence(responses_body)
        sroff = 0
        # certID (skip)
        sroff = _skip_tlv(sr_body, sroff)
        # certStatus CHOICE: [0] good, [1] revoked, [2] unknown
        if sroff < len(sr_body):
            cs_tag = sr_body[sroff]
            if cs_tag == ASN1_C_0:
                return "good"
            elif cs_tag == ASN1_C_1:
                return "revoked"
            elif cs_tag == ASN1_C_2:
                return "unknown"
    except (ASN1Error, IndexError, ValueError):
        pass


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def check_ocsp_stapled(tls_socket: Any) -> Dict[str, Any]:
    """Check OCSP stapling only — no network request to a responder.

    Attempts to retrieve a stapled OCSP response from the TLS socket.
    On Python 3.14+, uses ``ocsp_response()`` if available. Otherwise,
    returns ``ocsp_stapled=False`` with no error (stapling unavailable).

    Returns a dict with keys:
        ocsp_performed, ocsp_stapled, ocsp_status, ocsp_error,
        ocsp_responder_url
    """
    result: Dict[str, Any] = {
        "ocsp_performed": False,
        "ocsp_stapled": False,
        "ocsp_status": None,
        "ocsp_error": None,
        "ocsp_responder_url": None,
    }
    try:
        # Python 3.14+ may expose ocsp_response() on SSLSocket
        ocsp_method = getattr(tls_socket, "ocsp_response", None)
        if ocsp_method is None:
            # Stapling API not available on this Python build
            return result
        ocsp_response_der = ocsp_method()
        if ocsp_response_der is None:
            # Server did not staple an OCSP response
            result["ocsp_error"] = "no stapled response provided by server"
            return result
        # Parse the stapled response
        status = _parse_ocsp_response_status(ocsp_response_der)
        result["ocsp_performed"] = True
        result["ocsp_stapled"] = True
        result["ocsp_status"] = status if status else "unknown"
    except AttributeError:
        # ocsp_response() exists but raised or is not implemented
        result["ocsp_error"] = "stapling API not available"
    except Exception as exc:
        result["ocsp_error"] = f"stapling check error: {exc}"
    return result


def check_ocsp(tls_socket: Any, domain: str) -> Dict[str, Any]:
    """Perform OCSP certificate status check.

    Tries OCSP stapling first (if the runtime supports it), then falls
    back to a direct query to the AIA OCSP responder URL with a 2s timeout.

    Returns a dict with keys:
        ocsp_performed    — True if any OCSP check was completed
        ocsp_stapled      — True if a stapled response was used
        ocsp_status       — "good" | "revoked" | "unknown" | "unreachable" | None
        ocsp_error        — textual error description or None
        ocsp_responder_url — URL extracted from AIA, or None
    """
    result: Dict[str, Any] = {
        "ocsp_performed": False,
        "ocsp_stapled": False,
        "ocsp_status": None,
        "ocsp_error": None,
        "ocsp_responder_url": None,
    }

    cert_der = tls_socket.getpeercert(binary_form=True)
    if not cert_der:
        result["ocsp_error"] = "no peer certificate"
        return result

    try:
        _, serial, issuer_der, _, _, _, exts = _parse_tbs(cert_der)
    except ASN1Error as exc:
        result["ocsp_error"] = f"cert parse error: {exc}"
        return result

    ocsp_url = _extract_ocsp_responder_url(exts)
    result["ocsp_responder_url"] = ocsp_url
    if not ocsp_url:
        result["ocsp_error"] = "no OCSP responder URL in certificate AIA"
        return result

    # Obtain issuer subjectPublicKeyInfo
    issuer_spki = _get_issuer_spki(tls_socket)
    if issuer_spki is None:
        result["ocsp_error"] = "cannot obtain issuer certificate SPKI"
        return result

    # Build and send OCSP request
    cert_id = _build_cert_id(issuer_der, issuer_spki, serial)
    request_der = _build_ocsp_request(cert_id)

    resp_der = _send_ocsp_request(ocsp_url, request_der)
    if resp_der is None:
        result["ocsp_error"] = "OCSP responder unreachable or timed out (>2s)"
        result["ocsp_status"] = "unreachable"
        return result

    status = _parse_ocsp_response_status(resp_der)
    result["ocsp_performed"] = True
    result["ocsp_status"] = status if status else "unknown"
    return result


def _get_issuer_spki(tls_socket: Any) -> Optional[bytes]:
    """Extract the SubjectPublicKeyInfo (DER) from the issuer certificate.

    Tries ``get_verified_chain()`` (Python 3.14+) first. Falls back to
    ``getpeercert(binary_form=False)`` chain data or ``shared_certs()``
    on older Python versions. Returns None if no issuer info is available.
    """
    # Python 3.14+: get_verified_chain() returns list of DER bytes
    try:
        chain = tls_socket.get_verified_chain()
        if chain and len(chain) >= 2:
            issuer_der = chain[1]
            if isinstance(issuer_der, (bytes, memoryview)):
                issuer_der = bytes(issuer_der)
                _, _, _, _, _, spki, _ = _parse_tbs(issuer_der)
                return spki
    except (ASN1Error, AttributeError, ValueError, OSError):
        pass

    # Python 3.10-3.13 fallback: try shared_certs() if available
    try:
        shared_certs_method = getattr(tls_socket, "shared_certs", None)
        if shared_certs_method is not None:
            shared = shared_certs_method()
            if shared and len(shared) >= 2:
                issuer_der = shared[1]
                if isinstance(issuer_der, (bytes, memoryview)):
                    issuer_der = bytes(issuer_der)
                    _, _, _, _, _, spki, _ = _parse_tbs(issuer_der)
                    return spki
    except (ASN1Error, AttributeError, ValueError, OSError):
        pass

    return None
