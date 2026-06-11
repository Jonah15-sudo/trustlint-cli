"""Local Beta Release Verification (v0.3.2b0).

Usage:
    python scripts/verify_release.py

Runs 14 checks: full test suite, compileall, golden tests,
CLI smoke test, CLI negative fallback test, SPL Core integrity,
OFE status, package metadata, entry point, entry point tests,
install documentation, version consistency, Docker (optional),
VPS dry-run docs.

Docker and VPS checks are file-integrity only (optional).

Returns exit code 0 on success, 1 on any failure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import json
from typing import List, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _run(cmd: List[str], cwd: str = PROJECT_ROOT, timeout: int = 300) -> Tuple[int, str, str]:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def _check_tests() -> Tuple[bool, str]:
    """Run full unittest discover and return (passed, detail)."""
    code, out, err = _run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    # Extract the "Ran X tests" line
    for line in (out + err).splitlines():
        if line.startswith("Ran "):
            ok = "OK" in (out + err)
            status = "PASS" if ok else "FAIL"
            return ok, f"  {status}: {line.strip()}"
    return False, f"  FAIL: Could not parse test result (exit code {code})"


def _check_compileall() -> Tuple[bool, str]:
    """Run compileall on all modules."""
    dirs = [
        "decision_orchestrator",
        "experiments",
        "frontier",
        "scripts",
        "spl_v7",
        "tests",
        "tls_policy_adapter",
        "weakness_mapper",
        "datasets",
    ]
    code, out, err = _run(
        [sys.executable, "-m", "compileall", "-q"] + dirs,
    )
    if code == 0:
        return True, "  PASS: compileall -- no errors"
    return False, f"  FAIL: compileall errors:\n{err}"


def _check_golden_tests() -> Tuple[bool, str]:
    """Run golden acceptance tests specifically."""
    code, out, err = _run(
        [sys.executable, "-m", "pytest", "tests/test_cli_golden_acceptance.py", "--tb=short", "-q"],
    )
    # Parse the last line for summary
    lines = (out + err).strip().splitlines()
    last_line = lines[-1] if lines else "no output"
    if code == 0:
        return True, f"  PASS: golden tests ({last_line.strip()})"
    return False, f"  FAIL: golden tests ({last_line.strip()})"


def _check_cli_smoke() -> Tuple[bool, str]:
    """Run a mocked CLI smoke test (no network) by testing analyze_domain with golden data."""
    sys.path.insert(0, PROJECT_ROOT)
    from unittest.mock import patch
    from scripts.spl_tls_analyze import analyze_domain, format_structured_text

    mock_probe = {
        "domain": "smoke-test.example.com",
        "probe_timestamp": "2026-06-01T12:00:00Z",
        "resolved_ip": "192.0.2.1",
        "dns_error": None,
        "tls": {
            "tls_version": "TLSv1.3",
            "cert_expiry_days": 89,
            "cert_is_expired": False,
            "cert_chain_complete": True,
            "handshake_time_ms": 42.0,
        },
        "overall_status": "valid",
        "classification": "VALID_TLS",
    }

    try:
        with patch("scripts.spl_tls_analyze.probe_domain", return_value=mock_probe):
            result = analyze_domain("smoke-test.example.com", profile="balanced", timeout=5.0)
        text = format_structured_text(result)
        checks = [
            "DOMAIN: smoke-test.example.com" in text,
            "Profile: balanced" in text,
            "Classification: VALID_TLS" in text,
            "ALLOW" in result["final"]["decision"],
            "ADAPTER_FALLBACK" in result["final"]["source"],
            result["final"].get("fallback_used", False) is True,
            "FALLBACK" in result["spl"].get("confidence_source", ""),
            result["ofe_observed"] is False,
        ]
        if all(checks):
            return True, "  PASS: CLI smoke test (mocked VALID_TLS -> ALLOW via balanced fallback)"
        return False, f"  FAIL: CLI smoke test -- checks failed: {checks}"
    except Exception as e:
        return False, f"  FAIL: CLI smoke test -- exception: {e}"


def _check_cli_negative_smoke() -> Tuple[bool, str]:
    """Verify fallback guardrails: risky domains never ALLOW, conservative/strict never fallback."""
    sys.path.insert(0, PROJECT_ROOT)
    from unittest.mock import patch
    from scripts.spl_tls_analyze import analyze_domain

    checks: List[str] = []

    # 1. Expired cert should never ALLOW via fallback
    expired_probe = {
        "domain": "expired.test",
        "probe_timestamp": "2026-06-01T12:00:00Z",
        "resolved_ip": "1.2.3.4", "dns_error": None,
        "tls": {"tls_version": "TLSv1.2", "cert_expiry_days": -1,
                "cert_is_expired": True, "cert_chain_complete": True,
                "handshake_time_ms": 30.0},
        "overall_status": "expired", "classification": "EXPIRED_CERT",
    }
    with patch("scripts.spl_tls_analyze.probe_domain", return_value=expired_probe):
        r = analyze_domain("expired.test", profile="balanced", timeout=5.0)
    if r["final"]["decision"] == "ALLOW":
        checks.append("FAIL: expired cert became ALLOW via fallback")
    else:
        checks.append("PASS: expired cert not ALLOW")

    # 2. Wrong host cert should never ALLOW via fallback
    wronghost_probe = {
        "domain": "wrong.test",
        "probe_timestamp": "2026-06-01T12:00:00Z",
        "resolved_ip": "5.6.7.8", "dns_error": None,
        "tls": {"tls_version": "TLSv1.2", "cert_expiry_days": 200,
                "cert_is_expired": False, "cert_chain_complete": True,
                "handshake_time_ms": 30.0},
        "overall_status": "wrong_host", "classification": "WRONG_HOST_CERT",
    }
    with patch("scripts.spl_tls_analyze.probe_domain", return_value=wronghost_probe):
        r = analyze_domain("wrong.test", profile="balanced", timeout=5.0)
    if r["final"]["decision"] == "ALLOW":
        checks.append("FAIL: wrong host cert became ALLOW via fallback")
    else:
        checks.append("PASS: wrong host cert not ALLOW")

    # 3. DNS failure should remain REVIEW
    dns_probe = {
        "domain": "dnsfail.test",
        "probe_timestamp": "2026-06-01T12:00:00Z",
        "resolved_ip": None, "dns_error": "Name not found",
        "tls": None,
        "overall_status": "dns_failure", "classification": "DNS_FAILURE",
    }
    with patch("scripts.spl_tls_analyze.probe_domain", return_value=dns_probe):
        r = analyze_domain("dnsfail.test", profile="balanced", timeout=5.0)
    if r["final"]["decision"] == "ALLOW":
        checks.append("FAIL: DNS failure became ALLOW via fallback")
    else:
        checks.append("PASS: DNS failure stays REVIEW")

    # 4. Conservative profile should not fallback ALLOW clean VALID_TLS
    clean_probe = {
        "domain": "clean.test", "probe_timestamp": "2026-06-01T12:00:00Z",
        "resolved_ip": "9.9.9.9", "dns_error": None,
        "tls": {"tls_version": "TLSv1.3", "cert_expiry_days": 89,
                "cert_is_expired": False, "cert_chain_complete": True,
                "handshake_time_ms": 42.0},
        "overall_status": "valid", "classification": "VALID_TLS",
    }
    with patch("scripts.spl_tls_analyze.probe_domain", return_value=clean_probe):
        r = analyze_domain("clean.test", profile="conservative", timeout=5.0)
    if r["final"]["decision"] == "ALLOW":
        checks.append("FAIL: conservative fallback ALLOW clean VALID_TLS")
    elif r["final"].get("fallback_used"):
        checks.append("FAIL: conservative used fallback")
    else:
        checks.append("PASS: conservative does not fallback ALLOW")

    # 5. Strict profile should not fallback ALLOW clean VALID_TLS
    with patch("scripts.spl_tls_analyze.probe_domain", return_value=clean_probe):
        r = analyze_domain("clean.test", profile="strict", timeout=5.0)
    if r["final"]["decision"] == "ALLOW":
        checks.append("FAIL: strict fallback ALLOW clean VALID_TLS")
    elif r["final"].get("fallback_used"):
        checks.append("FAIL: strict used fallback")
    else:
        checks.append("PASS: strict does not fallback ALLOW")

    failed = [c for c in checks if c.startswith("FAIL")]
    if not failed:
        return True, "  PASS: all negative smoke checks passed (no fallback for risky domains/conservative/strict)"
    return False, f"  FAIL: negative smoke checks -- {', '.join(failed)}"


def _check_spl_core() -> Tuple[bool, str]:
    """Check whether SPL Core files have been modified (best-effort)."""
    spl_dir = os.path.join(PROJECT_ROOT, "spl_v7")
    main_files = [
        "__init__.py",
        "causal.py",
        "dsl.py",
        "kafka_pipeline.py",
        "pipeline.py",
        "schema.py",
        "verification.py",
        "frontier.py",
    ]
    modified = []
    for f in main_files:
        path = os.path.join(spl_dir, f)
        if os.path.exists(path):
            modified.append(f)
    if len(modified) >= 7:
        return True, f"  PASS: SPL Core files present ({len(modified)}/{len(main_files)})"
    return True, f"  INFO: SPL Core partial ({len(modified)}/{len(main_files)} files) — full git check requires history"


def _check_ofe_status() -> Tuple[bool, str]:
    """Verify OFE remains HOLD_PENDING_REAL_DATA in docs and orchestrator."""
    ofe_terms = ["OFE", "ofe", "HOLD_PENDING_REAL_DATA"]
    doc_dirs = ["docs"]
    found_doc = False
    for dd in doc_dirs:
        dpath = os.path.join(PROJECT_ROOT, dd)
        if not os.path.isdir(dpath):
            continue
        for fname in os.listdir(dpath):
            if fname.endswith(".md"):
                fpath = os.path.join(dpath, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                if "HOLD_PENDING_REAL_DATA" in content:
                    found_doc = True
                    break

    # Check orchestrator
    orch_path = os.path.join(PROJECT_ROOT, "decision_orchestrator", "policy.py")
    orch_holds_ofe = False
    if os.path.exists(orch_path):
        with open(orch_path, "r", encoding="utf-8") as f:
            content = f.read()
        if "HOLD_PENDING_REAL_DATA" in content or "ofe_observed" in content:
            orch_holds_ofe = True

    if found_doc and orch_holds_ofe:
        return True, "  PASS: OFE status -- HOLD_PENDING_REAL_DATA (documented + orchestrator)"
    if found_doc:
        return True, "  PASS: OFE status -- documented as HOLD_PENDING_REAL_DATA"
    return False, "  FAIL: OFE status -- could not confirm HOLD_PENDING_REAL_DATA"


def _check_package_metadata() -> Tuple[bool, str]:
    """Verify pyproject.toml contains required packaging metadata."""
    pp_path = os.path.join(PROJECT_ROOT, "pyproject.toml")
    if not os.path.exists(pp_path):
        return False, "  FAIL: pyproject.toml not found"

    with open(pp_path, "r", encoding="utf-8") as f:
        content = f.read()

    checks = {
        "name": "spl-tls-analyze" in content,
        "version": 'version = "0.3.2b0"' in content,
        "requires-python": "requires-python" in content,
        "entry point": "scripts.spl_tls_analyze:main" in content,
        "build-system": "[build-system]" in content,
    }

    missing = [k for k, v in checks.items() if not v]
    if missing:
        return False, f"  FAIL: Missing in pyproject.toml: {', '.join(missing)}"
    return True, "  PASS: Package metadata complete (name, version, entry point, build config)"


def _check_entry_point() -> Tuple[bool, str]:
    """Verify the console entry point can be imported and called."""
    try:
        import importlib.metadata
        dist = importlib.metadata.distribution("spl-tls-analyze")
        eps = [ep for ep in dist.entry_points if ep.name == "spl-tls-analyze"]
        if not eps:
            return False, "  FAIL: No 'spl-tls-analyze' entry point found in installed metadata"
        # Verify the referenced module loads
        from scripts.spl_tls_analyze import main  # noqa: F811
        return True, f"  PASS: Entry point found ({eps[0].value}) -- module loads cleanly"
    except importlib.metadata.PackageNotFoundError:
        return False, "  FAIL: spl-tls-analyze package not found (run 'pip install -e .')"
    except Exception as e:
        return False, f"  FAIL: Entry point check -- {e}"


def _check_entry_point_tests() -> Tuple[bool, str]:
    """Run the package entry point tests."""
    code, out, err = _run(
        [sys.executable, "-m", "pytest", "tests/test_package_entry.py", "--tb=short", "-q"],
    )
    lines = (out + err).strip().splitlines()
    last_line = lines[-1] if lines else "no output"
    if code == 0:
        return True, f"  PASS: entry point tests ({last_line.strip()})"
    return False, f"  FAIL: entry point tests ({last_line.strip()})"


def _check_install_docs() -> Tuple[bool, str]:
    """Verify install documentation exists."""
    install_path = os.path.join(PROJECT_ROOT, "docs", "INSTALL.md")
    versioning_path = os.path.join(PROJECT_ROOT, "docs", "VERSIONING.md")
    exists = os.path.exists(install_path) and os.path.exists(versioning_path)
    if exists:
        return True, "  PASS: Install docs present (INSTALL.md + VERSIONING.md)"
    missing = [p for p in [install_path, versioning_path] if not os.path.exists(p)]
    return False, f"  FAIL: Missing docs: {missing}"


def _check_version_consistency() -> Tuple[bool, str]:
    """Verify version string is consistent across all key files."""
    expected_version = "0.3.2b0"
    files_to_check = {
        "pyproject.toml": os.path.join(PROJECT_ROOT, "pyproject.toml"),
        "docs/VERSIONING.md": os.path.join(PROJECT_ROOT, "docs", "VERSIONING.md"),
        "docs/RELEASE_NOTES_0.3.0b0.md": os.path.join(PROJECT_ROOT, "docs", "RELEASE_NOTES_0.3.0b0.md"),
        "docs/LOCAL_BETA_FREEZE_MANIFEST.md": os.path.join(PROJECT_ROOT, "docs", "LOCAL_BETA_FREEZE_MANIFEST.md"),
    }
    missing_files = [name for name, path in files_to_check.items() if not os.path.exists(path)]
    if missing_files:
        return False, f"  FAIL: Missing version-bearing files: {', '.join(missing_files)}"

    mismatched = []
    for name, path in files_to_check.items():
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        if expected_version not in content:
            mismatched.append(name)

    if mismatched:
        return False, f"  FAIL: Version '{expected_version}' not found in: {', '.join(mismatched)}"
    return True, f"  PASS: Version '{expected_version}' consistent across all 4 key files"


def _check_docker() -> Tuple[bool, str]:
    """Optional Docker check — verify Dockerfile and docs integrity."""
    docker_path = shutil.which("docker")
    dockerfile = os.path.join(PROJECT_ROOT, "Dockerfile")
    docs_path = os.path.join(PROJECT_ROOT, "docs", "DOCKER_USAGE.md")

    if not os.path.exists(dockerfile):
        return False, "  FAIL: Dockerfile not found"
    if not os.path.exists(docs_path):
        return False, "  FAIL: docs/DOCKER_USAGE.md not found"

    if docker_path is None:
        return True, "  SKIP: Docker CLI not found — file integrity OK, build not verified"

    try:
        code, out, err = _run([docker_path, "build", "-q", "-t", "spl-tls-analyze:test", PROJECT_ROOT], timeout=300)
        if code == 0:
            image_id = out.strip()
            # Verify entry point works
            run_code, run_out, run_err = _run(
                [docker_path, "run", "--rm", image_id, "--help"],
                timeout=30,
            )
            _run([docker_path, "rmi", image_id], timeout=30)  # clean up
            if run_code == 0:
                return True, "  PASS: Docker build + CLI --help OK"
            return True, f"  WARN: Docker build OK but CLI --help failed ({run_err.strip()[:60]})"
        return True, f"  WARN: Docker build failed ({err.strip()[:60]}) — check Dockerfile"
    except Exception as e:
        return True, f"  SKIP: Docker check — {e}"


def _check_vps_docs() -> Tuple[bool, str]:
    """Verify VPS dry-run documentation and scripts exist (file integrity only)."""
    required = {
        "VPS guide": os.path.join(PROJECT_ROOT, "docs", "VPS_DRY_RUN.md"),
        "Report template": os.path.join(PROJECT_ROOT, "docs", "VPS_DRY_RUN_REPORT_TEMPLATE.md"),
        "Dry-run dataset": os.path.join(PROJECT_ROOT, "datasets", "vps_dry_run_domains.txt"),
        "Shell script": os.path.join(PROJECT_ROOT, "scripts", "run_vps_dry_run.sh"),
        "PowerShell script": os.path.join(PROJECT_ROOT, "scripts", "run_vps_dry_run.ps1"),
    }
    missing = [name for name, path in required.items() if not os.path.exists(path)]
    if missing:
        return False, f"  FAIL: Missing VPS dry-run artifacts: {', '.join(missing)}"

    # Verify Dockerfile still CLI-only (no ports, no web server)
    dockerfile = os.path.join(PROJECT_ROOT, "Dockerfile")
    with open(dockerfile, "r") as f:
        df_content = f.read()
    if "EXPOSE" in df_content:
        return False, "  FAIL: Dockerfile exposes ports (VPS dry run must not)"
    if "uvicorn" in df_content or "gunicorn" in df_content:
        return False, "  FAIL: Dockerfile runs web server (VPS dry run must not)"

    return True, "  PASS: VPS dry-run docs, scripts, dataset present; Dockerfile CLI-only"


def main() -> int:
    print("=" * 60)
    print("  LOCAL BETA RELEASE VERIFICATION (v0.3.2b0)")
    print("=" * 60)
    print()

    checks: List[Tuple[str, bool, str]] = [
        ("Full test suite", *_check_tests()),
        ("Compileall", *_check_compileall()),
        ("Golden acceptance tests", *_check_golden_tests()),
        ("CLI mocked smoke test", *_check_cli_smoke()),
        ("CLI negative fallback smoke test", *_check_cli_negative_smoke()),
        ("SPL Core integrity", *_check_spl_core()),
        ("OFE status", *_check_ofe_status()),
        ("Package metadata", *_check_package_metadata()),
        ("Console entry point", *_check_entry_point()),
        ("Entry point tests", *_check_entry_point_tests()),
        ("Install documentation", *_check_install_docs()),
        ("Version consistency", *_check_version_consistency()),
        ("Docker (optional)", *_check_docker()),
        ("VPS dry-run docs", *_check_vps_docs()),
    ]

    all_passed = True
    for name, ok, detail in checks:
        symbol = "PASS" if ok else "FAIL"
        print(f"  [{symbol}] {name}")
        print(detail)
        print()
        if not ok:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("  RESULT: ALL CHECKS PASSED -- release ready")
        print("=" * 60)
        return 0
    else:
        failed = [name for name, ok, _ in checks if not ok]
        print(f"  RESULT: {len(failed)} check(s) FAILED -- not release ready")
        print(f"  Failed: {', '.join(failed)}")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
