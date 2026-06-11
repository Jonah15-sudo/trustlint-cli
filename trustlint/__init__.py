"""TrustLint — TLS risk analysis library and CLI.

This module provides the public Python API for TrustLint.
For CLI usage, see the `trustlint` command.

Example:
    >>> from trustlint import analyze, analyze_batch
    >>> result = analyze("example.com")
    >>> print(result["final"]["decision"])
    "ALLOW"
"""

from __future__ import annotations

from typing import Any, Dict, List

# Re-export public API from the implementation module
from scripts.spl_tls_analyze import (
    analyze,
    analyze_batch,
    get_version,
    get_classifications,
)

__version__ = "1.0.0"

__all__ = [
    "analyze",
    "analyze_batch",
    "get_version",
    "get_classifications",
    "__version__",
]
