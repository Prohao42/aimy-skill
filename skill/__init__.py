"""Claude Skill adapter for aimy-skill.

This package provides a small, structured layer between the LLM/Claude runtime
and the project's scanning/exploitation toolkit. The goal is to keep the public
interface stable while letting the underlying modules remain modular and reusable.
"""

from .contracts import Finding, ScanRequest, ScanReport
from .runner import run_security_scan, run_validation, summarize_results

__all__ = [
    "Finding",
    "ScanRequest",
    "ScanReport",
    "run_security_scan",
    "run_validation",
    "summarize_results",
]
