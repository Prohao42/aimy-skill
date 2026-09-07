from __future__ import annotations

from typing import Iterable, List

from .contracts import Finding


def summarize_findings(findings: Iterable[Finding]) -> dict:
    items = list(findings)
    summary = {
        "total": len(items),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "validated": 0,
    }
    for item in items:
        level = item.severity.lower()
        if level in summary:
            summary[level] += 1
        elif level not in {"critical", "high", "medium", "low"}:
            summary["low"] += 1
        if item.validated:
            summary["validated"] += 1
    return summary


def make_next_actions(findings: Iterable[Finding]) -> List[str]:
    actions: List[str] = []
    items = list(findings)
    if not items:
        return [
            "Continue reconnaissance to expand the attack surface.",
            "Check whether authentication or bot protections are in effect.",
        ]

    if any(item.finding_type in {"sql_injection", "command_injection"} for item in items):
        actions.append("Validate each finding with a stable payload and compare response diff before escalation.")

    if any(item.finding_type in {"auth_bypass", "cors", "jwt"} for item in items):
        actions.append("Inspect authentication and session boundaries to confirm the impact and affected roles.")

    if any(item.severity in {"critical", "high"} for item in items):
        actions.append("Prepare a concise evidence pack and a remediation recommendation for the owner.")

    actions.append("If the target is production, require explicit authorization before attempting exploit steps.")
    return actions
