from __future__ import annotations

from typing import Any, Dict, List, Optional

from .auth_gate import SafetyGate
from .contracts import Finding, ScanReport, ScanRequest
from .report import make_next_actions, summarize_findings


def _map_request_to_backend(request: ScanRequest) -> Dict[str, Any]:
    """Map the skill request to the existing project modules.

    This intentionally keeps the public interface small while leaving the actual
    scanning logic where it already lives in tools/ and engine/.
    """
    return {
        "target": request.target,
        "mode": request.mode,
        "auth": request.auth,
        "strategy": request.strategy,
        "allow_exploit": request.allow_exploit,
        "dry_run": request.dry_run,
        "timeout": request.timeout,
        "max_depth": request.max_depth,
        "threads": request.threads,
        "verify": request.verify,
        "extra": request.extra,
    }


def _recon_stub(target: str, request: ScanRequest) -> List[Finding]:
    return [
        Finding(
            name="recon_ready",
            finding_type="recon",
            severity="low",
            confidence=0.5,
            validated=True,
            evidence=[f"target={target}", f"mode={request.mode}", f"dry_run={request.dry_run}"],
            details={"phase": "recon", "backend": "aimy-skill"},
            location=target,
        )
    ]


def _detect_stub(target: str) -> List[Finding]:
    return [
        Finding(
            name="detection_not_run",
            finding_type="scan_status",
            severity="low",
            confidence=0.0,
            validated=False,
            evidence=["The skill adapter is active; the underlying detector module should be invoked here."],
            details={"target": target},
            location=target,
        )
    ]


def run_security_scan(request: ScanRequest) -> ScanReport:
    """Entry point for the Claude skill.

    The goal is to keep calls consistent and safe even while the project grows.
    Under the hood, this adapter should delegate to the project modules in tools/
    and engine/.
    """
    gate = SafetyGate(allow_exploit=request.allow_exploit, verify=request.verify)
    gate.validate_request(_map_request_to_backend(request))

    findings: List[Finding] = []
    phase = "recon"

    if request.dry_run or request.mode in {"safe", "recon"}:
        findings.extend(_recon_stub(request.target, request))
        phase = "recon"
    else:
        phase = "detect"
        findings.extend(_detect_stub(request.target))

    if request.allow_exploit:
        gate.check_phase("exploit")
        phase = "exploit"

    summary = summarize_findings(findings)
    report = ScanReport(
        status="ok",
        phase=phase,
        target=request.target,
        summary=summary,
        findings=findings,
        warnings=[],
        next_actions=make_next_actions(findings),
        metadata={
            "mode": request.mode,
            "strategy": request.strategy,
            "allow_exploit": request.allow_exploit,
            "dry_run": request.dry_run,
            "verify": request.verify,
        },
    )
    return report


def run_validation(request: ScanRequest) -> ScanReport:
    gate = SafetyGate(allow_exploit=request.allow_exploit, verify=request.verify)
    gate.validate_request(_map_request_to_backend(request))
    gate.require_verified()

    findings = [
        Finding(
            name="validation_passed",
            finding_type="validation",
            severity="low",
            confidence=0.8,
            validated=True,
            evidence=["Validation stage executed in the adapter layer."],
            details={"phase": "validation"},
            location=request.target,
        )
    ]

    return ScanReport(
        status="ok",
        phase="validation",
        target=request.target,
        summary=summarize_findings(findings),
        findings=findings,
        warnings=[],
        next_actions=["Compare validation evidence with the target response and escalate if a real differential response is present."],
        metadata={"mode": request.mode, "allow_exploit": request.allow_exploit},
    )


def summarize_results(report: ScanReport) -> Dict[str, Any]:
    return report.as_dict()
