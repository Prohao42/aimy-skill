from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanRequest:
    """Structured input for a safe, staged security scan.

    The intent is to keep the interface simple enough for Claude while still
    mapping cleanly to the project modules in tools/ and engine/.
    """

    target: str
    mode: str = "safe"
    auth: Optional[Dict[str, Any]] = None
    strategy: str = "default"
    allow_exploit: bool = False
    dry_run: bool = True
    timeout: int = 10
    max_depth: int = 3
    threads: int = 20
    verify: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    name: str
    finding_type: str
    severity: str = "medium"
    confidence: float = 0.0
    validated: bool = False
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    location: str = ""


@dataclass
class ScanReport:
    status: str
    phase: str
    target: str
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "phase": self.phase,
            "target": self.target,
            "summary": self.summary,
            "findings": [
                {
                    "name": item.name,
                    "type": item.finding_type,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "validated": item.validated,
                    "evidence": item.evidence,
                    "details": item.details,
                    "location": item.location,
                }
                for item in self.findings
            ],
            "warnings": self.warnings,
            "next_actions": self.next_actions,
            "metadata": self.metadata,
        }
