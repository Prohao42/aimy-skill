from __future__ import annotations

from typing import Any, Dict, Optional


class SafetyGate:
    """Central gate for safety policy in a Claude skill session.

    It prevents the assistant from directly using exploit modules unless an
    explicit opt-in is provided. This keeps the skill useful for reconnaissance
    and validation while preventing accidental high-risk execution.
    """

    def __init__(self, allow_exploit: bool = False, verify: bool = True):
        self.allow_exploit = allow_exploit
        self.verify = verify

    def validate_request(self, request: Dict[str, Any]) -> None:
        if request.get("allow_exploit") is True:
            self.allow_exploit = True

        if request.get("verify") is False:
            self.verify = False

    def check_phase(self, phase: str) -> None:
        if phase == "exploit" and not self.allow_exploit:
            raise PermissionError(
                "Exploit phase is disabled unless allow_exploit=True and the target is explicitly authorized."
            )

    def require_verified(self) -> None:
        if not self.verify:
            raise ValueError("Verification is disabled; this scan is not safe for reporting results.")


def build_gate(request: Optional[Dict[str, Any]] = None) -> SafetyGate:
    payload = request or {}
    gate = SafetyGate(allow_exploit=bool(payload.get("allow_exploit")), verify=bool(payload.get("verify", True)))
    gate.validate_request(payload)
    return gate
