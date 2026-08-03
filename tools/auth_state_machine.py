"""Auth state machine: replay identical requests across privilege levels and
differentially detect authorization gaps.

Each "role" owns a session tagged with a privilege rank. The same request is
replayed through every role and the responses are compared. Signals:

* authz_inversion -- a *lower* role is allowed (2xx, non-denied) while a
  *higher* role is denied (401/403/login-redirect). Clear authz misconfig.
* privilege_gap   -- a lower role returns the identical body signature as the
  highest role on a resource that requires auth. Vertical privilege escalation.
* bola            -- two distinct identities at the same rank return identical
  data. Object-level authorization / IDOR.
* anon_access     -- anonymous reaches a resource that higher roles also reach
  with data. Missing authentication (informational, not counted as vulnerable).

The differential mirrors the repo's baseline-vs-probe philosophy: the highest
role is the baseline, and every lower role is judged against it, never
cumulating independent signals.
"""
import hashlib
import re
from collections import defaultdict
from typing import Dict, List, Optional, Sequence

from tools.log_utils import get_logger

logger = get_logger("auth_state_machine")

DENY_STATUS = frozenset((401, 403, 419))
REDIRECT_DENY_MARKERS = ("login", "signin", "sign_in", "auth", "sso")

DENY_BODY_MARKERS = (
    "unauthorized", "forbidden", "access denied", "permission denied",
    "not authorized", "sign in", "please login", "authentication required",
)


def _body_text(resp: Dict) -> str:
    body = resp.get("body") or resp.get("text") or ""
    return str(body)


def _signature(body: str) -> str:
    norm = re.sub(r"\s+", " ", body or "").strip()
    return hashlib.sha1(norm.encode("utf-8", errors="replace")).hexdigest()[:16]


def _denied(status: int, body: str, url: str = "", headers: Optional[Dict] = None) -> bool:
    if status in DENY_STATUS:
        return True
    if status == 302 and url and any(m in url.lower() for m in REDIRECT_DENY_MARKERS):
        return True
    low = (body or "")[:300].lower()
    return any(marker in low for marker in DENY_BODY_MARKERS)


def _fetch(sess, method: str, url: str, timeout: float, params=None,
           data=None, json_body=None, headers=None) -> Dict:
    kwargs = {"params": params, "data": data, "headers": headers, "timeout": timeout}
    if json_body is not None:
        kwargs["json"] = json_body
    try:
        r = sess.request(method, url, **kwargs)
        return {
            "status": int(getattr(r, "status_code", 0) or 0),
            "body": getattr(r, "text", "") or "",
            "url": getattr(r, "url", "") or url,
            "headers": dict(getattr(r, "headers", {}) or {}),
            "size": len(getattr(r, "content", b"") or b""),
        }
    except Exception as exc:
        return {"status": 0, "body": "", "url": url, "headers": {},
                "size": 0, "error": str(exc)}


class AuthStateMachine:
    def __init__(self, roles: Sequence[Dict], timeout: float = 10.0):
        """roles: [{"label", "rank", "sess"}, ...]; rank 0 = anonymous."""
        self.roles = list(roles)
        self.timeout = timeout
        self.max_rank = max((r.get("rank", 0) for r in self.roles), default=0)

    def _row(self, role: Dict, method: str, url: str, params=None,
             data=None, json_body=None, headers=None) -> Dict:
        resp = _fetch(role["sess"], method, url, self.timeout,
                      params=params, data=data, json_body=json_body, headers=headers)
        body = _body_text(resp)
        denied = _denied(resp["status"], body, resp.get("url", url), resp.get("headers"))
        return {
            "label": role.get("label", "?"),
            "rank": role.get("rank", 0),
            "status": resp["status"],
            "size": resp["size"],
            "signature": _signature(body),
            "denied": denied,
            "error": resp.get("error"),
            "body_preview": body[:80],
        }

    def _diff(self, rows: List[Dict]) -> List[Dict]:
        findings: List[Dict] = []
        by_rank = sorted(rows, key=lambda r: r["rank"])
        if not by_rank:
            return findings
        highest = by_rank[-1]
        max_rank = highest["rank"]

        for r in by_rank:
            if r["rank"] >= max_rank:
                continue
            allowed = (not r["denied"]) and r["status"] in (200, 201, 202, 204)
            if allowed and highest["denied"]:
                findings.append({
                    "type": "authz_inversion", "label": r["label"],
                    "note": "%s allowed (%d) while highest role denied (%d)"
                            % (r["label"], r["status"], highest["status"]),
                })

        if not highest["denied"]:
            for r in by_rank:
                if r["rank"] >= max_rank:
                    continue
                if (not r["denied"]) and r["signature"] and r["signature"] == highest["signature"]:
                    findings.append({
                        "type": "privilege_gap", "label": r["label"],
                        "note": "%s returned identical data to highest role"
                                % r["label"],
                    })

        same_rank: Dict[int, List[Dict]] = defaultdict(list)
        for r in rows:
            same_rank[r["rank"]].append(r)
        for rank, group in same_rank.items():
            labels = sorted({r["label"] for r in group})
            if len(labels) > 1 and len(group) >= 2:
                sigs = {r["signature"] for r in group}
                if len(sigs) == 1 and sigs != {""} and not any(r["denied"] for r in group):
                    findings.append({
                        "type": "bola", "label": ",".join(labels),
                        "note": "identities %s returned identical data (rank %d)"
                                % (",".join(labels), rank),
                    })

        anon = next((r for r in rows if r["rank"] == 0), None)
        if anon and (not anon["denied"]) and anon["status"] in (200, 201, 202, 204):
            if any(r["rank"] > 0 and (not r["denied"]) for r in rows):
                findings.append({
                    "type": "anon_access", "label": "anonymous",
                    "note": "anonymous reached an authenticated resource",
                })

        high_types = {"authz_inversion", "privilege_gap", "bola"}
        for f in findings:
            f["severity"] = "high" if f["type"] in high_types else "low"
        return findings

    def replay(self, url: str, method: str = "GET", params: Optional[Dict] = None,
               data: Optional[Dict] = None, json_body: Optional[Dict] = None,
               headers: Optional[Dict] = None,
               roles: Optional[Sequence[Dict]] = None) -> Dict:
        roles = roles or self.roles
        rows = [self._row(r, method, url, params=params, data=data,
                          json_body=json_body, headers=headers) for r in roles]
        findings = self._diff(rows)
        return {
            "url": url, "method": method,
            "roles": rows,
            "findings": findings,
            "vulnerable": any(f["type"] in ("authz_inversion", "privilege_gap", "bola")
                              for f in findings),
        }

    def replay_batch(self, points: Sequence[Dict],
                     roles: Optional[Sequence[Dict]] = None) -> Dict:
        out = []
        for p in points:
            try:
                out.append(self.replay(
                    p["url"], method=p.get("method", "GET"),
                    params=p.get("params"), data=p.get("data"),
                    json_body=p.get("json"), headers=p.get("headers"),
                    roles=roles,
                ))
            except Exception as exc:
                logger.debug("replay %s: %s", p.get("url"), exc)
        findings = [r for r in out if r["vulnerable"]]
        return {
            "points_replayed": len(out),
            "vulnerable": len(findings),
            "results": out,
        }


def auth_replay(points: Sequence[Dict], roles: Sequence[Dict],
                timeout: float = 10.0) -> Dict:
    machine = AuthStateMachine(roles, timeout=timeout)
    return machine.replay_batch(points)
