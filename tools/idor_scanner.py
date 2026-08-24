"""IDOR / 越权检测（SRC 最高频漏洞）。

水平越权: 用账号 A 的会话访问账号 B 的资源（改 id），响应返回数据而非
403/404/空/重定向 -> 越权。

未授权访问: 无会话访问需认证资源，响应仍返回数据 -> 未授权。

支持 GET 查询参数与 POST JSON body 两种注入点。
"""
import re
from typing import Dict, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("idor_scanner")

AUTH_REDIRECT_HINTS = ["login", "signin", "auth", "redirect", "sso", "logout"]


def _fill_template(tpl: str, value: str) -> str:
    """Replace {id}-style placeholder (or the last path segment / query value)."""
    if "{id}" in tpl or "{value}" in tpl:
        return tpl.replace("{id}", value).replace("{value}", value)
    # no placeholder: inject into query param id=xxx if present
    if "id=" in tpl:
        return re.sub(r"id=[^&]*", "id=" + value, tpl)
    # last path segment
    return tpl.rstrip("/") + "/" + value


def _looks_like_data(resp) -> bool:
    """Response actually returns content (not an auth wall / empty / error)."""
    if resp is None:
        return False
    if resp.status_code in (401, 403):
        return False
    if resp.status_code in (404, 410):
        return False
    if resp.status_code >= 500:
        return False
    text = (resp.text or "").strip().lower()
    if not text or len(text) < 8:
        return False
    # auth redirect / login page
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = (resp.headers or {}).get("Location", "").lower()
        if any(h in loc for h in AUTH_REDIRECT_HINTS):
            return False
        return True
    if any(h in text for h in ("login", "sign in", "please log in",
                               "unauthorized", "forbidden", "access denied")):
        return False
    if text in ("null", "[]", "{}", "false", "true", "ok", "success"):
        return False
    return True


def _request(sess: requests.Session, url: str, method: str, json_body: Optional[dict],
             timeout: float) -> Optional[requests.Response]:
    try:
        if json_body is not None:
            return sess.request(method, url, json=json_body, timeout=timeout)
        return sess.request(method, url, timeout=timeout)
    except Exception as e:
        logger.debug("idor req %s: %s", url, e)
        return None


def check(url: str, param: str = "id", sess_a: Optional[requests.Session] = None,
          sess_b: Optional[requests.Session] = None,
          my_id: str = "", other_id: str = "",
          method: str = "GET", json_param: Optional[str] = None,
          timeout: float = 10.0) -> Dict:
    """Horizontal privilege escalation check.

    - sess_a: victim session (used to hit the other user's resource)
    - sess_b: reference session (optional; used to confirm the resource exists)
    - my_id / other_id: own resource id vs target (other user's) id
    """
    sess_a = sess_a or make_session()
    result = {"vulnerable": False, "type": "idor", "evidence": [],
              "target_url": url, "param": param}

    if not my_id or not other_id:
        result["error"] = "my_id and other_id required (自己资源的 id 与目标用户的 id)"
        return result

    if json_param:
        # JSON body carries the id; URL stays untouched.
        own_url = other_url = url
        own_body = {json_param: my_id}
        other_body = {json_param: other_id}
    else:
        own_url = _fill_template(url, my_id)
        other_url = _fill_template(url, other_id)
        own_body = other_body = None

    # 1. Baseline: A accesses its own resource -> should return data
    r_own = _request(sess_a, own_url, method, own_body, timeout)
    if not _looks_like_data(r_own):
        result["evidence"].append("baseline own resource not accessible (status=%s)" % (
            getattr(r_own, "status_code", None)))
        return result

    # 2. A accesses B's resource (horizontal escalation)
    r_other = _request(sess_a, other_url, method, other_body, timeout)
    if not _looks_like_data(r_other):
        result["evidence"].append(
            "other resource blocked (status=%s) - no horizontal escalation" % (
                getattr(r_other, "status_code", None)))
        return result

    # 3. Distinguish "returns B's data" from "generic page": compare with B's session
    #    when available; otherwise compare content richness vs own resource.
    is_escalation = False
    if sess_b is not None:
        r_other_b = _request(sess_b, other_url, method, other_body, timeout)
        if _looks_like_data(r_other_b):
            same = (r_other_b.status_code == r_other.status_code and
                    abs(len(r_other_b.text) - len(r_other.text)) <= max(40, len(r_other.text) // 5))
            is_escalation = same
        else:
            # B itself cannot read it either -> generic page, not escalation
            is_escalation = False
    else:
        # heuristic: response differs from own-resource page but is data-rich
        if len((r_other.text or "")) >= 20 and r_other.text != r_own.text:
            is_escalation = True

    if is_escalation:
        result["vulnerable"] = True
        result["evidence"].append(
            "IDOR: session A reads resource %s (id=%s) -> %d, len=%d (matches B's view)" % (
                other_url, other_id, r_other.status_code, len(r_other.text or "")))
        result["own_url"] = own_url
        result["other_url"] = other_url
        result["response_preview"] = (r_other.text or "")[:200]
    else:
        result["evidence"].append(
            "other resource returns data but differs from B's view - may be generic page, not IDOR")
    return result


def check_unauthorized(url: str, sess: Optional[requests.Session] = None,
                       timeout: float = 10.0) -> Dict:
    """Unauthenticated access: no session -> protected resource still returns data."""
    sess = sess or make_session()
    result = {"vulnerable": False, "type": "unauth_access", "evidence": [], "url": url}
    r = _request(sess, url, "GET", None, timeout)
    if _looks_like_data(r):
        result["vulnerable"] = True
        result["evidence"].append(
            "unauthenticated access returns data: %d, len=%d" % (
                r.status_code, len(r.text or "")))
        result["response_preview"] = (r.text or "")[:200]
    else:
        result["evidence"].append("unauthenticated access blocked (status=%s)" % (
            getattr(r, "status_code", None)))
    return result
