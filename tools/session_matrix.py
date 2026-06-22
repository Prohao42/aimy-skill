import json, os, pickle, time, threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("session_matrix")

SESSION_FILE = os.path.expanduser("~/.aimy-sikll/sessions.pkl")


@dataclass
class Identity:
    label: str
    username: str
    password: str
    role: str = "user"
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionMatrix:
    def __init__(self, base_url: str = ""):
        self.base_url = base_url.rstrip("/")
        self.identities: Dict[str, Identity] = {}
        self._lock = threading.Lock()
        self._loaded = False

    def register(self, label: str, username: str, password: str,
                 role: str = "user") -> Identity:
        identity = Identity(label=label, username=username,
                           password=password, role=role)
        self.identities[label] = identity
        return identity

    def get(self, label: str) -> Optional[Identity]:
        return self.identities.get(label)

    def list(self) -> Dict[str, str]:
        return {k: f"{v.role}:{v.username}" for k, v in self.identities.items()}

    def authenticate_all(self, login_url: str, auth_mode: str = "form",
                         timeout: float = 10.0) -> Dict[str, bool]:
        import requests
        results = {}
        for label, identity in self.identities.items():
            if identity.authenticated:
                results[label] = True
                continue
            sess = requests.Session()
            ok = False
            try:
                if auth_mode == "form":
                    r = sess.post(login_url,
                                  data={"username": identity.username,
                                        "password": identity.password},
                                  timeout=timeout)
                    ok = r.status_code not in (401, 403)
                elif auth_mode == "json":
                    r = sess.post(login_url,
                                  json={"username": identity.username,
                                        "password": identity.password},
                                  timeout=timeout)
                    ok = r.status_code not in (401, 403)
                elif auth_mode == "basic":
                    from requests.auth import HTTPBasicAuth
                    r = sess.get(login_url,
                                 auth=HTTPBasicAuth(identity.username,
                                                    identity.password),
                                 timeout=timeout)
                    ok = r.status_code not in (401, 403)
                if ok:
                    for c in sess.cookies:
                        identity.cookies[c.name] = c.value
                    identity.authenticated = True
                    if "Authorization" in sess.headers:
                        identity.headers["Authorization"] = sess.headers["Authorization"]
                    id_str = identity.label
                    if hasattr(sess, '_auth'):
                        identity.headers.setdefault("Authorization",
                                                     str(sess._auth))
                sess.close()
            except Exception as e:
                logger.debug("auth %s failed: %s", label, e)
            results[label] = ok
        self._save()
        return results

    def make_session(self, label: str) -> Optional[object]:
        import requests
        identity = self.identities.get(label)
        if not identity:
            logger.warning("unknown identity: %s", label)
            return None
        sess = requests.Session()
        for k, v in identity.cookies.items():
            sess.cookies.set(k, v)
        for k, v in identity.headers.items():
            sess.headers[k] = v
        sess.verify = settings.verify_ssl
        return sess

    def cross_session_test(self, actor_label: str, target_label: str,
                           url: str, method: str = "GET",
                           **kwargs) -> Dict:
        actor_sess = self.make_session(actor_label)
        target_sess = self.make_session(target_label)
        if not actor_sess or not target_sess:
            return {"error": "session not found"}
        try:
            actor_resp = getattr(actor_sess, method.lower())(url,
                              timeout=10, **kwargs)
            target_resp = getattr(target_sess, method.lower())(url,
                               timeout=10, **kwargs)
            return {
                "actor": {"label": actor_label, "status": actor_resp.status_code,
                          "length": len(actor_resp.text)},
                "target": {"label": target_label, "status": target_resp.status_code,
                           "length": len(target_resp.text)},
                "body_match": actor_resp.text == target_resp.text,
                "authz_gap": (actor_resp.status_code in (200, 201, 204)
                              and actor_label != target_label
                              and len(actor_resp.text) > 50),
            }
        except Exception as e:
            return {"error": str(e)}

    def _save(self):
        with self._lock:
            try:
                os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
                with open(SESSION_FILE, "wb") as f:
                    pickle.dump({k: v for k, v in self.identities.items()
                                if v.authenticated}, f)
            except Exception as e:
                logger.debug("save sessions: %s", e)

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            if os.path.isfile(SESSION_FILE):
                with open(SESSION_FILE, "rb") as f:
                    data = pickle.load(f)
                    for k, v in data.items():
                        if k not in self.identities:
                            self.identities[k] = v
        except Exception as e:
            logger.debug("load sessions: %s", e)


class SessionComparator:
    def __init__(self, matrix: SessionMatrix):
        self.matrix = matrix

    def compare(self, url: str, actor_a: str, actor_b: str,
                method: str = "GET", **kwargs) -> Dict:
        sa = self.matrix.make_session(actor_a)
        sb = self.matrix.make_session(actor_b)
        if not sa or not sb:
            return {"error": "session not found"}
        try:
            ra = getattr(sa, method.lower())(url, timeout=10,
                                              **kwargs)
            rb = getattr(sb, method.lower())(url, timeout=10,
                                              **kwargs)
        except Exception as e:
            return {"error": str(e)}

        diff = self._compute_diff(ra, rb)
        return {
            "url": url,
            "actor_a": actor_a, "actor_b": actor_b,
            "a": {"status": ra.status_code, "len": len(ra.text)},
            "b": {"status": rb.status_code, "len": len(rb.text)},
            "identical": ra.status_code == rb.status_code and ra.text == rb.text,
            "diff": diff,
        }

    def _compute_diff(self, ra, rb) -> Dict:
        if ra.text == rb.text:
            return {"identical": True}
        a_json, b_json = None, None
        try:
            a_json = json.loads(ra.text)
            b_json = json.loads(rb.text)
        except (json.JSONDecodeError, ValueError):
            pass

        if a_json and b_json:
            return self._json_diff(a_json, b_json)
        return {
            "status_diff": ra.status_code != rb.status_code,
            "length_diff": len(ra.text) - len(rb.text),
        }

    def _json_diff(self, a: Any, b: Any, path: str = "") -> Dict:
        diffs = []
        if type(a) != type(b):
            diffs.append({"path": path or "root", "reason": "type_mismatch",
                         "a_type": type(a).__name__, "b_type": type(b).__name__})
        elif isinstance(a, dict):
            all_keys = set(a) | set(b)
            for k in all_keys:
                sub = f"{path}.{k}" if path else k
                if k not in a:
                    diffs.append({"path": sub, "reason": "key_missing_in_a"})
                elif k not in b:
                    diffs.append({"path": sub, "reason": "key_missing_in_b"})
                elif a[k] != b[k]:
                    sub_diff = self._json_diff(a[k], b[k], sub)
                    if isinstance(sub_diff, list):
                        diffs.extend(sub_diff)
                    else:
                        diffs.append(sub_diff)
        elif isinstance(a, list):
            for i in range(min(len(a), len(b))):
                if a[i] != b[i]:
                    diffs.append({"path": f"{path}[{i}]",
                                  "reason": "value_diff",
                                  "a": str(a[i])[:60], "b": str(b[i])[:60]})
            if len(a) != len(b):
                diffs.append({"path": path, "reason": "length_diff",
                             "a_len": len(a), "b_len": len(b)})
        elif a != b:
            diffs.append({"path": path or "root", "reason": "value_diff",
                         "a": str(a)[:60], "b": str(b)[:60]})
        return {"diffs": diffs, "total": len(diffs)}


def make_matrix(base_url: str = "") -> SessionMatrix:
    return SessionMatrix(base_url)
