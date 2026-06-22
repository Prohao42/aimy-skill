import re, time
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.settings import settings
from tools.http_client import build_url
from tools.payload_engine import (
    generate_sqli_error, generate_sqli_boolean,
    generate_sqli_time, generate_sqli_union, generate_sqli_stacked,
)

logger = get_logger("sql_injection")

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
    r"Syntax error or access violation",
    r"mysql_fetch",
    r"mysqli_fetch",
    r"supplied argument is not a valid MySQL",
    r"Division by zero.*SQL",
    r"Data truncated",
    r"Column count doesn't match",
    r"Table '[^']+' doesn't exist",
]


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          waf_name: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None, "dbms": None}

    ctx = "numeric" if param and param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"

    if post_body and post_data:
        base_data = post_data.copy()
    else:
        base_data = None

    def _do_req(payload):
        if post_data:
            d = base_data.copy() if base_data else {}
            d[param] = payload
            return sess.post(url, data=d, timeout=timeout)
        else:
            return sess.get(build_url(url, param, payload),
                           timeout=timeout)

    error_payloads = generate_sqli_error(ctx, waf_name)
    for payload in error_payloads:
        try:
            r = _do_req(payload)
            for p in SQLI_ERROR_PATTERNS:
                if re.search(p, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "error"
                    result["evidence"].append(payload[:40])
                    result["vector"] = payload
                    if "MySQL" in p or "mysql" in p:
                        result["dbms"] = "MySQL"
                    elif "Oracle" in p:
                        result["dbms"] = "Oracle"
                    elif "PostgreSQL" in p or "pg_" in p:
                        result["dbms"] = "PostgreSQL"
                    elif "SQLite" in p:
                        result["dbms"] = "SQLite"
                    elif "SQL Server" in p or "mssql" in p:
                        result["dbms"] = "MSSQL"
                    break
        except Exception as e:
            logger.debug("sqli error payload %s: %s", payload[:20], e)
        if result["vulnerable"]:
            return result

    if not result["vulnerable"]:
        union_payloads = generate_sqli_union(ctx, waf_name)
        for payload in union_payloads:
            try:
                r = _do_req(payload)
                for p in SQLI_ERROR_PATTERNS:
                    if re.search(p, r.text, re.IGNORECASE):
                        result["vulnerable"] = True
                        result["type"] = "error_union"
                        result["evidence"].append("union: %s" % payload[:30])
                        result["vector"] = payload
                        result["dbms"] = guess_dbms(r.text)
                        break
            except Exception as e:
                logger.debug("sqli union %s: %s", payload[:20], e)
            if result["vulnerable"]:
                return result

    if not result["vulnerable"]:
        baseline_len = 0
        try:
            bl = _do_req("1")
            baseline_len = len(bl.text)
        except Exception:
            pass

        bool_pairs = generate_sqli_boolean(ctx, waf_name)
        for true_p, false_p in bool_pairs:
            try:
                if post_data:
                    d = base_data.copy() if base_data else {}
                    d[param] = true_p
                    r_true = sess.post(url, data=d, timeout=timeout)
                    d[param] = false_p
                    r_false = sess.post(url, data=d, timeout=timeout)
                else:
                    r_true = sess.get(build_url(url, param, true_p),
                                      timeout=timeout)
                    r_false = sess.get(build_url(url, param, false_p),
                                       timeout=timeout)
                diff = abs(len(r_true.text) - len(r_false.text))
                max_len = max(len(r_true.text), len(r_false.text), 1)
                ratio = diff / max_len
                if r_true.status_code != r_false.status_code:
                    result["vulnerable"] = True
                elif ratio > 0.05 and diff > max(20, baseline_len * 0.02):
                    result["vulnerable"] = True
                if result["vulnerable"]:
                    result["type"] = "boolean"
                    result["evidence"].append("bool: %s (diff=%d, ratio=%.2f%%)" % (
                        true_p[:25], diff, ratio * 100))
                    result["vector"] = true_p
                    break
            except Exception as e:
                logger.debug("sqli boolean %s: %s", true_p[:20], e)
        if result["vulnerable"]:
            return result

    if not result["vulnerable"]:
        stacked_payloads = generate_sqli_stacked(ctx, waf_name)
        for payload in stacked_payloads:
            try:
                r = _do_req(payload)
                if r.status_code < 500:
                    for p in SQLI_ERROR_PATTERNS:
                        if re.search(p, r.text, re.IGNORECASE):
                            result["vulnerable"] = True
                            result["type"] = "stacked_error"
                            result["evidence"].append("stacked: %s" % payload[:25])
                            result["vector"] = payload
                            break
            except Exception as e:
                logger.debug("sqli stacked %s: %s", payload[:20], e)
            if result["vulnerable"]:
                return result

    if not result["vulnerable"]:
        time_payloads = generate_sqli_time(waf_name)
        for payload in time_payloads:
            try:
                start_t = time.time()
                if post_data:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    r = sess.post(url, data=d, timeout=timeout + 3)
                else:
                    r = sess.get(build_url(url, param, payload),
                                timeout=timeout + 3)
                elapsed = time.time() - start_t
                if elapsed >= 2.0:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("time: %.1fs" % elapsed)
                    result["vector"] = payload
                    if "SLEEP" in payload:
                        result["dbms"] = "MySQL"
                    elif "pg_sleep" in payload:
                        result["dbms"] = "PostgreSQL"
                    elif "WAITFOR" in payload:
                        result["dbms"] = "MSSQL"
                    break
            except Exception as e:
                logger.debug("sqli time %s: %s", payload[:20], e)

    return result


def guess_dbms(text: str) -> Optional[str]:
    for pat, name in [
        (r"mysql|MariaDB", "MySQL/MariaDB"),
        (r"postgresql|pg_|PSQLException", "PostgreSQL"),
        (r"ORA-\d{5}|oracle", "Oracle"),
        (r"sqlite|SQLite", "SQLite"),
        (r"mssql|sql server|OLE DB|SqlException", "MSSQL"),
    ]:
        if re.search(pat, text, re.IGNORECASE):
            return name
    return None
