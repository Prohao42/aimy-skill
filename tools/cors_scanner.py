from typing import Optional, Dict
import requests

CORS_HEADERS_CHECK = {
    "Access-Control-Allow-Origin": ["*", "null", "http://evil.com", "http://attacker.com"],
    "Access-Control-Allow-Credentials": ["true"],
    "Access-Control-Allow-Methods": ["*"],
    "Access-Control-Expose-Headers": ["*"],
}

VULNERABLE_ORIGINS = ["http://evil.com", "null", "http://attacker.com", "http://evil"]


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "findings": []}

    if not url.startswith("http"):
        url = "http://" + url

    test_origins = [
        "http://evil.com",
        "https://evil.com",
        "null",
        "http://evil.com.evil.com",
        "http://evilevil.com",
        "https://attacker.com",
    ]

    for origin in test_origins:
        try:
            r = sess.get(url, headers={"Origin": origin}, timeout=timeout, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acc = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin:
                finding = {"origin": origin, "acao": acao}
                if acc == "true":
                    finding["credentialed"] = True
                result["findings"].append(finding)
                result["vulnerable"] = True
            elif acao == "*":
                result["findings"].append({"origin": origin, "acao": "*",
                                           "note": "wildcard origin (not credentialable)"})
                result["vulnerable"] = True
        except:
            pass

    try:
        r = sess.options(url, timeout=timeout, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao:
            result["findings"].append({"method": "OPTIONS", "acao": acao})
    except:
        pass

    return result
