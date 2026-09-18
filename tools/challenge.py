import re
import subprocess

import requests as _req

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("challenge")

_CHALLENGE_PATTERN = None
_AES_JS_CACHE = None


def detect_challenge(html: str):
    global _CHALLENGE_PATTERN
    if _CHALLENGE_PATTERN is None:
        _CHALLENGE_PATTERN = re.compile(
            r'toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\).*?toNumbers\("([a-f0-9]+)"\)',
            re.DOTALL,
        )
    return _CHALLENGE_PATTERN.search(html[:2000])


def solve_with_node(match, base_url: str):
    global _AES_JS_CACHE
    a, b, c = match.group(1), match.group(2), match.group(3)
    if _AES_JS_CACHE is None:
        try:
            resp = _req.get(base_url.rstrip("/") + "/aes.js",
                            timeout=10, verify=settings.verify_ssl)
            if resp.status_code == 200 and len(resp.text) > 1000:
                text = resp.text
                # 远程 JS 将交由 node 执行 —— 黑名单仅是纵深防御的一层,
                # 挡住常见逃逸姿势 (constructor 链/动态导入/网络外联/编码执行)。
                forbidden = [
                    "require(", "require '", "import ", "import(", "fs.",
                    "child_process", "process.", "eval(", "Function(",
                    "constructor", "WebAssembly", "fetch(", "XMLHttpRequest",
                    "atob(", "btoa(", "fromCharCode", "globalThis",
                    "__proto__", "net.connect", "http.request", "spawn",
                    "execSync", "setTimeout(",
                ]
                if not any(tok in text for tok in forbidden):
                    _AES_JS_CACHE = text
                else:
                    logger.warning("aes.js contains suspicious patterns, skipping")
                    _AES_JS_CACHE = ""
            else:
                _AES_JS_CACHE = ""
        except Exception:
            _AES_JS_CACHE = ""
    if not _AES_JS_CACHE:
        return None
    safe_a = "".join(ch for ch in a if ch in "0123456789abcdef")
    safe_b = "".join(ch for ch in b if ch in "0123456789abcdef")
    safe_c = "".join(ch for ch in c if ch in "0123456789abcdef")
    js_code = _AES_JS_CACHE + f"""
function toNumbers(d){{var e=[];d.replace(/(..)/g,function(d){{e.push(parseInt(d,16))}});return e}}
function toHex(){{for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e='',f=0;f<d.length;f++)e+=(16>d[f]?'0':'')+d[f].toString(16);return e.toLowerCase()}}
try {{ console.log(toHex(slowAES.decrypt(toNumbers("{safe_c}"),2,toNumbers("{safe_a}"),toNumbers("{safe_b}")))); }} catch(e) {{ console.error(e.message); }}
"""
    try:
        result = subprocess.run(["node", "-e", js_code], capture_output=True, text=True, timeout=15)
        val = result.stdout.strip()
        if val and len(val) == 32 and all(ch in "0123456789abcdef" for ch in val):
            return val
    except Exception:
        pass
    return None
