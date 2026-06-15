import importlib
import inspect
import pkgutil
from typing import Dict, List, Callable, Optional

from tools.log_utils import get_logger

logger = get_logger("tool_registry")

REGISTRY: Dict[str, Dict] = {}

TOOL_MODULES = {
    "portscan": {"module": "tools.port_scanner", "func": "run", "desc": "TCP端口扫描"},
    "dirfuzz": {"module": "tools.dir_fuzzer", "func": "run", "desc": "目录枚举"},
    "sqlcheck": {"module": "tools.sql_injection", "func": "check", "desc": "SQL注入检测"},
    "xsscheck": {"module": "tools.xss_detector", "func": "check", "desc": "XSS检测"},
    "cmdi": {"module": "tools.cmdi_detector", "func": "check", "desc": "命令注入检测"},
    "ssti": {"module": "tools.ssti_detector", "func": "check", "desc": "模板注入检测"},
    "ssrf": {"module": "tools.ssrf_detector", "func": "check", "desc": "SSRF检测"},
    "nosqli": {"module": "tools.nosqli_detector", "func": "check", "desc": "NoSQL注入检测"},
    "lfi": {"module": "tools.lfi_scanner", "func": "check", "desc": "本地文件包含检测"},
    "sqli-blind": {"module": "tools.sqli_blind", "func": "check", "desc": "SQL盲注利用"},
    "sqli-oob": {"module": "tools.sqli_oob", "func": "check", "desc": "OOB SQL注入"},
    "auth-bypass": {"module": "tools.auth_bypass", "func": "check", "desc": "认证绕过检测"},
    "jwt": {"module": "tools.jwt_detector", "func": "check", "desc": "JWT检测"},
    "graphql": {"module": "tools.graphql_scanner", "func": "check", "desc": "GraphQL扫描"},
    "deser": {"module": "tools.deserialization_detector", "func": "check", "desc": "反序列化检测"},
    "proto-pollution": {"module": "tools.proto_pollution", "func": "check", "desc": "原型链污染检测"},
    "cors": {"module": "tools.cors_scanner", "func": "check", "desc": "CORS检测"},
    "xss-validate": {"module": "tools.xss_validator", "func": "check", "desc": "XSS验证"},
    "waf": {"module": "tools.waf_bypass", "func": "check", "desc": "WAF指纹识别与绕过"},
    "deepscan": {"module": "tools.orchestrator", "func": "run", "desc": "深度扫描"},
    "autohunt": {"module": "tools.orchestrator", "func": "run", "desc": "自动狩猎"},
    "chain": {"module": "tools.chain_engine", "func": "run", "desc": "利用链组合攻击"},
    "proxy": {"module": "tools.proxy", "func": "start_proxy", "desc": "MITM代理"},
    "sqli-weaponize": {"module": "tools.sqli_weaponizer", "func": "check", "desc": "SQL注入数据提取"},
    "jwt-exploit": {"module": "tools.jwt_exploiter", "func": "check", "desc": "JWT利用"},
    "ssrf-pwn": {"module": "tools.ssrf_pwn", "func": "check", "desc": "SSRF文件读取"},
    "ssrf-lateral": {"module": "tools.ssrf_lateral", "func": "run", "desc": "SSRF横向移动"},
    "deser-weaponize": {"module": "tools.deser_weaponizer", "func": "check", "desc": "反序列化payload生成"},
    "reverse-shell": {"module": "tools.reverse_shell", "func": "run", "desc": "反弹Shell生成器"},
    "param-mine": {"module": "tools.param_miner", "func": "mine", "desc": "参数挖掘"},
    "crawl": {"module": "tools.crawler", "func": "crawl", "desc": "网页爬虫"},
    "workflow": {"module": "tools.workflow", "func": "run", "desc": "工作流执行"},
    "bizlogic": {"module": "tools.biz_logic_scanner", "func": "check", "desc": "深度业务逻辑漏洞挖掘"},
    "waf-heavy": {"module": "tools.waf_heavy_bypass", "func": "check", "desc": "WAF严格绕过注入检测"},
    "kali-sqlmap": {"module": "tools.kali_toolset", "func": "sqlmap_detect", "desc": "Kali sqlmap注入检测"},
    "kali-nmap": {"module": "tools.kali_toolset", "func": "nmap_scan", "desc": "Kali nmap端口扫描"},
    "kali-ffuf": {"module": "tools.kali_toolset", "func": "ffuf_discover", "desc": "Kali ffuf目录枚举"},
    "kali-nuclei": {"module": "tools.kali_toolset", "func": "nuclei_scan", "desc": "Kali nuclei漏洞扫描"},
    "kali-whatweb": {"module": "tools.kali_toolset", "func": "whatweb_identify", "desc": "Kali whatweb指纹识别"},
    "capture": {"module": "tools.packet_capture", "func": "run_capture", "desc": "环境感知数据包捕获(Kali tcpdump/本地)"},
    "proxy": {"module": "tools.mitm_proxy", "func": "start_proxy", "desc": "MITM代理(请求/响应捕获+检测)"},
}


def get_tool(name: str) -> Optional[Callable]:
    info = TOOL_MODULES.get(name)
    if not info:
        return None
    try:
        mod = importlib.import_module(info["module"])
        return getattr(mod, info["func"])
    except Exception as e:
        logger.debug("tool %s load: %s", name, e)
        return None


def list_tools() -> Dict[str, str]:
    return {k: v["desc"] for k, v in sorted(TOOL_MODULES.items())}
