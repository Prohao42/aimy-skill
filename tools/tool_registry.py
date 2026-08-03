import importlib
import inspect
import threading
from typing import Callable, Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("tool_registry")

_registry: Dict[str, Dict] = {}
_risk_order: Dict[str, int] = {}
_load_lock = threading.RLock()


def detector(name: str, risk: int = 5, tags: Optional[List[str]] = None,
             description: str = ""):
    def wrapper(func: Callable) -> Callable:
        info = {
            "name": name,
            "fn": func,
            "risk": risk,
            "tags": tags or [],
            "description": description or func.__doc__ or "",
            "module": func.__module__,
        }
        with _load_lock:
            _registry[name] = info
            _risk_order[name] = risk
        logger.debug("registered detector: %s (risk=%d, module=%s)", name, risk, func.__module__)
        return func
    return wrapper


def register_tool(name: str, module_path: str, func_name: str,
                  description: str = "", risk: int = 5,
                  tags: Optional[List[str]] = None):
    info = {
        "name": name,
        "module": module_path,
        "func_name": func_name,
        "description": description,
        "risk": risk,
        "tags": tags or [],
    }
    with _load_lock:
        _registry[name] = info
        _risk_order[name] = risk


def get(name: str) -> Optional[Callable]:
    """懒加载并缓存工具函数 (线程安全)。"""
    info = _registry.get(name)
    if not info:
        return None
    fn = info.get("fn")
    if fn:
        return fn
    with _load_lock:
        fn = info.get("fn")
        if fn:
            return fn
        try:
            mod = importlib.import_module(info["module"])
            fn = getattr(mod, info["func_name"])
            info["fn"] = fn
            return fn
        except Exception as e:
            logger.debug("load %s: %s", name, e)
            return None


def get_info(name: str) -> Optional[Dict]:
    return _registry.get(name)


def list_all() -> Dict[str, str]:
    """返回 {工具名: 描述}，按键名排序。"""
    return {k: v.get("description", "") for k, v in sorted(_registry.items())}


def list_by_risk(min_risk: int = 0, max_risk: int = 5) -> List[str]:
    return sorted(
        [k for k, v in _registry.items() if min_risk <= v.get("risk", 5) <= max_risk],
        key=lambda k: (_risk_order.get(k, 5), k),
    )


def list_by_tag(tag: str) -> List[str]:
    return [k for k, v in _registry.items() if tag in v.get("tags", [])]


def run(name: str, *args, **kwargs) -> Dict:
    fn = get(name)
    if not fn:
        return {"error": f"tool not found: {name}"}
    try:
        result = fn(*args, **kwargs)
        return result if isinstance(result, dict) else {"result": result}
    except Exception as e:
        logger.debug("run %s: %s", name, e)
        return {"error": str(e)}


def auto_discover(package: str = "tools"):
    import pkgutil
    for importer, modname, ispkg in pkgutil.iter_modules([package.replace(".", "/")]):
        if modname.startswith("_"):
            continue
        try:
            full = f"{package}.{modname}"
            mod = importlib.import_module(full)
            for name, obj in inspect.getmembers(mod, inspect.isfunction):
                if hasattr(obj, "_registered") and obj._registered:
                    continue
        except Exception:
            continue


register_tool("portscan", "tools.recon.port_scanner", "scan_ports", "TCP端口扫描", risk=3, tags=["recon"])
register_tool("dirfuzz", "tools.recon.dir_fuzzer", "fuzz_directories", "目录枚举", risk=3, tags=["recon"])
register_tool("sqlcheck", "tools.sql_injection", "check", "SQL注入检测", risk=0, tags=["injection", "critical"])
register_tool("xsscheck", "tools.xss_detector", "check", "XSS检测", risk=2, tags=["injection"])
register_tool("cmdi", "tools.cmdi_detector", "check", "命令注入检测", risk=0, tags=["injection", "critical"])
register_tool("ssti", "tools.ssti_detector", "check", "模板注入检测", risk=1, tags=["injection"])
register_tool("ssrf", "tools.ssrf_detector", "check", "SSRF检测", risk=1, tags=["injection"])
register_tool("nosqli", "tools.nosqli_detector", "check", "NoSQL注入检测", risk=2, tags=["injection"])
register_tool("lfi", "tools.lfi_scanner", "check", "本地文件包含检测", risk=1, tags=["injection"])
register_tool("sqli-blind", "tools.sqli_blind", "check", "SQL盲注利用", risk=0, tags=["exploit"])
register_tool("sqli-oob", "tools.sqli_oob", "check", "OOB SQL注入", risk=0, tags=["exploit"])
register_tool("auth-bypass", "tools.auth_bypass", "check", "认证绕过检测", risk=1, tags=["auth"])
register_tool("jwt", "tools.jwt_detector", "check", "JWT检测", risk=3, tags=["auth"])
register_tool("graphql", "tools.graphql_scanner", "check", "GraphQL扫描", risk=2, tags=["injection"])
register_tool("deser", "tools.deserialization_detector", "check", "反序列化检测", risk=0, tags=["injection", "critical"])
register_tool("cors", "tools.cors_scanner", "check", "CORS检测", risk=3, tags=["auth"])
register_tool("xxe", "tools.xxe_detector", "check", "XXE XML外部实体检测", risk=0, tags=["injection", "critical"])
register_tool("waf", "tools.waf_bypass", "check", "WAF指纹识别", risk=4, tags=["recon"])
register_tool("waf-heavy", "tools.waf_bypass", "heavy_check", "WAF严格绕过注入检测", risk=4, tags=["bypass"])
register_tool("bizlogic", "tools.biz_logic_scanner", "check", "业务逻辑漏洞检测", risk=2, tags=["logic"])
register_tool("ssrf-pwn", "tools.ssrf_pwn", "check", "SSRF文件读取与云元数据", risk=0, tags=["exploit", "critical"])
register_tool("sqli-weaponize", "tools.sqli_weaponizer", "check", "SQL注入数据提取", risk=0, tags=["exploit", "critical"])
register_tool("jwt-exploit", "tools.jwt_exploiter", "check", "JWT利用(crack/伪造)", risk=1, tags=["exploit"])
register_tool("crawl", "tools.crawler", "crawl", "网页爬虫", risk=5, tags=["recon"])
register_tool("param-mine", "tools.param_miner", "mine", "参数挖掘", risk=5, tags=["recon"])
register_tool("chain", "tools.chain_engine", "run", "利用链组合攻击", risk=0, tags=["exploit", "critical"])
register_tool("reverse-shell", "tools.reverse_shell", "run", "反弹Shell生成器", risk=0, tags=["exploit"])
register_tool("deser-weaponize", "tools.deser_weaponizer", "check", "反序列化payload生成", risk=0, tags=["exploit"])
register_tool("internal-scan", "tools.internal_scan", "full_network_scan", "内网存活扫描", risk=3, tags=["internal"])
register_tool("smb-lateral", "tools.smb_lateral", "lateral_move", "SMB/WMI横向移动", risk=0, tags=["internal", "critical"])
register_tool("responder", "tools.responder_kit", "ResponderKit", "LLMNR/NBT-NS哈希捕获", risk=2, tags=["internal"])
register_tool("db-lateral", "tools.db_lateral", "scan_database_credentials", "数据库横向移动", risk=0, tags=["internal", "critical"])
register_tool("auto-pwn", "tools.auto_pwn", "auto_pwn", "自律攻击循环", risk=0, tags=["auto", "critical"])


def get_detectors_by_risk() -> Dict[int, List[str]]:
    by_risk: Dict[int, List[str]] = {}
    for name, info in _registry.items():
        r = info.get("risk", 5)
        by_risk.setdefault(r, []).append(name)
    return by_risk


def get_detector_config() -> Dict:
    return {
        "risk_order": dict(_risk_order),
        "high_value": list_by_risk(0, 1),
        "low_value": list_by_risk(3, 5),
        "all": list_all(),
    }
