"""orchestrator_engine helpers: 检测调度与签名缓存。

从 orchestrator.py 提取的自由函数，
供 Orchestrator 类方法调用。
"""

import inspect
from typing import Callable, Dict, Optional

from tools.tool_registry import get, get_detector_config

_detector_config = get_detector_config()
ALL_DETECTOR_NAMES = list(_detector_config["all"].keys())
DETECTOR_RISK_ORDER = _detector_config["risk_order"]
HIGH_VALUE_DETECTORS = set(_detector_config["high_value"])
LOW_VALUE_DETECTORS = set(_detector_config["low_value"])

ALL_DETECTORS: Dict[str, Callable] = {}
for _name in ALL_DETECTOR_NAMES:
    _fn = get(_name)
    if _fn:
        ALL_DETECTORS[_name] = _fn


_signature_cache: Dict[Callable, Optional[set]] = {}


def _detector_kwargs(fn: Callable, waf_name: str, oob_opts: dict,
                       post_data: Optional[dict], method: str) -> Dict:
    """计算检测器调用 kwargs (缓存)。"""
    params = _signature_cache.get(fn)
    if params is None:
        try:
            params = set(inspect.signature(fn).parameters)
        except Exception:
            params = None
        _signature_cache[fn] = params
    if not params:
        return {}
    kwargs = {}
    if "waf_name" in params:
        kwargs["waf_name"] = waf_name or None
    if "oob_url" in params:
        kwargs["oob_url"] = (oob_opts or {}).get("oob_url")
    if "oob_domain" in params:
        kwargs["oob_domain"] = (oob_opts or {}).get("oob_domain")
    if "oob_server" in params:
        kwargs["oob_server"] = (oob_opts or {}).get("oob_url")
    if "post_body" in params:
        kwargs["post_body"] = bool(post_data)
    if "post_data" in params:
        kwargs["post_data"] = post_data or None
    if "method" in params:
        kwargs["method"] = method or "GET"
    return kwargs


def _run_detector_by_name(vtype: str, url: str, param: str,
                             sess, timeout: float, waf_name: str = "",
                             oob_opts: dict = None,
                             post_data: Optional[dict] = None,
                             method: str = "GET") -> Dict:
    fn = ALL_DETECTORS.get(vtype)
    if not fn:
        fn = get(vtype)
    if not fn:
        fn = get(vtype.replace("_", "-"))
    if not fn:
        return {"vulnerable": False, "error": f"no detector: {vtype}"}
    try:
        kwargs = _detector_kwargs(fn, waf_name, oob_opts, post_data, method)
        try:
            result = fn(url=url, param=param, sess=sess, timeout=timeout, **kwargs)
        except TypeError:
            result = fn(url, param, sess, timeout, waf_name, oob_opts or {})
        return result if isinstance(result, dict) else {"vulnerable": False, "raw": str(result)}
    except Exception as e:
        from tools.log_utils import get_logger
        logger = get_logger("orchestrator")
        logger.debug("run_detector %s: %s", vtype, e)
        return {"vulnerable": False, "error": str(e)}
