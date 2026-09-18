"""Detection engine: 漏洞检测阶段。

对应 orchestrator.py 中的 30+ detector 调用。

核心接口:
- detect(vtype, url, param, sess, timeout, ...) -> Finding
- 所有检测器应返回统一 Finding 实例
- 旧检测器通过 adapt_old_format() 适配
"""

from typing import Optional

from tools._finding import Finding, OldFormatFinding, Severity, VulnType

# 检测器注册中心
# 新检测器直接返回 Finding 实例
# 旧检测器结果通过 adapt_old_format() 转换

# 统一检测入口
def detect(
    vtype: str,
    url: str,
    param: str,
    sess,
    timeout: float,
    waf_name: str = "",
    oob_opts: dict = None,
    post_data: Optional[dict] = None,
    method: str = "GET",
) -> Finding:
    """统一检测入口。

    调用相应的检测器函数并返回统一 Finding。

    参数:
        vtype: 漏洞类型 (sqli, xss, ssrf, ssti, cmdi, lfi, xxe, nosqli, jwt, cors, etc.)
        url: 目标 URL
        param: 参数名
        sess: requests.Session
        timeout: 超时秒数
        waf_name: WAF 指纹
        oob_opts: OOB 配置
        post_data: POST 数据
        method: HTTP 方法

    返回:
        Finding 实例 (或空 Finding)
    """
    from tools.tool_registry import ALL_DETECTORS

    fn = ALL_DETECTORS.get(vtype)
    if not fn:
        alt_vtype = vtype.replace("_", "-")
        fn = ALL_DETECTORS.get(alt_vtype)

    if not fn:
        from tools.tool_registry import get
        fn = get(vtype)
        if fn:
            ALL_DETECTORS[vtype] = fn

    if not fn:
        import time
        return Finding(
            id=f"missing_{vtype}_{int(time.time())}",
            vuln_type=VulnType.INFO,
            severity=Severity.INFO,
            title=f"Detector not found: {vtype}",
            target=url,
            endpoint=url,
            parameter=param,
            confidence=0.0,
            evidence=None,
            description=f"No detector registered for {vtype}",
        )

    try:
        from inspect import signature
        params = set(signature(fn).parameters)
    except Exception:
        params = set()

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

    try:
        result = fn(url=url, param=param, sess=sess, timeout=timeout, **kwargs)

        if isinstance(result, Finding):
            if not result.id:
                import time
                result.id = f"{result.vuln_type.value}_{url}_{param}_{int(time.time())}"
            return result

        if isinstance(result, dict):
            if "vuln_type" in result and "severity" in result:
                if isinstance(result, dict) and not isinstance(result, Finding):
                    return OldFormatFinding.adapt(result)
                return result
            else:
                return OldFormatFinding.adapt(result)

        if result is None:
            import time
            return Finding(
                id=f"no_find_{int(time.time())}",
                vuln_type=VulnType.INFO,
                severity=Severity.INFO,
                title="No vulnerability detected",
                target=url,
                endpoint=url,
                parameter=param,
                confidence=0.0,
            evidence=None,
                description="Scanner completed without finding targeted vulnerability type",
            )

        import time
        return Finding(
            id=f"unknown_{int(time.time())}",
            vuln_type=VulnType.INFO,
            severity=Severity.INFO,
            title="Unknown result format from detector",
            target=url,
            endpoint=url,
            parameter=param,
            confidence=0.0,
            evidence=None,
            description=f"Detector returned unexpected type: {type(result)}",
        )

    except Exception as e:
        import time
        logger = __import__("tools.log_utils", fromlist=["get_logger"]).get_logger("detect")
        logger.debug("detect %s error: %s", vtype, e)
        return Finding(
            id=f"error_{int(time.time())}",
            vuln_type=VulnType.INFO,
            severity=Severity.INFO,
            title=f"Detection error: {vtype}",
            target=url,
            endpoint=url,
            parameter=param,
            confidence=0.0,
            evidence=None,
            description=str(e),
        )
