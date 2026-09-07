"""Detect Engine: 漏洞检测阶段。

对应 orchestrator.py 中的 30+ detector 调用。

核心接口:
- detect(vtype, url, param, sess, timeout, ...) -> Finding
- 所有检测器应返回统一 Finding 实例
- 旧检测器通过 adapt_old_format() 适配
"""

from typing import Dict, List, Optional, Callable
from tools._finding import Finding, OldFormatFinding, Evidence, VulnType, Severity
from tools._session import make_session
from tools.settings import settings


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
    from tools.tool_registry import ALL_DETECTORS, get_detector_config
    
    # 从注册表获取检测器函数
    fn = ALL_DETECTORS.get(vtype)
    if not fn:
        # 尝试按别名查找
        alt_vtype = vtype.replace("_", "-")
        fn = ALL_DETECTORS.get(alt_vtype)
    
    if not fn:
        # 尝试从 get() 懒加载
        from tools.tool_registry import get
        fn = get(vtype)
        if fn:
            # 缓存到 ALL_DETECTORS
            ALL_DETECTORS[vtype] = fn
    
    if not fn:
        # 未找到检测器，返回空 Finding
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
            description=f"No detector registered for {vtype}",
        )
    
    # 计算调用参数
    try:
        from inspect import signature
        params = set(signature(fn).parameters)
    except Exception:
        params = set()
    
    # 构建 kwargs 字典
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
    
    # 执行检测器
    try:
        result = fn(url=url, param=param, sess=sess, timeout=timeout, **kwargs)
        
        # 处理返回结果
        # 情况 1: 返回 Finding 实例 (新格式)
        if isinstance(result, Finding):
            # 确保 ID 包含足够信息
            if not result.id:
                import time
                result.id = f"{result.vuln_type.value}_{url}_{param}_{int(time.time())}"
            return result
        
        # 情况 2: 返回 dict (旧格式)
        if isinstance(result, dict):
            # 检测是否为新格式
            if "vuln_type" in result and "severity" in result:
                # 新格式 - 直接返回 (可能已是 Finding，但检查类型)
                if isinstance(result, dict) and not isinstance(result, Finding):
                    # 通过适配器转换
                    return OldFormatFinding.adapt(result)
                return result
            else:
                # 旧格式 - 通过适配器转换
                return OldFormatFinding.adapt(result)
        
        # 情况 3: 返回其他类型 (列表、字符串等)
        if result is None:
            # 无漏洞发现
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
                description="Scanner completed without finding targeted vulnerability type",
            )
        
        # 情况 4: 未知格式 - 尝试转换
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
            description=f"Detector returned unexpected type: {type(result)}",
        )
    
    # 正常返回
    import time
    return Finding(
        id=f"detected_{int(time.time())}",
        vuln_type=VulnType.INFO,
        severity=Severity.INFO,
        title="Detection completed",
        target=url,
        endpoint=url,
        parameter=param,
        confidence=0.5,
        description="Detection pipeline completed",
    )