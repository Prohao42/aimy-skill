import json

from tools._finding import Finding
from tools.log_utils import get_logger
from tools.mode import enrich_result, filter_vulnerabilities

logger = get_logger("output")


def _serialize(item):
    """统一转可 JSON 序列化的 dict。

    - Finding 实例 -> to_dict()
    - 普通字典 -> 原样返回 (保留旧检测器的输出结构, 平滑过渡)
    - 其他对象 -> 尽力转 dict, 兜底 str
    """
    if isinstance(item, dict):
        return item
    if isinstance(item, Finding):
        return item.to_dict()
    if hasattr(item, "to_dict"):
        try:
            return item.to_dict()
        except Exception:
            pass
    if hasattr(item, "__dict__"):
        return dict(item.__dict__)
    return {"raw": str(item)}


def _prepare(items):
    """veteran 过滤 -> rookie 富化 -> 统一序列化。"""
    enriched = [enrich_result(v) for v in filter_vulnerabilities(list(items))]
    return [_serialize(v) for v in enriched]


def output(result) -> None:
    if isinstance(result, dict) and "vulnerabilities" in result:
        vulns = result["vulnerabilities"]
        result["vulnerabilities"] = _prepare(vulns if isinstance(vulns, list) else [])
        result_json = json.dumps(result, ensure_ascii=False, default=str)
    elif isinstance(result, list):
        result_json = json.dumps({"vulnerabilities": _prepare(result)},
                                 ensure_ascii=False, default=str)
    else:
        result_json = json.dumps(result, ensure_ascii=False, default=str)

    print(result_json)


__all__ = ["output"]
