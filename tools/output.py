import json
import sys
import time
import uuid

from tools._finding import Finding
from tools.log_utils import get_logger
from tools.mode import enrich_result, filter_vulnerabilities

logger = get_logger("output")

_JSON_MODE = False
_QUIET = False

# 统一结果信封上下文: main() / MCP 调用前设置，output() 读取后注入 _meta。
# request_id 为 None 时不注入信封，保持直接调用 output() 的既有契约不变。
_CTX = {
    "tool": None,
    "request_id": None,
    "started": None,
    "format": "json",  # json | jsonl
}


def configure(json_mode: bool = False, quiet: bool = False) -> None:
    """Configure machine-readable output and progress verbosity."""
    global _JSON_MODE, _QUIET
    _JSON_MODE = bool(json_mode)
    _QUIET = bool(quiet or json_mode)


def progress(message="", *args, **kwargs) -> None:
    """Emit human progress on stderr so stdout stays pure JSON."""
    if _QUIET:
        return
    text = message % args if args else str(message)
    kwargs.pop("file", None)
    kwargs.setdefault("flush", True)
    print(text, file=sys.stderr, **kwargs)


def set_format(fmt: str) -> None:
    _CTX["format"] = fmt or "json"


def begin_context(tool=None) -> None:
    _CTX["tool"] = tool
    _CTX["request_id"] = uuid.uuid4().hex[:12]
    _CTX["started"] = time.time()


def _meta(status="ok", error=None):
    """返回 _meta 信封; 未处于命令上下文时返回 None (不改变裸调用输出)。"""
    if _CTX["request_id"] is None:
        return None
    m = {
        "schema_version": 1,
        "status": status,
        "tool": _CTX["tool"],
        "request_id": _CTX["request_id"],
        "duration_ms": None,
    }
    if _CTX["started"] is not None:
        m["duration_ms"] = int((time.time() - _CTX["started"]) * 1000)
    if error is not None:
        m["error"] = str(error)
    return m


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


def _enforce_contract(result):
    """Normalize detector results to the shared CheckResult shape.

    Unknown fields are preserved in ``extras``; missing ``vulnerable`` becomes
    ``False`` and malformed confidence fields are logged instead of crashing.
    """
    if not isinstance(result, dict):
        return result
    if "vulnerable" not in result and "type" not in result:
        return result
    from engine.contract import CheckResult, check_return_shape

    for warning in check_return_shape(result, strict=True):
        logger.warning("detector contract: %s", warning)
    return CheckResult.from_dict(result).to_dict()


def to_json(result) -> str:
    """返回带信封的 JSON 字符串 (不打印)，供 MCP / 程序化调用捕获。"""
    result = _enforce_contract(result)
    if isinstance(result, dict) and "vulnerabilities" in result:
        out = dict(result)
        out["vulnerabilities"] = _prepare(
            result["vulnerabilities"] if isinstance(result["vulnerabilities"], list) else []
        )
    elif isinstance(result, list):
        out = {"vulnerabilities": _prepare(result)}
    elif isinstance(result, dict):
        out = dict(result)
    else:
        out = {"result": result}
    meta = _meta()
    if meta is not None:
        out["_meta"] = meta
    return json.dumps(out, ensure_ascii=False, default=str)


def _output_jsonl(result) -> None:
    if isinstance(result, dict) and isinstance(result.get("vulnerabilities"), list):
        items = result["vulnerabilities"]
    elif isinstance(result, list):
        items = result
    else:
        items = [result]
    for it in items:
        print(json.dumps(_serialize(_enforce_contract(it)), ensure_ascii=False, default=str))


def output(result) -> None:
    """打印带信封的结果。--format jsonl 时按 finding 逐行输出。"""
    if _CTX["format"] == "jsonl":
        _output_jsonl(result)
    else:
        print(to_json(result))


def error(message: str, code: str = "error", **extra) -> None:
    """Emit a structured error envelope (stdout in JSON mode, stderr otherwise)."""
    payload = {"ok": False, "error": str(message), "code": code}
    payload.update(extra)
    stream = sys.stdout if _JSON_MODE else sys.stderr
    print(json.dumps(payload, ensure_ascii=False, default=str), file=stream)


__all__ = [
    "configure",
    "progress",
    "output",
    "error",
    "to_json",
    "set_format",
    "begin_context",
]
