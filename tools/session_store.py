"""session_id 一等公民: 本地文件存储会话，供 stateless agent 跨调用复用登录态。

对比 --session-file (调用方自管路径) 的痛点: agent 每次调用是独立进程，
用文件路径传递容易丢、易冲突。这里改为服务端本地 KV，login 返回 session_id，
后续命令 --session-id 复用，agent 只记住一个短 ID。
"""

from __future__ import annotations

import json
import os
import uuid

from tools.log_utils import get_logger

logger = get_logger("session_store")

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sessions")


def _path(session_id: str) -> str:
    return os.path.join(_DIR, "%s.json" % session_id)


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def save(session_id: str, session) -> str:
    os.makedirs(_DIR, exist_ok=True)
    data = {"cookies": dict(session.cookies), "headers": dict(session.headers)}
    with open(_path(session_id), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return session_id


def load(session_id: str, session) -> bool:
    try:
        with open(_path(session_id), "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.get("cookies", {}).items():
            session.cookies.set(k, v)
        for k, v in data.get("headers", {}).items():
            session.headers[k] = v
        return True
    except Exception as e:
        logger.debug("session_store.load(%s): %s", session_id, e)
        return False
