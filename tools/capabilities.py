"""Environment capability diagnostics for CLI/MCP installations.

The report is intentionally offline: it checks installed Python packages,
external binaries and writable data directories, but never contacts a target.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sys
from typing import Dict

from tools.settings import settings
from tools.version import __version__

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REQUIRED_DEPENDENCIES = {
    "requests": "HTTP 请求",
    "bs4": "HTML 解析",
    "jwt": "JWT 检测",
    "cryptography": "加密与证书",
    "yaml": "Payload 配置",
    "defusedxml": "安全 XML 解析",
}

OPTIONAL_DEPENDENCIES = {
    "mcp": "MCP 服务接入",
    "playwright": "浏览器验证与 SPA 爬虫",
    "paramiko": "Kali SSH 远程执行",
}

EXTERNAL_TOOLS = ["nmap", "sqlmap", "tshark", "tcpdump", "ffuf", "nuclei", "nikto"]


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _writable_dir(path: str) -> bool:
    probe = os.path.join(path, ".aimy_write_probe")
    try:
        os.makedirs(path, exist_ok=True)
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except OSError:
        try:
            if os.path.isfile(probe):
                os.remove(probe)
        except OSError:
            pass
        return False


def _kali_status() -> Dict:
    try:
        from tools.kali_executor import HAS_PARAMIKO, get_kali
        from tools.kali_executor import is_available as kali_available

        instance = get_kali()
        return {
            "available": bool(kali_available()),
            "local": bool(instance and instance.config.local),
            "remote_configured": bool(instance and instance.config.host),
            "paramiko": bool(HAS_PARAMIKO),
        }
    except Exception:
        return {
            "available": False,
            "local": False,
            "remote_configured": False,
            "paramiko": False,
        }


def check_capabilities() -> Dict:
    """Return a machine-readable readiness report without network access."""
    required = {name: _module_available(name) for name in REQUIRED_DEPENDENCIES}
    optional = {name: _module_available(name) for name in OPTIONAL_DEPENDENCIES}
    external = {name: bool(shutil.which(name)) for name in EXTERNAL_TOOLS}
    kali = _kali_status()
    sessions_dir = os.path.join(_PROJECT_ROOT, "data", "sessions")
    reports_dir = os.path.join(_PROJECT_ROOT, "reports")
    sessions_writable = _writable_dir(sessions_dir)
    reports_writable = _writable_dir(reports_dir)
    oob_configured = bool(settings.oob_domain or settings.oob_callback_url)
    python_supports_mcp = sys.version_info >= (3, 10)

    capabilities = {
        "web_validation": all(required.values()),
        "mcp_server": bool(optional["mcp"] and python_supports_mcp),
        "browser_verification": bool(optional["playwright"]),
        "kali_execution": bool(kali["available"]),
        "oob_testing": oob_configured,
        "packet_capture": bool(external["tshark"] or external["tcpdump"]),
        "session_persistence": sessions_writable,
        "report_export": reports_writable,
    }

    warnings = []
    missing_required = [name for name, ok in required.items() if not ok]
    if missing_required:
        warnings.append("缺少核心依赖: %s" % ", ".join(missing_required))
    if not python_supports_mcp:
        warnings.append("MCP 需要 Python 3.10+；当前版本仅支持 CLI")
    elif not optional["mcp"]:
        warnings.append("未安装 MCP SDK: pip install -e '.[mcp]'")
    if not optional["playwright"]:
        warnings.append("未安装 Playwright，浏览器 XSS 验证和 SPA 爬虫将降级")
    if not kali["available"]:
        warnings.append("Kali 未连接，可配置 --kali-local 或 --kali-host/--kali-user/--kali-pass")
    if not oob_configured:
        warnings.append("未配置 OOB 回调，盲 SSRF/命令注入回连检测能力受限")
    if not sessions_writable:
        warnings.append("会话目录不可写: %s" % sessions_dir)
    if not reports_writable:
        warnings.append("报告目录不可写: %s" % reports_dir)

    return {
        "ready": all(required.values()) and sessions_writable and reports_writable,
        "version": __version__,
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "supports_mcp": python_supports_mcp,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "dependencies": {
            "required": required,
            "optional": optional,
        },
        "external_tools": external,
        "kali": kali,
        "oob": {
            "domain_configured": bool(settings.oob_domain),
            "callback_configured": bool(settings.oob_callback_url),
        },
        "paths": {
            "sessions": sessions_dir,
            "reports": reports_dir,
        },
        "capabilities": capabilities,
        "warnings": warnings,
    }


__all__ = ["check_capabilities"]
