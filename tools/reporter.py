import json, os
from datetime import datetime
from typing import Dict, Any

from tools.log_utils import get_logger

logger = get_logger("reporter")


class SafeJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        if hasattr(o, "__dict__"):
            return repr(o)
        try:
            return super().default(o)
        except TypeError:
            return str(o)


def to_json(data: Any, indent: int = 2) -> str:
    return json.dumps(data, cls=SafeJSONEncoder, indent=indent, ensure_ascii=False, default=str)

USE_COLOR = os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def _color(code: str, text: str) -> str:
    if not USE_COLOR:
        return text
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    return f"{colors.get(code, '')}{text}{colors['reset']}"


def print_summary(report: Dict[str, Any]) -> None:
    s = report.get("summary", {})
    recon = report.get("recon", {})

    print()
    print(_color("bold", "=" * 60))
    print(_color("bold", _color("cyan", "  AIMY-SIKLL SCAN REPORT")))
    print(_color("bold", "=" * 60))
    print(f"  Target: {_color('cyan', report.get('target', 'N/A'))}")
    print(f"  Time:   {report.get('elapsed_seconds', 0):.1f}s")
    print()

    print(_color("bold", "  [Recon]"))
    print(f"    Pages crawled:   {recon.get('pages_crawled', 0)}")
    print(f"    Endpoints found: {recon.get('endpoints', 0)}")
    print(f"    Parameters:      {recon.get('params_mined', 0)}")
    print(f"    JS APIs:         {recon.get('js_api_discovered', 0)}")
    print()

    vulns = s.get("vulnerabilities", 0)
    by_type = s.get("by_type", {})
    critical = s.get("critical", False)
    exploit_ready = s.get("exploit_ready", 0)

    status_color = "red" if critical else ("yellow" if vulns > 0 else "green")
    print(_color("bold", f"  [Vulnerabilities] {_color(status_color, str(vulns))}"))

    for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
        label = vt.upper()
        if count >= 3:
            print(f"    {_color('red', label)}: {count}")
        elif count >= 1:
            print(f"    {_color('yellow', label)}: {count}")

    if exploit_ready > 0:
        print(f"    {_color('bold', 'Exploit-ready')}: {_color('red', str(exploit_ready))}")

    if critical:
        print(f"    {_color('red', _color('bold', '*** CRITICAL ***'))}")

    print(_color("bold", "=" * 60))


def print_vuln_detail(result: Dict[str, Any], indent: str = "    ") -> None:
    vuln = result.get("vulnerable", False)
    if not vuln:
        return
    vtype = result.get("type", "unknown")
    evidence = result.get("evidence", [])
    vector = result.get("vector", "")
    dbms = result.get("dbms", "")

    print(f"{indent}{_color('red', 'Type:')} {vtype}")
    if dbms:
        print(f"{indent}{_color('yellow', 'DBMS:')} {dbms}")
    if vector:
        print(f"{indent}{_color('dim', 'Vector:')} {vector[:60]}")
    for ev in evidence[:3]:
        print(f"{indent}{_color('dim', '  -')} {ev[:80]}")
