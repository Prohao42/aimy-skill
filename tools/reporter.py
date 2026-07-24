import json
import os
import time
from datetime import datetime
from typing import Any, Dict, Optional

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
    colors = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
              "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
              "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}
    return "%s%s%s" % (colors.get(code, ""), text, colors["reset"])


def print_summary(report: Dict[str, Any]) -> None:
    s = report.get("summary", {})
    recon = report.get("recon", {})
    print()
    print(_color("bold", "=" * 60))
    print(_color("bold", _color("cyan", "  AIMY-SIKLL SCAN REPORT")))
    print(_color("bold", "=" * 60))
    print("  Target: %s" % _color("cyan", report.get("target", "N/A")))
    print("  Time:   %.1fs" % report.get("elapsed_seconds", 0))
    print()
    print(_color("bold", "  [Recon]"))
    print("    Pages crawled:   %d" % recon.get("pages_crawled", 0))
    print("    Endpoints found: %d" % recon.get("endpoints", 0))
    print("    Parameters:      %d" % recon.get("params_mined", 0))
    print("    JS APIs:         %d" % recon.get("js_api_discovered", 0))
    print()
    vulns = s.get("vulnerabilities", 0)
    by_type = s.get("by_type", {})
    critical = s.get("critical", False)
    exploit_ready = s.get("exploit_ready", 0)
    status_color = "red" if critical else ("yellow" if vulns > 0 else "green")
    print(_color("bold", "  [Vulnerabilities] %s" % _color(status_color, str(vulns))))
    for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
        label = vt.upper()
        print("    %s: %d" % (_color("red" if count >= 3 else "yellow", label), count))
    if exploit_ready > 0:
        print("    %s: %s" % (_color("bold", "Exploit-ready"), _color("red", str(exploit_ready))))
    if critical:
        print("    %s" % _color("red", _color("bold", "*** CRITICAL ***")))
    print(_color("bold", "=" * 60))


def print_vuln_detail(result: Dict[str, Any], indent: str = "    ") -> None:
    vuln = result.get("vulnerable", False)
    if not vuln:
        return
    vtype = result.get("type", "unknown")
    evidence = result.get("evidence", [])
    vector = result.get("vector", "")
    dbms = result.get("dbms", "")
    print("%s%s %s" % (indent, _color("red", "Type:"), vtype))
    if dbms:
        print("%s%s %s" % (indent, _color("yellow", "DBMS:"), dbms))
    if vector:
        print("%s%s %s" % (indent, _color("dim", "Vector:"), vector[:60]))
    for ev in evidence[:3]:
        print("%s%s %s" % (indent, _color("dim", "  -"), ev[:80]))


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_html(report: Dict) -> str:
    s = report.get("summary", {})
    recon = report.get("recon", {})
    target = _html_escape(report.get("target", "N/A"))
    elapsed = report.get("elapsed_seconds", 0)
    vulns = s.get("vulnerabilities", 0)
    by_type = s.get("by_type", {})
    exploit_ready = s.get("exploit_ready", 0)
    critical = s.get("critical", False)

    vuln_rows = ""
    for vt, count in sorted(by_type.items(), key=lambda x: -x[1]):
        color = "#dc3545" if count >= 3 else "#ffc107"
        vuln_rows += "<tr><td>%s</td><td style='color:%s;font-weight:bold'>%d</td></tr>\n" % (vt.upper(), color, count)

    exploit_str = ""
    if exploit_ready:
        exploit_str = "<p><strong>Exploit-ready:</strong> <span style='color:#dc3545'>%d</span></p>" % exploit_ready
        for detail in s.get("exploit_ready_details", []):
            exploit_str += "<p style='margin-left:20px'>&#8594; %s</p>" % _html_escape(str(detail))

    findings_html = ""
    ai_hunt = report.get("ai_hunt", {})
    if ai_hunt:
        brief = ai_hunt.get("brief", "")
        if brief:
            findings_html += "<h3>AI Intelligence Brief</h3><pre style='background:#f8f9fa;padding:10px'>%s</pre>\n" % _html_escape(brief)

    details = report.get("details", {})
    for vt, finds in details.items():
        findings_html += "<h3>%s (%d)</h3><ul>\n" % (vt.upper(), len(finds))
        for f in finds[:5]:
            url = _html_escape(f.get("url", ""))
            param = _html_escape(f.get("param", ""))
            conf = f.get("confidence_score", 0)
            findings_html += "<li><a href='%s'>%s</a>?%s (conf=%.2f)</li>\n" % (url, url, param, conf)
        findings_html += "</ul>\n"

    context_mem = report.get("context_memory", {})
    ctx_html = ""
    if context_mem:
        ctx_html = "<h3>Context Memory</h3><pre>%s</pre>\n" % _html_escape(json.dumps(context_mem, indent=2))

    graph_html = ""
    if report.get("attack_graph"):
        g = report["attack_graph"]
        graph_html = "<h3>Attack Graph</h3><p>Nodes: %d | Edges: %d | Goals: %d</p>\n" % (
            g.get("total_nodes", 0), g.get("total_edges", 0), len(g.get("goals", [])))

    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>AIMY-SIKLL Report - %s</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:20px;color:#333;background:#fff}
h1{color:#1a1a2e;border-bottom:3px solid #e94560;padding-bottom:5px}
h2{color:#16213e;margin-top:30px}
table{border-collapse:collapse;width:50%%;margin:10px 0}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd}
th{background:#1a1a2e;color:#fff}
pre{background:#f5f5f5;padding:10px;border-radius:4px;overflow-x:auto}
.critical{color:#dc3545;font-weight:bold}
.warning{color:#ffc107;font-weight:bold}
.ok{color:#28a745}
.footer{margin-top:40px;padding-top:10px;border-top:1px solid #ddd;font-size:12px;color:#666}
a{color:#007bff}
</style></head>
<body>
<h1>AIMY-SIKLL Security Report</h1>
<p><strong>Target:</strong> %s</p>
<p><strong>Duration:</strong> %.1fs</p>
<p><strong>Timestamp:</strong> %s</p>
<h2>Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Pages Crawled</td><td>%d</td></tr>
<tr><td>Endpoints Found</td><td>%d</td></tr>
<tr><td>Parameters Mined</td><td>%d</td></tr>
<tr><td>Vulnerabilities</td><td class="%s">%d</td></tr>
<tr><td>Technologies</td><td>%s</td></tr>
<tr><td>Open Ports</td><td>%s</td></tr>
</table>
%s
<h2>Vulnerabilities by Type</h2>
<table><tr><th>Type</th><th>Count</th></tr>%s</table>
%s
<h2>Details</h2>
%s
%s
<div class="footer">Generated by aimy-sikll at %s</div>
</body></html>""" % (
        target, target, elapsed,
        datetime.fromtimestamp(report.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S"),
        recon.get("pages_crawled", 0), recon.get("endpoints", 0), recon.get("params_mined", 0),
        "critical" if critical else ("warning" if vulns > 0 else "ok"),
        vulns,
        ", ".join(recon.get("technologies", [])),
        ", ".join(str(p) for p in recon.get("open_ports", [])),
        exploit_str, vuln_rows, findings_html, ctx_html, graph_html,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def generate_html_report(report: Dict, output_path: Optional[str] = None) -> str:
    html = generate_html(report)
    if not output_path:
        output_path = "report_%s.html" % report.get("target", "unknown").replace("://", "_").replace("/", "_")
    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("HTML report saved to %s", output_path)
    return output_path


def _output(data: Any):
    if isinstance(data, dict) and "summary" in data:
        print_summary(data)
        try:
            hpath = generate_html_report(data)
            print("HTML report: %s" % hpath)
        except Exception as e:
            logger.debug("html report: %s", e)
    else:
        print(to_json(data, indent=2))
