import json
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, Optional

from tools.log_utils import get_logger
from tools.version import __version__

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
    return "%s%s%s" % (colors.get(code, ""), text, colors["reset"])


def save_report(report: Dict[str, Any], directory: str = "reports") -> Dict:
    """Persist a scan report as JSON/HTML/SARIF/Markdown. Returns file paths."""
    try:
        os.makedirs(directory, exist_ok=True)
        target = (report.get("target") or "target").split("//")[-1]
        # Windows forbids ? : * " < > | in file names; a URL query would crash the write.
        target = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
        ts = time.strftime("%Y%m%d_%H%M%S")
        base = "%s_%s" % (target, ts)
        json_path = os.path.join(directory, base + ".json")
        html_path = os.path.join(directory, base + ".html")
        sarif_path = os.path.join(directory, base + ".sarif")
        md_path = os.path.join(directory, base + ".md")
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(to_json(report))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(generate_html(report))
        with open(sarif_path, "w", encoding="utf-8") as f:
            f.write(to_json(generate_sarif(report)))
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(generate_markdown(report))
        return {
            "json": json_path,
            "html": html_path,
            "sarif": sarif_path,
            "markdown": md_path,
        }
    except Exception as e:
        logger.warning("save_report failed: %s", e, exc_info=True)
        return {}


def _iter_findings(report: Dict[str, Any]):
    details = report.get("details") or {}
    if isinstance(details, dict):
        for vtype, items in details.items():
            if isinstance(items, list):
                for item in items:
                    yield vtype, item
    elif isinstance(details, list):
        for item in details:
            yield item.get("type", "unknown"), item


def _sarif_level(finding: Dict[str, Any]) -> str:
    score = finding.get("confidence_score", finding.get("confidence", 0)) or 0
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 0.85:
        return "error"
    if score >= 0.6:
        return "warning"
    return "note"


def generate_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 document for CI/code-scanning integrations."""
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for vtype, finding in _iter_findings(report):
        rule_id = "aimy/%s" % vtype
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": vtype,
                "shortDescription": {"text": "aimy-skill %s finding" % vtype},
            },
        )
        url = finding.get("url", report.get("target", ""))
        param = finding.get("param", "")
        score = finding.get("confidence_score", finding.get("confidence", 0)) or 0
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding),
                "message": {
                    "text": "%s at %s%s (confidence=%s)"
                    % (
                        vtype,
                        url,
                        ("?" + param) if param else "",
                        score,
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(url)},
                        }
                    }
                ],
                "properties": {
                    "param": param,
                    "confidence": score,
                    "evidence": finding.get("evidence", []),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aimy-skill",
                        "version": __version__,
                        "informationUri": "https://github.com/Prohao42/aimy-skill",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def generate_markdown(report: Dict[str, Any]) -> str:
    """Render a compact Markdown report suitable for SRC/issues/wiki."""
    summary = report.get("summary", {}) or {}
    lines = [
        "# aimy-skill 扫描报告",
        "",
        "- 目标: `%s`" % report.get("target", "N/A"),
        "- 时间: %s" % report.get("timestamp", ""),
        "- 耗时: %ss" % report.get("elapsed_seconds", 0),
        "- 漏洞数: **%s**" % summary.get("vulnerabilities", 0),
        "- 可利用路径: %s" % summary.get("exploit_ready", 0),
        "- 是否 critical: %s" % summary.get("critical", False),
        "",
        "## 漏洞明细",
        "",
    ]
    rows = list(_iter_findings(report))
    if not rows:
        lines.append("未发现已确认漏洞。")
    for vtype, finding in rows:
        lines.append("### %s" % vtype.upper())
        lines.append("")
        lines.append("- URL: `%s`" % finding.get("url", ""))
        lines.append("- 参数: `%s`" % finding.get("param", ""))
        lines.append(
            "- 置信度: %s" % finding.get("confidence_score", finding.get("confidence", "N/A"))
        )
        evidence = finding.get("evidence", [])
        if evidence:
            lines.append("- 证据:")
            for ev in evidence[:5]:
                lines.append("  - `%s`" % str(ev)[:300])
        lines.append("")
    return "\n".join(lines)


def print_summary(report: Dict[str, Any]) -> None:
    s = report.get("summary", {})
    recon = report.get("recon", {})
    print()
    print(_color("bold", "=" * 60))
    print(_color("bold", _color("cyan", "  aimy-skill SCAN REPORT")))
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


def _format_report_time(value: Any) -> str:
    """Accept epoch numbers and ISO strings (phase_report stores a string)."""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError):
            pass
    if isinstance(value, str) and value.strip():
        return value
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
        vuln_rows += "<tr><td>%s</td><td style='color:%s;font-weight:bold'>%d</td></tr>\n" % (
            vt.upper(),
            color,
            count,
        )

    exploit_str = ""
    if exploit_ready:
        exploit_str = (
            "<p><strong>Exploit-ready:</strong> <span style='color:#dc3545'>%d</span></p>"
            % exploit_ready
        )
        for detail in s.get("exploit_ready_details", []):
            exploit_str += "<p style='margin-left:20px'>&#8594; %s</p>" % _html_escape(str(detail))

    findings_html = ""
    ai_hunt = report.get("ai_hunt", {})
    if ai_hunt:
        brief = ai_hunt.get("brief", "")
        if brief:
            findings_html += (
                "<h3>AI Intelligence Brief</h3><pre style='background:#f8f9fa;padding:10px'>%s</pre>\n"
                % _html_escape(brief)
            )

    details = report.get("details", {})
    for vt, finds in details.items():
        findings_html += "<h3>%s (%d)</h3><ul>\n" % (vt.upper(), len(finds))
        for f in finds[:5]:
            url = _html_escape(f.get("url", ""))
            param = _html_escape(f.get("param", ""))
            conf = f.get("confidence_score", 0)
            findings_html += "<li><a href='%s'>%s</a>?%s (conf=%.2f)</li>\n" % (
                url,
                url,
                param,
                conf,
            )
        findings_html += "</ul>\n"

    context_mem = report.get("context_memory", {})
    ctx_html = ""
    if context_mem:
        ctx_html = "<h3>Context Memory</h3><pre>%s</pre>\n" % _html_escape(
            json.dumps(context_mem, indent=2)
        )

    graph_html = ""
    if report.get("attack_graph"):
        g = report["attack_graph"]
        graph_html = "<h3>Attack Graph</h3><p>Nodes: %d | Edges: %d | Goals: %d</p>\n" % (
            g.get("total_nodes", 0),
            g.get("total_edges", 0),
            len(g.get("goals", [])),
        )

    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<title>aimy-skill Report - %s</title>
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
<div class="footer">Generated by aimy-skill at %s</div>
</body></html>""" % (
        target,
        target,
        elapsed,
        _format_report_time(report.get("timestamp")),
        recon.get("pages_crawled", 0),
        recon.get("endpoints", 0),
        recon.get("params_mined", 0),
        "critical" if critical else ("warning" if vulns > 0 else "ok"),
        vulns,
        ", ".join(recon.get("technologies", [])),
        ", ".join(str(p) for p in recon.get("open_ports", [])),
        exploit_str,
        vuln_rows,
        findings_html,
        ctx_html,
        graph_html,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def generate_html_report(report: Dict, output_path: Optional[str] = None) -> str:
    html = generate_html(report)
    if not output_path:
        output_path = "report_%s.html" % report.get("target", "unknown").replace(
            "://", "_"
        ).replace("/", "_")
    output_path = os.path.abspath(output_path)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    logger.info("HTML report saved to %s", output_path)
    return output_path
