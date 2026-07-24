import html
import re
from typing import Dict, List

from tools.log_utils import get_logger

logger = get_logger("semantic_analyzer")

STRUCTURAL_TAGS = {"table", "div", "form", "input", "select", "a", "script", "img",
                    "h1", "h2", "h3", "p", "ul", "li", "span", "section", "article"}


class ResponseSignature:
    def __init__(self, status: int, length: int, structure_hash: str,
                 error_patterns: List[str], content_type: str,
                 title: str = "", keywords: List[str] = None):
        self.status = status
        self.length = length
        self.structure_hash = structure_hash
        self.error_patterns = error_patterns
        self.content_type = content_type
        self.title = title
        self.keywords = keywords or []

    def diff(self, other: "ResponseSignature") -> Dict:
        changes = {}
        if self.status != other.status:
            changes["status"] = (self.status, other.status)
        length_ratio = abs(self.length - other.length) / max(self.length, other.length, 1)
        if length_ratio > 0.01:
            changes["length_ratio"] = round(length_ratio, 3)
        if self.structure_hash != other.structure_hash:
            changes["structure_changed"] = True
        new_errors = [e for e in other.error_patterns if e not in self.error_patterns]
        if new_errors:
            changes["new_errors"] = new_errors
        return changes


def extract_structure(text: str) -> Dict:
    tags = re.findall(r'<(/?)(' + '|'.join(STRUCTURAL_TAGS) + r')([^>]*)>', text, re.I)
    counts = {}
    depth = 0
    max_depth = 0
    for is_close, tag, attrs in tags:
        if not is_close:
            counts[tag.lower()] = counts.get(tag.lower(), 0) + 1
            depth += 1
            max_depth = max(max_depth, depth)
        else:
            depth = max(0, depth - 1)
    form_count = len(re.findall(r'<form[^>]*>', text, re.I))
    input_count = len(re.findall(r'<input[^>]*>', text, re.I))
    script_count = len(re.findall(r'<script[^>]*>', text, re.I))
    return {
        "tag_counts": counts,
        "max_depth": max_depth,
        "form_count": form_count,
        "input_count": input_count,
        "script_count": script_count,
        "total_tags": sum(counts.values()),
    }


def structure_hash(text: str) -> str:
    s = extract_structure(text)
    tag_str = ";".join(f"{k}:{v}" for k, v in sorted(s["tag_counts"].items()))
    return str(hash(tag_str + f"|d{s['max_depth']}|f{s['form_count']}|i{s['input_count']}"))


def extract_error_patterns(text: str) -> List[str]:
    patterns = []
    checks = [
        (r"SQL syntax.*MySQL|Warning.*mysql_|MariaDB", "mysql"),
        (r"Fatal error.*Uncaught.*|Warning.*PHP", "php"),
        (r"org\.springframework\.|java\.lang\.|NullPointerException|ClassCastException", "java_spring"),
        (r"Warning.*pg_|PostgreSQL.*ERROR|psql.*ERROR", "postgresql"),
        (r"Unclosed quotation mark|Microsoft OLE DB|SQL Server.*Error", "mssql"),
        (r"Warning.*oci_|ORA-[0-9]{5}|Oracle.*Driver", "oracle"),
        (r"Traceback.*most recent call|File.*line.*|NameError|TypeError.*", "python"),
        (r"Warning.*SimpleXML|DOMDocument|loadXML.*", "xml_xxe"),
        (r"Parse error|syntax error.*unexpected|unexpected T_", "php_parse"),
        (r"root@|www-data@|ubuntu@", "shell_output"),
        (r"uid=\d+|gid=\d+|groups=\d+", "unix_id"),
        (r"404 Not Found|404 Page|not found", "not_found"),
        (r"500 Internal Server|500 Error|Internal Server Error", "server_error"),
        (r"403 Forbidden|Access Denied|Forbidden", "forbidden"),
        (r"Warning.*file_get_contents|failed to open stream", "file_read_error"),
        (r"Warning.*include\(|require\(.*failed", "include_error"),
    ]
    for pattern, label in checks:
        if re.search(pattern, text, re.I):
            patterns.append(label)
    return patterns


def analyze_single_response(body: str, status: int, content_type: str = "") -> Dict:
    title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.DOTALL)
    title = title_m.group(1).strip() if title_m else ""
    keywords = list(set(re.findall(r'\b([A-Z]\w{3,20})\b', body[:500])))
    return {
        "status": status,
        "length": len(body),
        "title": title,
        "content_type": content_type,
        "keywords": keywords[:20],
        "structure": extract_structure(body),
        "errors": extract_error_patterns(body),
        "hash": structure_hash(body),
    }


def compare_responses(baseline: Dict, probe: Dict) -> Dict:
    changes = {}
    if baseline["status"] != probe["status"]:
        changes["status"] = "%d -> %d" % (baseline["status"], probe["status"])
    length_diff = probe["length"] - baseline["length"]
    length_ratio = abs(length_diff) / max(baseline["length"], 1)
    if length_ratio > 0.01:
        changes["length"] = "%+d (%.1f%%)" % (length_diff, length_ratio * 100)
    if baseline["hash"] != probe["hash"]:
        changes["structure_changed"] = True
        b_tags = baseline.get("structure", {}).get("tag_counts", {})
        p_tags = probe.get("structure", {}).get("tag_counts", {})
        tag_diffs = {}
        for tag in set(list(b_tags.keys()) + list(p_tags.keys())):
            bv = b_tags.get(tag, 0)
            pv = p_tags.get(tag, 0)
            if bv != pv:
                tag_diffs[tag] = "%d->%d" % (bv, pv)
        if tag_diffs:
            changes["tag_diffs"] = tag_diffs
    new_errors = [e for e in probe.get("errors", []) if e not in baseline.get("errors", [])]
    if new_errors:
        changes["new_errors"] = new_errors
    removed_errors = [e for e in baseline.get("errors", []) if e not in probe.get("errors", [])]
    if removed_errors:
        changes["errors_cleared"] = removed_errors

    if changes.get("structure_changed") or new_errors:
        changes["anomaly_score"] = _score_anomaly(changes)
    return changes


def _score_anomaly(changes: Dict) -> float:
    score = 0.0
    if changes.get("new_errors"):
        score += 0.4
    if changes.get("structure_changed"):
        score += 0.3
    if "status" in changes:
        score += 0.2
    length_str = changes.get("length", "")
    if length_str and "(" in str(length_str):
        try:
            ratio_str = str(length_str).split("(")[-1].strip("%)")
            ratio = float(ratio_str) / 100
            if ratio > 0.2:
                score += 0.2
        except (ValueError, IndexError):
            pass
    return min(1.0, score)


def cluster_text_similarity(t1: str, t2: str) -> float:
    lines1 = set(t1.strip().split("\n"))
    lines2 = set(t2.strip().split("\n"))
    if not lines1 or not lines2:
        return 0.0
    intersection = lines1 & lines2
    union = lines1 | lines2
    return len(intersection) / len(union) if union else 0.0


def detect_content_reflection(original_payload: str, response_body: str) -> Dict:
    result = {"reflected": False, "context": None, "positions": []}
    for length in range(min(len(original_payload), 50), 5, -5):
        fragment = original_payload[:length]
        if fragment in response_body:
            escaped_variants = [
                html.escape(fragment),
                fragment.replace("<", "&lt;").replace(">", "&gt;"),
                fragment.replace('"', "&quot;"),
            ]
            for idx in [m.start() for m in re.finditer(re.escape(fragment[:20]), response_body)]:
                window = response_body[idx:idx + len(fragment) + 50]
                is_escaped = any(ev in window for ev in escaped_variants if ev != fragment)
                if not is_escaped and fragment in window:
                    context = _detect_html_context(response_body, idx)
                    result["reflected"] = True
                    result["positions"].append({"offset": idx, "context": context})
                    if len(result["positions"]) >= 3:
                        break
            if result["reflected"]:
                break
    if result["positions"]:
        contexts = [p["context"] for p in result["positions"]]
        result["context"] = max(set(contexts), key=contexts.count) if contexts else "unknown"
    return result


def _detect_html_context(html_text: str, offset: int) -> str:
    before = html_text[max(0, offset - 100):offset]
    if "<script" in before[-50:]:
        return "js"
    if 'onerror=' in before[-50:] or 'onload=' in before[-50:] or 'onfocus=' in before[-50:]:
        return "event_handler"
    if 'href=' in before[-30:] or 'src=' in before[-30:]:
        return "attribute"
    if before.rstrip().endswith("=") or before.rstrip().endswith('"') or before.rstrip().endswith("'"):
        return "attribute_value"
    if ">" not in before[-50:]:
        return "html"
    return "unknown"
