import re
from typing import Dict

from tools.log_utils import get_logger

logger = get_logger("enrich")


def enrich_sqli(result: Dict, url: str, param: str, response_text: str = "",
                response_status: int = 0, elapsed: float = 0.0) -> Dict:
    result["_url"] = url
    result["_param"] = param
    result["_response_summary"] = {
        "status": response_status,
        "length": len(response_text),
        "elapsed": round(elapsed, 3),
    }
    if not result.get("vulnerable") and response_text:
        hints = []
        error_patterns = [
            (r"SQL syntax.*MySQL", "MySQL syntax error"),
            (r"Warning.*mysql_", "MySQL warning"),
            (r"ORA-\d{5}", "Oracle error"),
            (r"PostgreSQL.*ERROR", "PostgreSQL error"),
            (r"Microsoft OLE DB", "MSSQL OLE DB error"),
            (r"unclosed quotation mark", "MSSQL unclosed quote"),
            (r"SQLite/JDBCDriver", "SQLite error"),
            (r"driver.*SQL\_", "Generic SQL driver error"),
            (r"Division by zero", "Division by zero in SQL"),
        ]
        for pat, label in error_patterns:
            if re.search(pat, response_text, re.IGNORECASE):
                hints.append(label)
        if hints:
            result["_sql_hints"] = hints
            result["_ai_advice"] = f"Response contains SQL error patterns: {hints}. Consider trying time-based blind or UNION injection."
    if result.get("vulnerable") and result.get("type"):
        type_advice = {
            "boolean_blind": "Confirms vulnerable. Next step: use sqli_weaponizer to extract data via UNION.",
            "time_blind": "Confirmed via time delay. Use sqli_weaponizer with --blind for data extraction.",
            "error_based": "Error-based injection confirmed. Try UNION extraction next.",
            "union": "UNION injection works. Proceed with sqli_weaponizer for full data dump.",
        }
        result["_ai_advice"] = type_advice.get(result["type"], "SQL injection confirmed. Consider weaponization.")
    result["_next_steps"] = ["sqli_weaponizer", "sqlmap"] if result.get("vulnerable") else []
    return result


def enrich_xss(result: Dict, url: str, param: str, response_text: str = "",
               response_status: int = 0) -> Dict:
    result["_url"] = url
    result["_param"] = param
    result["_response_summary"] = {"status": response_status, "length": len(response_text)}
    if result.get("vulnerable"):
        contexts = []
        if re.search(r'<script[^>]*>.*' + re.escape(param), response_text, re.I):
            contexts.append("script_block")
        for attr in ["src", "href", "onerror", "onload", "onclick"]:
            if attr in response_text[:3000]:
                contexts.append(f"attr_{attr}")
        result["_xss_contexts"] = contexts
        result["_ai_advice"] = f"XSS confirmed in contexts: {contexts}. Try browser validation with xss-validate."
        result["_next_steps"] = ["xss-validate", "xss-browser-verify"]
    return result


def enrich_ssrf(result: Dict, url: str, param: str, response_text: str = "",
                response_status: int = 0, elapsed: float = 0.0) -> Dict:
    result["_url"] = url
    result["_param"] = param
    result["_response_summary"] = {"status": response_status, "length": len(response_text), "elapsed": round(elapsed, 3)}
    if result.get("vulnerable"):
        cloud_hints = []
        for cloud, patterns in {"aws": ["ami-", "instance-id", "security-credentials"],
                                 "gcp": ["google", "computeMetadata"],
                                 "azure": ["azure", "vmId"]}.items():
            if any(p in response_text for p in patterns):
                cloud_hints.append(cloud)
        if cloud_hints:
            result["_cloud_provider"] = cloud_hints
            result["_ai_advice"] = f"Cloud metadata accessible: {cloud_hints}. Use ssrf-pwn for credential extraction."
        if "file://" in str(result.get("payload", "")):
            result["_ai_advice"] = "File read via SSRF confirmed. Try reading /proc/self/environ for secrets."
        result["_next_steps"] = ["ssrf-pwn", "ssrf-lateral"]
    return result


def enrich_generic(result: Dict, url: str = "", param: str = "",
                   response_status: int = 0, response_length: int = 0,
                   detector_type: str = "") -> Dict:
    result.setdefault("_url", url)
    result.setdefault("_param", param)
    result.setdefault("_response_summary", {"status": response_status, "length": response_length})
    if result.get("vulnerable") and not result.get("_next_steps"):
        result["_next_steps"] = ["verify", f"weaponize-{detector_type}"] if detector_type else ["verify"]
    return result


def deep_check(check_fn, url: str, param: str, sess, timeout: float,
               detector_type: str = "generic") -> Dict:
    result = check_fn(url, param, sess, timeout)
    if not isinstance(result, dict):
        return {"vulnerable": False, "_error": "non-dict result"}
    if not result.get("vulnerable"):
        alt_params = [param.upper(), param.lower(), param + "[]",
                       param.replace("id", "ID"), param.replace("_", "")]
        for alt in set(alt_params):
            if alt == param:
                continue
            try:
                r2 = check_fn(url, alt, sess, timeout)
                if isinstance(r2, dict) and r2.get("vulnerable"):
                    result["vulnerable"] = True
                    result["type"] = r2.get("type", result.get("type"))
                    result["_found_via_alt_param"] = alt
                    result["evidence"] = result.get("evidence", []) + r2.get("evidence", [])
                    break
            except Exception:
                continue
    return result
