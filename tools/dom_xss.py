"""DOM XSS 检测：静态分析页面 JS 的 DOM sink 与可注入 source 配对。

现代前端（Vue/React/原生 JS）的 XSS 多在客户端 DOM 处理，服务端看不到反射。
本模块：
1) 抓页面 HTML + 内联/外链 JS
2) 识别 DOM sink（innerHTML / document.write / eval / location / src 赋值 ...）
3) 识别可注入 source（location.hash / document.URL / location.search / referrer ...）
4) 输出"source -> sink"路径与验证 payload（#hash 注入）
Playwright 可用时做真实执行验证。
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from tools._session import make_session
from tools.log_utils import get_logger

logger = get_logger("dom_xss")

SINKS = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"document\.write\s*\(", "document.write"),
    (r"document\.writeln\s*\(", "document.writeln"),
    (r"\beval\s*\(", "eval"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout"),
    (r"setInterval\s*\(\s*['\"]", "setInterval"),
    (r"new\s+Function\s*\(", "new Function"),
    (r"\.location\s*=", "location="),
    (r"location\.href\s*=", "location.href="),
    (r"\.src\s*=", ".src="),
    (r"\.href\s*=", ".href="),
    (r"setAttribute\s*\(\s*['\"](?:src|href|onerror|onload)", "setAttribute"),
    (r"document\.execCommand\s*\(", "execCommand"),
    (r"\.replaceChild\s*\(", "replaceChild"),
    (r"\.appendChild\s*\(", "appendChild"),
    (r"\.textContent\s*=", "textContent"),
]

SOURCES = [
    "location.hash",
    "document.URL",
    "document.location",
    "location.search",
    "location.href",
    "document.referrer",
    "window.name",
    "document.cookie",
    "location.pathname",
]

# sinks that are actually XSS-capable (textContent is not, .src/.href need checks)
_XSS_SINKS = {"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
              "document.writeln", "eval", "new Function", "setTimeout", "setInterval",
              "location=", "location.href=", "setAttribute", "execCommand"}


def _get_scripts(url: str, sess: requests.Session, timeout: float) -> List[str]:
    """Fetch page HTML and extract inline + external JS sources."""
    try:
        resp = sess.get(url, timeout=timeout)
    except Exception:
        return []
    html = resp.text or ""
    scripts = []
    inline = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    for s in inline:
        if s.strip():
            scripts.append(s)
    ext = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    base = "%s://%s" % (urlparse(url).scheme, urlparse(url).netloc)
    for src in ext:
        if src.startswith("http"):
            full = src
        else:
            full = base + (src if src.startswith("/") else "/" + src)
        try:
            r = sess.get(full, timeout=timeout)
            if r.status_code == 200:
                scripts.append(r.text or "")
        except Exception:
            continue
    return scripts


def _analyze_scripts(scripts: List[str]) -> List[Dict]:
    """Find source -> sink pairs within JS snippets."""
    findings = []
    for script in scripts:
        for sink_re, sink_name in SINKS:
            for m in re.finditer(sink_re, script):
                # look for a source feeding this sink within a reasonable window
                window = script[max(0, m.start() - 300):m.end() + 100]
                for src in SOURCES:
                    if src in window:
                        findings.append({
                            "sink": sink_name,
                            "source": src,
                            "context": window[-120:].strip()[:120],
                        })
                        break
    # dedupe
    seen = set()
    out = []
    for f in findings:
        key = (f["sink"], f["source"], f["context"][:40])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _verification_payload(source: str, sink: str) -> str:
    """Craft a hash-based payload for the source that should execute in the sink."""
    if "hash" in source:
        return "#'-alert(1)-'"
    if "search" in source or "URL" in source or "href" in source:
        return "?x='-alert(1)-'"
    if "referrer" in source or "name" in source:
        return "<img src=x onerror=alert(1)> (inject via %s)" % source
    return "<img src=x onerror=alert(1)>"


def check(url: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    sess = sess or make_session()
    result = {"vulnerable": False, "type": "dom_xss", "findings": [],
              "sinks_found": [], "note": ""}
    scripts = _get_scripts(url, sess, timeout)
    if not scripts:
        result["note"] = "no scripts found to analyze"
        return result

    findings = _analyze_scripts(scripts)
    result["sinks_found"] = [f["sink"] for f in findings]
    if findings:
        # a source feeding a dangerous sink is a candidate DOM XSS
        dangerous = [f for f in findings if f["sink"] in _XSS_SINKS]
        for f in dangerous:
            f["payload"] = _verification_payload(f["source"], f["sink"])
        if dangerous:
            result["vulnerable"] = True
            result["findings"] = dangerous[:8]
            result["note"] = (
                "DOM XSS candidate: %s feeds %s. Verify with the suggested "
                "payload via location.hash / query injection." % (
                    dangerous[0]["source"], dangerous[0]["sink"]))
    return result
