import re
from typing import Optional

from tools.log_utils import get_logger

logger = get_logger("html_context_parser")

PROBE_MARKER = "CTXPROBE_%d"


def probe_and_detect(
    url: str,
    param: str,
    sess,
    timeout: float = 10.0,
    post_body: bool = False,
    post_data: dict = None,
) -> str:
    import random
    from tools.http_client import build_url

    marker = PROBE_MARKER % random.randint(10000, 99999)
    try:
        if post_body and post_data:
            d = post_data.copy()
            d[param] = marker
            resp = sess.post(url, data=d, timeout=timeout)
        else:
            resp = sess.get(
                build_url(url, param, marker), timeout=timeout
            )
        html = resp.text
    except Exception as e:
        logger.debug("probe failed %s?%s: %s", url, param, e)
        return "unknown"

    return detect_context(html, marker)


def detect_context(html: str, marker: str) -> str:
    if marker not in html:
        return "not_reflected"

    pos = html.index(marker)
    before = html[max(0, pos - 300) : pos]
    after = html[pos + len(marker) : pos + len(marker) + 300]

    if _inside_comment(before):
        return "comment"

    if _inside_script(html, pos, before):
        return "script"

    ctx = _check_attr_context(before, after)
    if ctx:
        return ctx

    if _inside_style(before):
        return "style"

    if _inside_event_handler(before):
        return "event_handler"

    return "html"


def _inside_comment(before: str) -> bool:
    last_comment_start = before.rfind("<!--")
    last_comment_end = before.rfind("-->")
    return last_comment_start > last_comment_end


def _inside_script(html: str, pos: int, before: str) -> bool:
    before_script = html[:pos]
    script_starts = [m.end() for m in re.finditer(r"<script[^>]*>", before_script, re.I)]
    script_ends = [m.start() for m in re.finditer(r"</script>", before_script, re.I)]
    if not script_starts:
        return False
    last_start = script_starts[-1]
    last_end = 0
    for e in reversed(script_ends):
        if e < last_start:
            break
        last_end = e
    return last_start > last_end


def _inside_style(before: str) -> bool:
    style_starts = [m.end() for m in re.finditer(r"<style[^>]*>", before, re.I)]
    style_ends = [m.start() for m in re.finditer(r"</style>", before, re.I)]
    if not style_starts:
        return False
    last_start = style_starts[-1]
    last_end = 0
    for e in reversed(style_ends):
        if e < last_start:
            break
        last_end = e
    return last_start > last_end


def _inside_event_handler(before: str) -> bool:
    return bool(
        re.search(
            r"(on\w+\s*=\s*['\"]?)[^'\">]*$", before, re.I
        )
    )


def _check_attr_context(before: str, after: str) -> Optional[str]:
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")

    if last_tag_open <= last_tag_close:
        return None

    double_quotes = before.count('"')
    single_quotes = before.count("'")

    if after.startswith("="):
        return "attr_value_unquoted"

    if double_quotes % 2 == 1:
        if single_quotes % 2 == 1:
            if double_quotes > single_quotes:
                return "attr_double"
            return "attr_single"
        return "attr_double"
    if single_quotes % 2 == 1:
        return "attr_single"

    tag_content = before[last_tag_open + 1 :]
    if re.search(r"\w+\s*=\s*$", tag_content):
        return "attr_value_unquoted"

    return "tag_body"
