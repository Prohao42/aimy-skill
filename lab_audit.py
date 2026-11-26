"""Quantitative acceptance for the legacy core subset of the hardened lab.

The full 25-case matrix, including SSRF/JWT/deserialization, lives in
``bench/profiles/lab.yml`` and is the authoritative benchmark used by CI.
"""

import sys
import time

sys.path.insert(0, ".")

from tools import (
    cmdi_detector,
    lfi_scanner,
    nosqli_detector,
    sql_injection,
    ssti_detector,
    xss_detector,
)
from tools._session import make_session

BASE = "http://127.0.0.1:18774"
sess = make_session()

# (label, url, param, detector_fn, expected_vulnerable, kwargs)
CASES = [
    ("sqli_error", BASE + "/sqli_error", "id", sql_injection.check, True, {}),
    ("sqli_bool", BASE + "/sqli_bool", "id", sql_injection.check, True, {}),
    ("sqli_union", BASE + "/sqli_union", "id", sql_injection.check, True, {}),
    (
        "sqli_post",
        BASE + "/sqli_post",
        "id",
        sql_injection.check,
        True,
        {"post_body": True, "post_data": {"id": "1"}},
    ),
    ("xss_reflect", BASE + "/xss_reflect", "q", xss_detector.check, True, {}),
    ("xss_attr", BASE + "/xss_attr", "q", xss_detector.check, True, {}),
    ("xss_js", BASE + "/xss_js", "q", xss_detector.check, True, {}),
    (
        "xss_post",
        BASE + "/xss_post",
        "q",
        xss_detector.check,
        True,
        {"post_body": True, "post_data": {"q": "1"}},
    ),
    ("cmdi", BASE + "/cmdi", "cmd", cmdi_detector.check, True, {}),
    ("ssti", BASE + "/ssti", "name", ssti_detector.check, True, {}),
    ("ssti_alt", BASE + "/ssti_alt", "name", ssti_detector.check, True, {}),
    ("lfi", BASE + "/lfi", "file", lfi_scanner.check, True, {}),
    ("lfi_hardened", BASE + "/lfi_hardened", "file", lfi_scanner.check, True, {}),
    ("nosql", BASE + "/nosql", "id", nosqli_detector.check, True, {}),
    ("nosqli_get", BASE + "/nosqli_get", "id", nosqli_detector.check, True, {}),
    ("clean_sqli", BASE + "/clean_sqli", "q", sql_injection.check, False, {}),
    ("clean_xss", BASE + "/clean_xss", "q", xss_detector.check, False, {}),
    ("clean_attr", BASE + "/clean_attr", "q", xss_detector.check, False, {}),
    ("clean_ssti", BASE + "/clean_ssti", "name", ssti_detector.check, False, {}),
]

report = []
for label, url, param, fn, expected, kwargs in CASES:
    start = time.time()
    try:
        r = fn(url, param, sess=sess, timeout=5, **kwargs)
        detected = bool(r.get("vulnerable"))
    except Exception as e:
        detected = False
        r = {"error": str(e)[:60]}
    elapsed = round(time.time() - start, 1)
    vtype = r.get("type", "")
    verdict = (
        "TP"
        if (detected and expected)
        else (
            "FP" if (detected and not expected) else ("FN" if (not detected and expected) else "TN")
        )
    )
    report.append(
        {
            "case": label,
            "expected": expected,
            "detected": detected,
            "type": vtype,
            "verdict": verdict,
            "time_s": elapsed,
        }
    )

tps = [r for r in report if r["verdict"] == "TP"]
fps = [r for r in report if r["verdict"] == "FP"]
fns = [r for r in report if r["verdict"] == "FN"]
tns = [r for r in report if r["verdict"] == "TN"]
vuln_total = sum(1 for r in CASES if r[4])
clean_total = sum(1 for r in CASES if not r[4])

print("=" * 78)
print("AIMY-SKILL QUANTITATIVE ACCEPTANCE (%d-endpoint hardened lab)" % len(CASES))
print("=" * 78)
for r in report:
    mark = {"TP": "OK  ", "TN": "OK  ", "FP": "!!  ", "FN": "MISS"}[r["verdict"]]
    print(
        "  [%s] %-14s expected=%-5s detected=%-5s type=%-16s %.1fs"
        % (mark, r["case"], r["expected"], r["detected"], r["type"] or "-", r["time_s"])
    )
print("-" * 78)
print(
    "  True positives : %d/%d  (detection rate %.0f%%)"
    % (len(tps), vuln_total, 100.0 * len(tps) / max(1, vuln_total))
)
print("  True negatives : %d/%d  (no false positives on clean endpoints)" % (len(tns), clean_total))
print("  False positives: %d   False negatives: %d" % (len(fps), len(fns)))
print("  Overall accuracy: %.0f%%" % (100.0 * (len(tps) + len(tns)) / len(CASES)))
print("=" * 78)
sys.exit(0 if not fps and not fns else 1)
