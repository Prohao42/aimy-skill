#!/usr/bin/env python3
"""aimy-skill 真实基准验收运行器 (ground-truth driven)。

用法:
    # DVWA (需先起靶场, 见 bench/README.md)
    python bench/run_bench.py --profile dvwa --base-url http://127.0.0.1:8080

    # 内置 mock 靶场冒烟 (harness 自验证, 先跑 python lab_server.py)
    python bench/run_bench.py --profile lab

评分: TP / FP / FN / TN 四象限 + 按漏洞类召回率 + precision/recall/F1 + 耗时。
产出: reports/bench_<profile>_<ts>.json / .md
"""
import argparse
import json
import os
import sys
import time
from urllib.parse import urlencode

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import (  # noqa: E402
    cmdi_detector,
    lfi_scanner,
    nosqli_detector,
    sql_injection,
    ssti_detector,
    xss_detector,
)
from tools._session import make_session  # noqa: E402

DETECTORS = {
    "sqli": sql_injection.check,
    "xss": xss_detector.check,
    "cmdi": cmdi_detector.check,
    "lfi": lfi_scanner.check,
    "ssti": ssti_detector.check,
    "nosqli": nosqli_detector.check,
}

BENIGN_VALUE = {"sqli": "1", "xss": "hello", "cmdi": "127.0.0.1",
                "lfi": "include.php", "ssti": "world", "nosqli": "1"}


def build_request(case, base_url):
    """从 case 构造 (url, kwargs)。"""
    url = base_url.rstrip("/") + case["path"]
    kwargs = {}
    extra = dict(case.get("extra_query") or {})
    method = (case.get("method") or "GET").upper()
    if method == "GET":
        q = {case["param"]: case.get("value", BENIGN_VALUE.get(case["vuln_class"], "1"))}
        q.update(extra)
        url = url + "?" + urlencode(q)
    else:  # POST
        post_data = dict(case.get("post_data") or {case["param"]: "1"})
        kwargs["post_body"] = True
        kwargs["post_data"] = post_data
        if extra:
            url = url + "?" + urlencode(extra)
    return url, kwargs


def run_case(case, sess, timeout):
    fn = DETECTORS[case["vuln_class"]]
    url, kwargs = build_request(case, case["_base_url"])
    try:
        r = fn(url, case["param"], sess=sess, timeout=timeout, **kwargs)
        return bool(r.get("vulnerable")), r.get("type", ""), None
    except TypeError:
        # 个别检测器不接受 post_body/post_data -> 降级为 GET 语义报错标注
        return False, "", "detector does not support POST contract"
    except Exception as e:
        return False, "", "%s: %s" % (type(e).__name__, str(e)[:80])


def verdict(detected, expected):
    if detected and expected:
        return "TP"
    if detected and not expected:
        return "FP"
    if not detected and expected:
        return "FN"
    return "TN"


def metrics(results):
    tps = [r for r in results if r["verdict"] == "TP"]
    fps = [r for r in results if r["verdict"] == "FP"]
    fns = [r for r in results if r["verdict"] == "FN"]
    tns = [r for r in results if r["verdict"] == "TN"]
    precision = len(tps) / max(1, len(tps) + len(fps))
    recall = len(tps) / max(1, len(tps) + len(fns))
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    by_class = {}
    for r in results:
        c = by_class.setdefault(r["vuln_class"], {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        c[r["verdict"].lower()] += 1
    return {"tp": len(tps), "fp": len(fps), "fn": len(fns), "tn": len(tns),
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3), "by_class": by_class}


def render_markdown(profile, results, m, skipped):
    lines = ["# aimy-skill 基准验收报告 (profile: %s)" % profile, "",
             "| 指标 | 值 |", "|---|---|",
             "| TP | %d |" % m["tp"],
             "| FP | %d |" % m["fp"],
             "| FN | %d |" % m["fn"],
             "| TN | %d |" % m["tn"],
             "| Precision (精确率) | %.1f%% |" % (100 * m["precision"]),
             "| Recall (检出率) | %.1f%% |" % (100 * m["recall"]),
             "| F1 | %.3f |" % m["f1"], "",
             "## 按漏洞类", "", "| 漏洞类 | TP | FP | FN | TN |", "|---|---|---|---|---|"]
    for cls, c in sorted(m["by_class"].items()):
        lines.append("| %s | %d | %d | %d | %d |" % (cls, c["tp"], c["fp"], c["fn"], c["tn"]))
    lines += ["", "## 用例明细", "",
              "| 判定 | 用例 | 级别 | 漏洞类 | 期望 | 检出 | 类型 | 耗时s | 备注 |",
              "|---|---|---|---|---|---|---|---|---|"]
    mark = {"TP": "✅", "TN": "✅", "FP": "❌", "FN": "❌"}
    for r in results:
        lines.append("| %s%s | %s | %s | %s | %s | %s | %s | %.1f | %s |" % (
            mark[r["verdict"]], r["verdict"], r["name"], r["level"],
            r["vuln_class"], r["expected"], r["detected"],
            r["type"] or "-", r["time_s"], (r["error"] or r.get("note", "") or "-")[:60]))
    if skipped:
        lines += ["", "## 跳过用例 (契约外)", "",
                  "| 用例 | 级别 | 原因 |", "|---|---|---|"]
        for s in skipped:
            lines.append("| %s | %s | %s |" % (s["name"], s["level"], s.get("skip_reason", "-")))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="aimy-skill benchmark runner")
    ap.add_argument("--profile", default="dvwa", help="profiles/ 下的清单名 (dvwa/lab)")
    ap.add_argument("--base-url", default=None, help="覆盖清单中的 base_url")
    ap.add_argument("--levels", default="low,medium,high", help="DVWA 要跑的安全级别")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out", default="reports")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="password")
    ap.add_argument("--fail-on-fp", action="store_true", help="存在 FP 时退出码为 1")
    args = ap.parse_args()

    prof_path = os.path.join(os.path.dirname(__file__), "profiles", args.profile + ".yml")
    with open(prof_path, encoding="utf-8") as f:
        prof = yaml.safe_load(f)
    base_url = (args.base_url or prof["base_url"]).rstrip("/")
    cases = [c for c in prof["cases"] if not c.get("status")]
    skipped = [c for c in prof["cases"] if c.get("status")]

    # ---- 会话准备 ----
    dvwa = None
    if prof.get("requires_login"):
        from bench.dvwa_client import connect
        print("[*] DVWA 连接: %s (user=%s)" % (base_url, args.user))
        dvwa = connect(base_url, args.user, args.password)
        print("[*] 登录成功")
        plain_sess = None
    else:
        plain_sess = make_session()

    want_levels = [l.strip() for l in args.levels.split(",") if l.strip()]

    # ---- 逐级别执行 ----
    results = []
    levels_in_profile = sorted({c.get("level", "any") for c in cases})
    for level in levels_in_profile:
        if level != "any" and level not in want_levels:
            continue
        level_cases = [c for c in cases if c.get("level", "any") == level]
        if not level_cases:
            continue
        if dvwa is not None:
            dvwa.set_security(level)
            sess = dvwa.sess
            print("[*] 安全级别已切换到 %s (%d 用例)" % (level, len(level_cases)))
        else:
            sess = plain_sess
            print("[*] 执行 %d 用例" % len(level_cases))

        for case in level_cases:
            case["_base_url"] = base_url
            t0 = time.time()
            detected, vtype, err = run_case(case, sess, args.timeout)
            elapsed = round(time.time() - t0, 1)
            v = verdict(detected, case["expected"])
            results.append({
                "name": case["name"], "level": case.get("level", "any"),
                "vuln_class": case["vuln_class"], "expected": case["expected"],
                "detected": detected, "type": vtype, "verdict": v,
                "time_s": elapsed, "error": err, "note": case.get("note", ""),
            })
            tag = {"TP": "OK  ", "TN": "OK  ", "FP": "!!FP", "FN": "MISS"}[v]
            print("  [%s] %-20s lvl=%-6s %-6s exp=%-5s got=%-5s type=%-14s %.1fs%s" % (
                tag, case["name"], case.get("level", "any"), case["vuln_class"],
                case["expected"], detected, vtype or "-", elapsed,
                ("  " + err) if err else ""))

    # ---- 汇总 ----
    m = metrics(results)
    print("=" * 84)
    print("  TP=%d  FP=%d  FN=%d  TN=%d" % (m["tp"], m["fp"], m["fn"], m["tn"]))
    print("  Precision=%.1f%%  Recall(检出率)=%.1f%%  F1=%.3f" % (
        100 * m["precision"], 100 * m["recall"], m["f1"]))
    for cls, c in sorted(m["by_class"].items()):
        print("    %-8s recall=%s  fp=%d" % (
            cls, "%d/%d" % (c["tp"], c["tp"] + c["fn"]), c["fp"]))
    print("=" * 84)

    os.makedirs(args.out, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    payload = {"profile": args.profile, "base_url": base_url,
               "timestamp": ts, "metrics": m, "results": results,
               "skipped": skipped}
    jpath = os.path.join(args.out, "bench_%s_%s.json" % (args.profile, ts))
    mpath = os.path.join(args.out, "bench_%s_%s.md" % (args.profile, ts))
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    with open(mpath, "w", encoding="utf-8") as f:
        f.write(render_markdown(args.profile, results, m, skipped))
    print("[*] 报告: %s / %s" % (jpath, mpath))

    if args.fail_on_fp and m["fp"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
