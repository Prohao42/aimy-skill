# security-context-hook.py 

```python
#!/usr/bin/env python3
"""UserPromptSubmit hook for security research scene routing.

v4.0 — LLM intent classification with keyword fallback:
- Default mode (auto): LLM (Haiku) intent classification, fallback to keyword
- CLAUDE_HOOK_MODE=llm|keyword|auto env var to control
- Graceful degradation: any failure passes through original input
- API config read from environment (same as Claude Code settings)
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import urllib.error
from functools import lru_cache

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

HOOK_MODE = os.getenv("CLAUDE_HOOK_MODE", "auto")  # llm | keyword | auto
CLAUDE_MODE = os.getenv("CLAUDE_MODE", "rookie")  # rookie | veteran

API_KEY = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
API_BASE = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
LLM_MODEL = os.getenv("ANTHROPIC_DEFAULT_HAIKU_MODEL", "claude-haiku-4-5-20251001")
LLM_TIMEOUT_S = int(os.getenv("CLAUDE_HOOK_LLM_TIMEOUT", "8"))

DEBUG = os.getenv("CLAUDE_HOOK_DEBUG") == "1"

# ---------------------------------------------------------------------------
# Scene hints (shared by both modes)
# ---------------------------------------------------------------------------

_HINTS_ROOKIE = {
    "ctf": "[security:ctf] 按 CTF 题解流程输出：题型判断、利用思路、验证步骤、必要脚本。以教育为导向，详细解释每步原理与工具用法，提供学习资源链接。",
    "vuln": "[security:vuln] 按漏洞研究流程输出：根因、触发条件、影响、PoC/复现与修复建议。详细解释漏洞原理，提供防御编码示例与检测方法。",
    "pentest": "[security:pentest] 按授权测试流程输出：攻击面、验证步骤、结果记录与风险说明。详细解释每步原理，给出工具命令示例与输出解读。",
    "tool": "[security:tool] 按安全工具开发流程输出：目标、输入输出、模块划分、验证方式。解释设计决策，提供代码示例与测试方法。",
    "audit": "[security:audit] 按代码审计流程输出：入口点、危险流、漏洞点、修复建议。解释审计思路，提供危险函数速查与修复对照。",
    "ir": "[security:ir] 按应急响应流程输出：证据保全、时间线、IOC、处置建议。解释取证工具使用，提供常见 IOC 特征与排查命令。",
    "crypto": "[security:crypto] 按密码学分析流程输出：算法、缺陷、利用条件、验证思路。解释数学原理，提供 SageMath/Python 示例。",
    "reverse": "[security:reverse] 按逆向分析流程输出：关键函数、保护点、行为推断、验证步骤。解释反编译技巧，提供常见保护识别方法。",
}

_HINTS_VETERAN = {
    "ctf": "[security:ctf] 按 CTF 题解流程输出：题型判断、利用思路、验证步骤、必要脚本。专业输出，聚焦高难度题型，低难度题直接给 flag 不提详细步骤。",
    "vuln": "[security:vuln] 按漏洞研究流程输出：根因、触发条件、影响、PoC/复现与修复建议。直接定位漏洞点并给出可用攻击 payload，验证危害后再分析根因。重点是可落地利用，非理论分析。",
    "pentest": "[security:pentest] 按授权测试流程输出：攻击面、验证步骤、结果记录与风险说明。先快速定位可攻击入口点，给出具体利用命令/PoC 并验证效果。按攻击链组织步骤：入口点 → 单点突破 → 横向/纵向扩展 → 获取目标。每一步都要落地，不空谈攻击面。",
    "tool": "[security:tool] 按安全工具开发流程输出：目标、输入输出、模块划分、验证方式。聚焦架构设计与高效实现，不提基础 API 用法。",
    "audit": "[security:audit] 按代码审计流程输出：入口点、危险流、漏洞点、修复建议。先盯危险数据流（用户输入→处理→敏感操作），找到漏洞点直接给出利用方式。逻辑缺陷 > 参数注入，正向追踪比反向搜函数更有效。",
    "ir": "[security:ir] 按应急响应流程输出：证据保全、时间线、IOC、处置建议。聚焦 IOC 提取与根因分析，不提基础操作。",
    "crypto": "[security:crypto] 按密码学分析流程输出：算法、缺陷、利用条件、验证思路。直达数学缺陷与利用条件，不重复算法基础。",
    "reverse": "[security:reverse] 按逆向分析流程输出：关键函数、保护点、行为推断、验证步骤。跳过基础反编译，直接分析关键逻辑与对抗技巧。",
}

GENERAL_HINT_ROOKIE = "[security:general] 安全研究语境；优先给出技术分析、验证路径与防御视角，详细解释每步原理，提供学习资源。"
GENERAL_HINT_VETERAN = "[security:general] 安全研究语境；专业输出，假设已掌握基础，直接给出技术方案与关键验证步骤。专注高质量漏洞，水洞不展开。"


def get_scene_hints() -> tuple[dict, str]:
    if CLAUDE_MODE == "veteran":
        return _HINTS_VETERAN, GENERAL_HINT_VETERAN
    return _HINTS_ROOKIE, GENERAL_HINT_ROOKIE

# ---------------------------------------------------------------------------
# LLM classifier
# ---------------------------------------------------------------------------

_CLASSIFY_PROMPT = (
    "判断用户输入是否属于安全研究场景。\n\n"
    "安全研究场景：CTF竞赛、漏洞分析、渗透测试、代码安全审计、"
    "应急响应/取证/溯源、逆向工程、安全工具开发。\n\n"
    "重要：以下情况不是安全研究，应输出 PASS：\n"
    "- 日常开发任务（优化SQL、部署、调试、重构）\n"
    "- \"exploit\" 表示\"利用机会\"而非漏洞利用（如 exploit caching for performance）\n"
    "- \"audit\" 表示\"数据库审计/查询审计\"而非安全审计（如 audit query plan）\n"
    "- \"payload\" 表示\"HTTP载荷/数据载荷\"而非攻击载荷（如 HTTP request payload）\n"
    "- \"challenge\" 表示\"困难任务\"而非 CTF（如 this challenge is difficult）\n\n"
    "如果是安全研究，输出：INJECT <场景>\n"
    "场景：ctf, vuln, pentest, audit, ir, reverse, tool\n"
    "如果不是安全研究，输出：PASS\n\n"
    "用户输入：{prompt}"
)


def _call_llm(prompt_text: str) -> dict | None:
    """Call LLM API for intent classification. Returns {scene, raw} or None."""
    if not API_KEY:
        return None

    body = json.dumps({
        "model": LLM_MODEL,
        "max_tokens": 32,
        "messages": [{"role": "user", "content": _CLASSIFY_PROMPT.format(prompt=prompt_text)}],
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{API_BASE.rstrip('/')}/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": API_KEY,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw = data["content"][0]["text"].strip().upper()

            if raw.startswith("INJECT"):
                parts = raw.split(None, 1)
                scene = parts[1].strip().lower().strip("<>") if len(parts) > 1 else None
                return {"inject": True, "scene": scene, "raw": raw}

            return {"inject": False, "scene": None, "raw": raw}
    except Exception:
        return None


def classify_llm(prompt_text: str) -> dict | None:
    """Returns {hint: str, mode: str, raw: str} or None on failure."""
    result = _call_llm(prompt_text)
    if result is None:
        return None

    if not result["inject"]:
        return None  # not security research

    hints, general = get_scene_hints()
    scene = result.get("scene")
    hint = hints.get(scene, general) if scene else general
    return {"hint": hint, "mode": "llm", "scene": scene, "raw": result["raw"]}


# ---------------------------------------------------------------------------
# Keyword classifier (fallback)
# ---------------------------------------------------------------------------

SECURITY_PATTERNS = [
    r"\bctf\b", r"\bpwn\b",
    r"\bcve-?\d{4}-\d+\b", r"\bexploit\b", r"\bpoc\b", r"\brce\b",
    r"\bxss\b", r"\bssrf\b", r"\bsqli\b", r"\bdeserialization\b",
    r"sql\s*注入", r"sql\s+injection", r"反序列化", r"漏洞", r"注入", r"复现",
    r"\bpentest\b", r"渗透", r"靶场", r"提权", r"privilege\s*escalation",
    r"域控", r"domain\s*controller",
    r"\baudit\b", r"\bsemgrep\b", r"\bcodeql\b", r"审计", r"白盒", r"静态分析", r"源码审计",
    r"\bforensic\b", r"\bmalware\b", r"\bioc\b",
    r"应急", r"取证", r"溯源", r"木马", r"后门", r"\bbackdoor\b", r"恶意样本",
    r"\bghidra\b", r"\bida\b", r"反汇编",
    r"\bpayload\b", r"\bscanner\b", r"扫描器", r"\bfuzzer\b", r"逆向",
    r"密钥",
]

SCENE_PATTERNS = {
    "ctf": [r"\bctf\b", r"\bflag\b", r"\bchallenge\b", r"\bpwn\b", r"\bmisc\b", r"web题", r"逆向", r"解密"],
    "vuln": [r"\bcve-?\d{4}-\d+\b", r"漏洞", r"\bvuln\b", r"\bpoc\b", r"\bexploit\b", r"复现",
            r"\brce\b", r"\bsqli\b", r"\bxss\b", r"\bssrf\b", r"注入"],
    "pentest": [r"渗透", r"\bpentest\b", r"靶场", r"红队", r"提权", r"privilege\s*escalation",
                r"后渗透", r"横向", r"域控", r"domain\s*controller", r"\bactive directory\b"],
    "tool": [r"扫描器", r"\bscanner\b", r"\bfuzzer\b", r"自动化", r"\bpayloads?\b", r"生成器", r"安全工具"],
    "audit": [r"审计", r"\baudit\b", r"代码审计", r"白盒", r"静态分析", r"\bsemgrep\b", r"\bcodeql\b",
             r"源码", r"sql\s*注入", r"sql\s+injection"],
    "ir": [r"应急", r"\bincident\b", r"取证", r"\bforensic\b", r"溯源", r"\bioc\b",
          r"恶意样本", r"\bmalware\b", r"木马", r"后门", r"\bbackdoor\b"],
    "crypto": [r"加密", r"\bcrypto\b", r"\brsa\b", r"\baes\b", r"\bdes\b", r"\bhash\b", r"签名", r"密钥"],
    "reverse": [r"逆向", r"\breverse\b", r"反汇编", r"\bghidra\b", r"\bida\b", r"调试", r"二进制", r"\bbinary\b"],
}

SCENE_PRIORITY = ["pentest", "vuln", "audit", "ir", "reverse", "crypto", "ctf", "tool"]


@lru_cache(maxsize=1)
def _compiled_security_patterns():
    return [re.compile(p, re.IGNORECASE) for p in SECURITY_PATTERNS]


@lru_cache(maxsize=1)
def _compiled_scene_patterns():
    return {s: [re.compile(p, re.IGNORECASE) for p in ps] for s, ps in SCENE_PATTERNS.items()}


def classify_keyword(prompt_text: str) -> dict | None:
    """Returns {hint, mode, scene} or None if not security."""
    if not any(p.search(prompt_text) for p in _compiled_security_patterns()):
        return None

    hints, general = get_scene_hints()
    compiled = _compiled_scene_patterns()
    scene = None
    for s in SCENE_PRIORITY:
        if any(p.search(prompt_text) for p in compiled.get(s, [])):
            scene = s
            break

    hint = hints.get(scene, general) if scene else general
    return {"hint": hint, "mode": "keyword", "scene": scene}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def classify(prompt_text: str) -> dict | None:
    """Unified classifier. Returns {hint, mode, scene} or None."""
    if HOOK_MODE == "llm":
        result = classify_llm(prompt_text)
        if result:
            return result
        return classify_keyword(prompt_text)  # fallback

    if HOOK_MODE == "keyword":
        return classify_keyword(prompt_text)

    # auto: LLM first, keyword fallback
    if API_KEY:
        result = classify_llm(prompt_text)
        if result is not None:
            return result
    return classify_keyword(prompt_text)


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    raw = ""

    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(raw)
            return

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            print(raw)
            return

        prompt = payload if isinstance(payload, str) else payload.get("prompt", "")
        if not isinstance(prompt, str) or not prompt.strip():
            print(raw)
            return

        result = classify(prompt)
        if result is None:
            print(raw)
            return

        output = {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": result["hint"],
            }
        }

        if DEBUG:
            output["hookSpecificOutput"]["debug"] = (
                f"mode={result['mode']}, scene={result.get('scene', 'general')}"
            )

        print(json.dumps(output, ensure_ascii=False))

    except Exception:
        print(raw if raw else "")
        sys.exit(0)


if __name__ == "__main__":
    main()
```
