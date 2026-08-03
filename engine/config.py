"""判定引擎集中配置：所有阈值参数化于此，杜绝散落的绝对判据。

相对基线差分一律用「比率/倍数」，零散绝对值 (响应字节数、关键词命中数、
陈旧秒数) 收归此处，便于统一调参与环境覆盖。
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Thresholds:
    # --- 相对基线差分 (比率/倍数，禁用绝对值判据) ---
    length_diff_ratio_strong: float = 0.20
    length_diff_ratio: float = 0.08
    length_diff_ratio_weak: float = 0.03
    latency_ratio: float = 1.5
    latency_floor_s: float = 2.0
    latency_margin_s: float = 1.5
    latency_margin_ms: float = 500.0

    # --- 证据分层 ---
    min_confidence: float = 0.5
    min_evidence: int = 2

    # --- 响应噪声过滤 (绝对值集中于此) ---
    min_response_bytes: int = 50
    min_signature_bytes: int = 20
    noise_keyword_hits: int = 3
    stale_seconds: int = 3600

    # --- 布尔差分最小绝对偏移 (辅助，仍以相对比率为主要判据) ---
    min_abs_length_diff: int = 30

    # --- 复现性 ---
    reproducibility_samples: int = 3
    reproduction_cap: float = 0.55

    # --- OOB / 离线判定 ---
    oob_callback_wait_s: float = 2.0
    offline_oob_ceiling: float = 0.6


DEFAULT_THRESHOLDS = Thresholds()

# 相关证据归族：同一机制的多条证据视为相关，组内取 max，绝不叠加。
# 顺序敏感：越靠前的族越具体，先命中先归类。
EVIDENCE_FAMILIES = {
    "boolean_diff": ["bool_", "bool", "true_false", "length_gap", "multi_bool", "single_bool"],
    "time_delay": [
        "time_", "time", "delay", "sleep", "timeout", "elapsed", "latency",
        "multi_time", "single_time",
    ],
    "output_indicator": [
        "output_", "indicator", "json_diff", "regex_diff", "error_",
        "multi_output", "single_output",
    ],
    "reflection": ["reflect", "trigger", "payload_ratio", "context_", "unescaped"],
    "oob_callback": ["oob_", "callback", "disclosure", "dns", "http_"],
    "content_signature": [
        "etc_passwd", "win_ini", "root:", "wrapper", "phar", "pearcmd",
        "log_poison", "rce_", "file_",
    ],
    "extraction": ["data_extracted", "multi_field", "error_extract", "dbms_identified"],
    "reproducibility": ["multi_confirmed", "confirmed", "reproduced", "multi_", "single_"],
}
