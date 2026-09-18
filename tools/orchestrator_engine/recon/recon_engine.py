"""Recon Engine: 信息收集阶段。

薄委托层 —— 真实实现位于 tools/recon/ 包
(dir_fuzzer / git_leak / port_scanner / subdomain / tech_fingerprint)，
本模块仅作为 orchestrator 的稳定入口，保持调用签名与返回结构
(interesting / resolved / http_reachable / open_count / git_exposed /
sensitive_finds / technologies) 与 orchestrator 各阶段一致。
"""

from tools.recon.dir_fuzzer import fuzz_directories
from tools.recon.git_leak import check_git_leak
from tools.recon.port_scanner import scan_ports
from tools.recon.subdomain import COMMON_SUBDOMAINS, enum_subdomains
from tools.recon.tech_fingerprint import fingerprint_tech

__all__ = [
    "COMMON_SUBDOMAINS",
    "check_git_leak",
    "enum_subdomains",
    "fingerprint_tech",
    "fuzz_directories",
    "scan_ports",
]
