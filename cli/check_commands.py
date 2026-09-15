"""Data-driven command dispatch table for simple check commands.

Replaces ~30 repetitive ``cmd_*`` one-liner functions in ``main.py`` that
follow the pattern:

    from tools.X import check as X_check
    r = X_check(args.url, args.param, _sess(args), args.timeout, ...)
    _output(r)

Each entry in ``COMMAND_SPECS`` declaratively describes how to call the
underlying check function.  ``build_dispatcher`` turns a spec into a
callable ``cmd(args)`` suitable for ``parser.set_defaults(func=...)``.

Special values in the ``args`` / ``kwargs`` maps:
  ``_SESS``  → resolved to the authenticated session via ``sess_fn(args)``
  ``None``   → passed as a Python ``None`` literal
  ``"attr_name"`` → resolved to ``getattr(args, "attr_name", None)``
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

_SESS = object()

_SENTINELS = {_SESS}


@dataclass
class CheckSpec:
    module: str
    func: str
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    post_hook: Optional[Callable] = None


def _resolve(value: Any, args: Any, sess: Any) -> Any:
    if value is _SESS:
        return sess
    if isinstance(value, str):
        return getattr(args, value, None)
    return value


def build_dispatcher(
    spec: CheckSpec,
    sess_fn: Callable,
    output_fn: Callable,
) -> Callable:
    def cmd(args: Any) -> None:
        mod = importlib.import_module(spec.module)
        check = getattr(mod, spec.func)
        sess = sess_fn(args)
        pos = [_resolve(v, args, sess) for v in spec.args]
        kws = {k: _resolve(v, args, sess) for k, v in spec.kwargs.items()}
        result = check(*pos, **kws)
        if spec.post_hook:
            extra = spec.post_hook(args, result, sess)
            if extra is not None:
                output_fn(extra)
        output_fn(result)

    cmd.__name__ = f"cmd_{spec.module.rsplit('.', 1)[-1]}"
    return cmd


COMMAND_SPECS: Dict[str, CheckSpec] = {
    "sqlcheck": CheckSpec(
        "tools.sql_injection", "check", args=["url", "param", _SESS, "timeout", "post", "data"]
    ),
    "xsscheck": CheckSpec(
        "tools.xss_detector",
        "check",
        args=["url", "param", _SESS, "timeout", "post", "data", "context"],
    ),
    "cmdi": CheckSpec("tools.cmdi_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "ssti": CheckSpec("tools.ssti_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "ssrf": CheckSpec("tools.ssrf_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "nosqli": CheckSpec("tools.nosqli_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "lfi": CheckSpec("tools.lfi_scanner", "check", args=["url", "param", _SESS, "timeout"]),
    "sqli-blind": CheckSpec(
        "tools.sqli_blind", "check", args=["url", "param", _SESS, "timeout", "post", "data"]
    ),
    "sqli-oob": CheckSpec(
        "tools.sqli_oob", "check", args=["url", "param", "domain", _SESS, "timeout"]
    ),
    "auth-bypass": CheckSpec("tools.auth_bypass", "check", args=["url", _SESS, "timeout"]),
    "jwt": CheckSpec("tools.jwt_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "graphql": CheckSpec("tools.graphql_scanner", "check", args=["url", None, _SESS, "timeout"]),
    "deser": CheckSpec(
        "tools.deserialization_detector", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "proto-pollution": CheckSpec(
        "tools.proto_pollution", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "xxe": CheckSpec("tools.xxe_detector", "check", args=["url", "param", _SESS, "timeout"]),
    "graphql-abuse": CheckSpec(
        "tools.graphql_abuser", "check", kwargs={"url": "url", "sess": _SESS, "timeout": "timeout"}
    ),
    "jwt-attack": CheckSpec(
        "tools.jwt_attacker",
        "check",
        kwargs={"url": "url", "sess": _SESS, "timeout": "timeout", "token": "token"},
    ),
    "verify": CheckSpec(
        "tools.second_order_verifier", "check", args=["url", "param", "vuln_type", _SESS, "timeout"]
    ),
    "cors": CheckSpec("tools.cors_scanner", "check", args=["url", None, _SESS, "timeout"]),
    "bizlogic": CheckSpec(
        "tools.biz_logic_scanner", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "waf-heavy": CheckSpec(
        "tools.waf_bypass", "heavy_check", args=["url", "param", _SESS, "timeout"]
    ),
    "xss-validate": CheckSpec(
        "tools.xss_validator", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "waf": CheckSpec("tools.waf_bypass", "check", args=["url", "param", _SESS, "timeout"]),
    "sqli-weaponize": CheckSpec(
        "tools.sqli_weaponizer", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "sqli-second-order": CheckSpec(
        "tools.second_order_sqli", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "dom-xss": CheckSpec(
        "tools.dom_xss", "check", kwargs={"url": "url", "sess": _SESS, "timeout": "timeout"}
    ),
    "jwt-exploit": CheckSpec(
        "tools.jwt_exploiter",
        "check",
        kwargs={
            "url": "url",
            "param": "param",
            "token": "token",
            "sess": _SESS,
            "timeout": "timeout",
        },
    ),
    "ssrf-pwn": CheckSpec("tools.ssrf_pwn", "check", args=["url", "param", _SESS, "timeout"]),
    "deser-weaponize": CheckSpec(
        "tools.deser_weaponizer",
        "check",
        kwargs={"url": "url", "param": "param", "sess": _SESS, "timeout": "timeout"},
    ),
    "reverse-shell": CheckSpec("tools.reverse_shell", "run", args=["lhost", "lport", "encode"]),
    "ssrf-lateral": CheckSpec("tools.ssrf_pwn", "run", args=["url", "param", _SESS, "timeout"]),
    "crawl": CheckSpec(
        "tools.crawler", "crawl", args=["target", "depth", "max_pages", _SESS, "timeout"]
    ),
    "weakpass": CheckSpec(
        "tools.weakpass",
        "check",
        kwargs={
            "url": "url",
            "timeout": "timeout",
            "delay": "delay",
            "max_attempts": "max_attempts",
            "api_url": "api_url",
            "user_field": "user_field",
            "pass_field": "pass_field",
        },
    ),
    "race": CheckSpec("tools.race_condition", "check", args=["url", "param", _SESS, "timeout"]),
    "race-profile": CheckSpec(
        "tools.race_profiler", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "workflow-trace": CheckSpec(
        "tools.workflow_tracer",
        "check",
        kwargs={
            "base_url": "url",
            "sess": _SESS,
            "timeout": "timeout",
        },
    ),
    "deviation": CheckSpec(
        "tools.deviation_oracle", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "constraint": CheckSpec(
        "tools.constraint_graph", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "bizlogic-v2": CheckSpec(
        "tools.biz_logic_v2", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "xss-verify": CheckSpec(
        "tools.xss_browser_verify",
        "check",
        args=["url", "param", _SESS, "timeout"],
    ),
    "auth-default-creds": CheckSpec(
        "tools.auth_bypass", "check_default_creds", args=["url", _SESS, "timeout"]
    ),
    "auth-cookie-tamper": CheckSpec(
        "tools.auth_bypass", "check_cookie_tamper", args=["url", _SESS, "timeout"]
    ),
    "auth-header-injection": CheckSpec(
        "tools.auth_bypass", "check_header_injection", args=["url", _SESS, "timeout"]
    ),
    "auth-method-bypass": CheckSpec(
        "tools.auth_bypass", "check_method_bypass", args=["url", _SESS, "timeout"]
    ),
    "auth-mass-assignment": CheckSpec(
        "tools.auth_bypass", "check_mass_assignment", args=["url", _SESS, "timeout"]
    ),
    "chain-sqli-lfi": CheckSpec(
        "tools.cross_validator",
        "validate_sqli_with_lfi",
        args=["url", "param", _SESS, "timeout"],
    ),
    "chain-sqli-auth": CheckSpec(
        "tools.cross_validator",
        "validate_auth_with_sqli",
        args=["url", "param", _SESS, "timeout"],
    ),
    "chain-ssrf-lfi": CheckSpec(
        "tools.cross_validator",
        "validate_ssrf_with_lfi",
        args=["url", "param", _SESS, "timeout"],
    ),
    "smuggle": CheckSpec("tools.smuggler", "check", args=["url", "param", _SESS, "timeout"]),
    "clickjacking": CheckSpec("tools.clickjacking", "check", args=["url", _SESS, "timeout"]),
    "crlf-injection": CheckSpec(
        "tools.crlf_injection", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "open-redirect": CheckSpec(
        "tools.open_redirect", "check", args=["url", "param", _SESS, "timeout"]
    ),
    "hpp": CheckSpec("tools.hpp", "check", args=["url", "param", _SESS, "timeout"]),
    "web-cache": CheckSpec("tools.web_cache", "check", args=["url", _SESS, "timeout"]),
    "file-upload": CheckSpec("tools.file_upload", "check", args=["url", "param", _SESS, "timeout"]),
    "saml-sso": CheckSpec("tools.saml_sso", "check", args=["url", "param", _SESS, "timeout"]),
}
