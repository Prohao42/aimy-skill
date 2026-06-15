import os, signal, sys, time
from typing import Optional, Dict
from tools.log_utils import get_logger
from tools.kali_capture import KaliCapture
from tools.kali_executor import get_kali, is_available, has_tool
from tools.mitm_proxy import start_proxy, stop_proxy, get_proxy

logger = get_logger("packet_capture")


def auto_detect_mode(args) -> str:
    if getattr(args, "proxy", False):
        return "proxy"
    if getattr(args, "capture", False):
        if getattr(args, "kali_local", False):
            return "kali-local"
        if getattr(args, "kali_host", None):
            return "kali-remote"
        _check_self_kali()
        return "kali-local"
    return ""


def _check_self_kali():
    try:
        import subprocess
        r = subprocess.run(["which", "tcpdump"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            logger.info("Auto-detected local tcpdump, using local capture")
            return
    except Exception:
        pass
    logger.warning("No Kali backend specified (--kali-host or --kali-local)")


def run_capture(args) -> Dict:
    mode = auto_detect_mode(args)
    if not mode:
        return {"success": False, "error": "No capture mode. Use --proxy, --capture + --kali-host/--kali-local"}

    if mode == "proxy":
        return _run_proxy(args)
    return _run_kali_capture(args, local=(mode == "kali-local"))


def _run_proxy(args) -> Dict:
    port = getattr(args, "proxy_port", 8080)
    host = getattr(args, "proxy_host", "127.0.0.1")
    duration = getattr(args, "proxy_duration", 0)

    proxy = start_proxy(port=port, host=host)
    ca = proxy.ca_info()

    print(f"\n{'='*60}")
    print(f"  MITM Proxy running on {host}:{port}")
    print(f"  CA cert: {ca['ca_cert']}")
    print(f"  Install CA into browser for HTTPS inspection")
    print(f"{'='*60}\n")
    print(proxy.install_ca_instruction())

    if duration > 0:
        logger.info("Proxy will run for %d seconds...", duration)
        try:
            for remaining in range(duration, 0, -1):
                cnt = len(proxy.get_captured())
                print(f"\r  Captured: {cnt} requests  |  {remaining}s remaining  ", end="")
                time.sleep(1)
            print()
        except KeyboardInterrupt:
            pass
        captured = proxy.get_captured(clear=True)
        stop_proxy()
        return {
            "success": True,
            "mode": "proxy",
            "total_captured": len(captured),
            "captured": captured[:500],
        }
    else:
        print("Press Ctrl+C to stop and dump captured data...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            captured = proxy.get_captured(clear=True)
            stop_proxy()
            return {
                "success": True,
                "mode": "proxy",
                "total_captured": len(captured),
                "captured": captured[:500],
            }


def _run_kali_capture(args, local: bool = False) -> Dict:
    if not is_available():
        return {"success": False, "error": "Kali backend not available"}

    capture = KaliCapture(local=local)
    interface = getattr(args, "capture_iface", "") or None
    count = getattr(args, "capture_count", 1000)
    bpf = getattr(args, "capture_filter", "")
    timeout = getattr(args, "capture_timeout", 60)
    tls_only = getattr(args, "capture_tls", False)
    http_only = getattr(args, "capture_http", False)

    if tls_only:
        logger.info("TLS capture mode")
        return capture.capture_https(interface=interface, count=count, timeout=timeout)
    elif http_only:
        logger.info("HTTP capture mode")
        return capture.capture_http(interface=interface, count=count, timeout=timeout)
    else:
        logger.info("Full capture mode")
        return capture.capture(
            interface=interface,
            count=count,
            bpf_filter=bpf,
            timeout=timeout,
        )


def run_realtime(args):
    if not is_available():
        return {"success": False, "error": "Kali backend not available"}
    local = getattr(args, "kali_local", False)
    capture = KaliCapture(local=local)
    interface = getattr(args, "capture_iface", "") or None
    max_pkts = getattr(args, "capture_count", 100)
    timeout = getattr(args, "capture_timeout", 30)

    logger.info("Realtime HTTP capture on %s ...", interface or "auto")
    entries = capture.live_http(interface=interface, max_packets=max_pkts, timeout=timeout)
    return {
        "success": True,
        "mode": "realtime",
        "total": len(entries),
        "entries": entries,
    }
