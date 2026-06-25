import re, time, random, string, threading, socket, struct
from typing import Optional
import requests

from tools.log_utils import get_logger
from tools.http_client import build_url
from tools.payload_engine import generate
from tools.settings import settings

logger = get_logger("cmdi_detector")

OUTPUT_INDICATORS = [
    (r"uid=\d+\([\w]+\)", "id_output"),
    (r"gid=\d+\([\w]+\)", "id_output"),
    (r"groups?=\d+\([\w]+\)", "id_output"),
    (r"Microsoft Windows", "os"),
    (r"NT AUTHORITY", "os"),
    (r"root:[^:]+:\d+:\d+", "passwd"),
    (r"www-data", "user"),
    (r"bin/bash", "shell"),
    (r"bin/sh", "shell"),
    (r"cmd\.exe", "os"),
    (r"command not found", "exec_error"),
    (r"is not recognized", "exec_error"),
    (r"\d+ bytes from", "network"),
    (r"time[<=]\d+", "network"),
    (r"PING |ping statistics", "network"),
    (r"Linux", "os"),
    (r"DIR |dir.*Volume", "directory"),
    (r"total \d+", "directory"),
    (r"drwxr|xr-x", "directory"),
]

CLEAN_VALUE = "CMDI_NOMINAL_000"


class _OobServer:
    def __init__(self, timeout=6.0):
        self.port = 0
        self.timeout = timeout
        self.caught = threading.Event()
        self._sock = None
        self._thread = None
        self._lan_ip = self._get_lan_ip()

    def _get_lan_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(("0.0.0.0", 0))
            self._sock.settimeout(self.timeout)
            self.port = self._sock.getsockname()[1]
        except OSError:
            return None, None
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        oob_domain = "%s.%s.%s.oob" % (token, self._lan_ip.replace(".", "-"), self.port)
        oob_url = "http://%s:%d/" % (self._lan_ip, self.port)
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        return oob_url, oob_domain

    def _listen(self):
        while not self.caught.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
                self.caught.set()
            except socket.timeout:
                break
            except Exception:
                break

    def stop(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass


def _measure_baseline_timing(url, param, sess, timeout):
    samples = []
    for _ in range(2):
        try:
            start = time.time()
            sess.get(build_url(url, param, CLEAN_VALUE), timeout=timeout)
            samples.append(time.time() - start)
        except Exception:
            pass
    if not samples:
        return 0.3
    return sum(samples) / len(samples)


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0, waf_name: Optional[str] = None,
          oob_url: Optional[str] = None,
          oob_domain: Optional[str] = None) -> dict:
    if sess is None:
        sess = requests.Session()
        sess.verify = settings.verify_ssl
    result = {"vulnerable": False, "type": None, "evidence": [], "payload": None,
              "oob_tested": False}

    output_seeds = generate("cmdi", "output", "all", waf_name)
    for entry in output_seeds:
        payload = entry["payload"]
        indicator = entry.get("indicator")
        try:
            r = sess.get(build_url(url, param, payload), timeout=timeout)
            if indicator and indicator in r.text:
                result["vulnerable"] = True
                result["type"] = "output"
                result["evidence"].append("cmdi: %s => %s" % (payload[:15], indicator))
                result["payload"] = payload
                return result
            for pat, label in OUTPUT_INDICATORS:
                if re.search(pat, r.text):
                    result["vulnerable"] = True
                    result["type"] = "output"
                    result["evidence"].append("cmdi: %s matched <%s>" % (payload[:15], label))
                    result["payload"] = payload
                    return result
        except Exception as e:
            logger.debug("cmdi payload %s: %s", payload[:15], e)

    if not result["vulnerable"]:
        baseline_sec = _measure_baseline_timing(url, param, sess, timeout)
        if baseline_sec >= timeout * 0.8:
            return result
        threshold = max(2.5, baseline_sec * 1.5 + 2.0)

        time_seeds = generate("cmdi", "time", "all", waf_name)
        for entry in time_seeds:
            payload = entry["payload"]
            try:
                start = time.time()
                sess.get(build_url(url, param, payload), timeout=timeout + 3)
                elapsed = time.time() - start
                if elapsed >= threshold:
                    result["vulnerable"] = True
                    result["type"] = "time"
                    result["evidence"].append("cmdi time: %s => %.1fs (baseline=%.1fs)" % (
                        payload[:15], elapsed, baseline_sec))
                    result["payload"] = payload
                    return result
            except requests.Timeout:
                pass
            except Exception as e:
                logger.debug("cmdi time %s: %s", payload[:15], e)

    if not result["vulnerable"]:
        oob_server = _OobServer(timeout=min(timeout, 6.0))
        auto_oob_url, auto_oob_domain = oob_server.start()
        cb_url = oob_url or auto_oob_url
        cb_domain = oob_domain or auto_oob_domain

        if cb_domain:
            result["oob_tested"] = True
            templates = [
                "nslookup %s" if cb_domain else "",
                "ping -c 1 %s" if cb_domain else "",
                "curl %s" if cb_url else "",
                "wget %s" if cb_url else "",
            ]
            for tpl in templates:
                if not tpl:
                    continue
                payload = tpl % (cb_domain or cb_url)
                try:
                    sess.get(build_url(url, param, payload), timeout=timeout)
                except Exception:
                    pass

            if oob_server.caught.wait(timeout=min(timeout, 6.0)):
                result["vulnerable"] = True
                result["type"] = "oob_callback"
                result["evidence"].append("cmdi OOB: DNS/HTTP callback received")
                result["payload"] = templates[0] % (cb_domain or cb_url)

        oob_server.stop()

    return result
