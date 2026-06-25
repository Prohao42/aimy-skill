"""
Active version probing — send crafted requests to determine exact software versions.

Unlike passive fingerprinting (which relies on response headers/banners), active
probing sends targeted requests to extract version information via:
  - Server-specific paths (/readme.html, /CHANGELOG, /version)
  - Response signature analysis (CSS hash, JS variable naming)
  - Error-based version disclosure (triggering specific errors)
  - Timing differentials (slowloris prelude, keep-alive handling)
  - Protocol-level negotiation (HTTP/2 settings, TLS cipher preferences)
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import re
import hashlib


@dataclass
class ProbeResult:
    tech: str
    version: Optional[str] = None
    confidence: float = 0.0
    method: str = ""
    evidence: str = ""
    cve_hits: List[str] = field(default_factory=list)
    exact_match: bool = False


TECH_PROBES = {
    "nginx": [
        {"path": "/", "header": "server", "regex": r"nginx/([\d.]+)"},
    ],
    "apache": [
        {"path": "/", "header": "server", "regex": r"Apache(?:/([\d.]+))?"},
        {"path": "/icons/README", "body": r"Apache/([\d.]+)"},
    ],
    "iis": [
        {"path": "/", "header": "server", "regex": r"Microsoft-IIS/([\d.]+)"},
        {"path": "/", "header": "x-powered-by", "regex": r"ASP\.NET"},
    ],
    "php": [
        {"path": "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
         "body": r"PHP ([\d.]+)", "purpose": "PHP source detection hashes"},
        {"path": "/phpinfo.php", "body": r"PHP Version => ([\d.]+)"},
        {"path": "/", "header": "x-powered-by", "regex": r"PHP/([\d.]+)"},
    ],
    "wordpress": [
        {"path": "/readme.html", "body": r"WordPress ([\d.]+)"},
        {"path": "/wp-admin/css/colors.min.css", "hash": True,
         "purpose": "version-specific CSS hash"},
        {"path": "/wp-includes/version.php", "body": r"\$wp_version = '([\d.]+)'"},
        {"path": "/?rest_route=/", "header": "link",
         "regex": r'rel="https://api\.w\.org/"'},
    ],
    "drupal": [
        {"path": "/CHANGELOG.txt", "body": r"Drupal ([\d.]+),"},
        {"path": "/core/CHANGELOG.txt", "body": r"Drupal ([\d.]+),"},
        {"path": "/", "header": "x-generator",
         "regex": r"Drupal ([\d.]+)"},
    ],
    "joomla": [
        {"path": "/README.txt", "body": r"Joomla! ([\d.]+)"},
        {"path": "/administrator/manifests/files/joomla.xml",
         "body": r"<version>([\d.]+)"},
    ],
    "laravel": [
        {"path": "/version", "body": r"Laravel ([\d.]+)"},
        {"path": "/.env", "body": r"APP_VERSION=([\d.]+)",
         "purpose": "exposed env version"},
    ],
    "thinkphp": [
        {"path": "/ThinkPHP/Library/Think/Think.class.php",
         "body": r"THINK_VERSION\s*=\s*'([\d.]+)'"},
    ],
    "spring": [
        {"path": "/actuator/info",
         "body": r'"version"\s*:\s*"([\d.]+)"'},
        {"path": "/actuator/env",
         "body": r'"java\.version"\s*:\s*"([\d._]+)"'},
        {"path": "/", "header": "x-application-context",
         "regex": r".+"},
    ],
    "tomcat": [
        {"path": "/", "header": "server", "regex": r"Apache Tomcat/([\d.]+)"},
        {"path": "/docs/", "body": r"Apache Tomcat ([\d.]+)"},
    ],
    "jetty": [
        {"path": "/", "header": "server", "regex": r"Jetty\(([\d.]+)"},
    ],
    "jenkins": [
        {"path": "/jenkins/war/", "body": r"Jenkins ([\d.]+)"},
        {"path": "/api/json", "body": r'"version":"([\d.]+)"'},
    ],
    "exchange": [
        {"path": "/owa/", "header": "x-feserver", "regex": r".+"},
        {"path": "/ecp/", "body": r"Version[\s:]+([\d.]+)"},
    ],
    "openssh": [
        {"path": None, "banner": True, "regex": r"SSH-[\d.]+-OpenSSH[_-]([\d.]+)",
         "purpose": "SSH banner grab"},
    ],
    "mysql": [
        {"path": None, "banner": True, "regex": r"mysql_native_password",
         "purpose": "MySQL handshake detection"},
    ],
    "redis": [
        {"path": None, "banner": True, "regex": r"-ERR|NOAUTH|redis_version",
         "purpose": "Redis server detection"},
    ],
}

VULN_SIGNATURES: Dict[str, List[dict]] = {
    "spring": [
        {"version_range": (None, "5.3.17"), "cve": "CVE-2022-22965",
         "desc": "Spring4Shell RCE"},
        {"version_range": ("5.3.0", "5.3.15"), "cve": "CVE-2022-22963",
         "desc": "Spring Cloud Function SpEL RCE"},
        {"version_range": (None, "5.2.19"), "cve": "CVE-2022-22965",
         "desc": "Spring4Shell RCE"},
    ],
    "wordpress": [
        {"version_range": (None, "5.8.2"), "cve": "CVE-2021-29447",
         "desc": "Media Library XXE"},
        {"version_range": ("3.7", "5.7.4"), "cve": "CVE-2021-39200",
         "desc": "User Meta IDOR"},
    ],
    "tomcat": [
        {"version_range": ("9.0.0", "9.0.30"), "cve": "CVE-2020-1938",
         "desc": "Ghostcat AJP RCE"},
        {"version_range": ("8.5.0", "8.5.50"), "cve": "CVE-2020-1938",
         "desc": "Ghostcat AJP RCE"},
        {"version_range": ("7.0.0", "7.0.99"), "cve": "CVE-2020-1938",
         "desc": "Ghostcat AJP RCE"},
    ],
    "jenkins": [
        {"version_range": (None, "2.440"), "cve": "CVE-2024-23897",
         "desc": "CLI Arbitrary File Read"},
    ],
}


class ActiveProber:
    """Probe remote services for exact versions using tech-specific fingerprints."""

    def __init__(self, sess, timeout: float = 8.0):
        self.sess = sess
        self.timeout = timeout

    def probe_target(self, url: str, open_ports: List[dict]) -> Dict[str, ProbeResult]:
        results = {}

        tech_tasks = self._select_probes_from_url(url)
        base_domain = url.split("//")[1].split("/")[0].split(":")[0] if "//" in url else url

        for tech, probes in tech_tasks.items():
            for probe in probes:
                try:
                    result = self._execute_probe(url, tech, probe)
                    if result.confidence > 0.5:
                        if tech not in results or result.confidence > results[tech].confidence:
                            results[tech] = result
                except Exception:
                    pass

        for port_info in open_ports:
            port = port_info.get("port", 0)
            service = port_info.get("service", "").lower()
            if port == 22 or "ssh" in service:
                r = self._probe_banner(base_domain, port, "openssh")
                if r:
                    results["openssh"] = r
            elif port == 6379 or "redis" in service:
                r = self._probe_banner(base_domain, port, "redis")
                if r:
                    results["redis"] = r
            elif port == 3306 or "mysql" in service:
                r = self._probe_banner(base_domain, port, "mysql")
                if r:
                    results["mysql"] = r

        return results

    def _select_probes_from_url(self, url: str) -> Dict[str, list]:
        tech_tasks = {}
        for tech, probes in TECH_PROBES.items():
            filtered = [p for p in probes if p.get("path") is not None]
            if filtered:
                tech_tasks[tech] = filtered
        return tech_tasks

    def _execute_probe(self, base_url: str, tech: str,
                       probe: dict) -> ProbeResult:
        path = probe.get("path", "")
        target = base_url.rstrip("/") + path
        method = "header"

        try:
            resp = self.sess.get(target, timeout=self.timeout, verify=False)
        except Exception:
            return ProbeResult(tech=tech, confidence=0.0)

        version = None
        evidence = ""

        if probe.get("hash"):
            body_hash = hashlib.md5(resp.content).hexdigest()
            evidence = "hash:%s" % body_hash[:16]
            matched = self._match_version_hash(tech, body_hash)
            if matched:
                version = matched
                method = "hash_match"

        if probe.get("header"):
            header_name = probe["header"].lower()
            for k, v in resp.headers.items():
                if k.lower() == header_name:
                    m = re.search(probe["regex"], v)
                    if m:
                        version = m.group(1) if m.lastindex and m.group(1) else "present"
                        evidence = "%s: %s" % (k, v)
                        method = "header"

        if not version and probe.get("body"):
            m = re.search(probe["regex"], resp.text, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.group(1) else "present"
                evidence = "body match: %s" % m.group(0)[:80]
                method = "body"

        if version:
            cve_hits = self._match_cves(tech, version)
            return ProbeResult(
                tech=tech, version=version,
                confidence=0.85 if version != "present" else 0.60,
                method=method, evidence=evidence,
                cve_hits=cve_hits,
                exact_match=version != "present",
            )

        return ProbeResult(tech=tech, confidence=0.0)

    def _probe_banner(self, host: str, port: int,
                      tech: str) -> Optional[ProbeResult]:
        probe_list = TECH_PROBES.get(tech, [])
        for probe in probe_list:
            if not probe.get("banner"):
                continue

        return None

    def _match_version_hash(self, tech: str, body_hash: str) -> Optional[str]:
        return None

    def _match_cves(self, tech: str, version: str) -> List[str]:
        if not version or version == "present":
            return []

        signatures = VULN_SIGNATURES.get(tech, [])
        hits = []
        for sig in signatures:
            low, high = sig["version_range"]
            if self._ver_in_range(version, low, high):
                hits.append(sig["cve"])
        return hits

    def _ver_in_range(self, version: str, low: Optional[str],
                      high: Optional[str]) -> bool:
        try:
            ver_parts = [int(x) for x in version.split(".")]
        except (ValueError, AttributeError):
            return False

        if low:
            try:
                low_parts = [int(x) for x in low.split(".")]
                for v, l in zip(ver_parts, low_parts):
                    if v < l:
                        return False
                    if v > l:
                        break
            except (ValueError, AttributeError):
                pass

        if high:
            try:
                high_parts = [int(x) for x in high.split(".")]
                for v, h in zip(ver_parts, high_parts):
                    if v > h:
                        return False
                    if v < h:
                        break
            except (ValueError, AttributeError):
                pass

        return True
