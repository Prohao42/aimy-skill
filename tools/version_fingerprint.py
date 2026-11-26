import re
from dataclasses import dataclass, field
from typing import Dict, List

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("version_fingerprint")

VERSION_PATTERNS = [
    (r"(?:Spring|spring-boot|spring-cloud)[/\s]+v?(\d+\.\d+\.\d+)", "spring"),
    (r"Apache Tomcat/(\d+\.\d+\.\d+)", "tomcat"),
    (r"PHP/(\d+\.\d+\.\d+)", "php"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
    (r"Apache/(\d+\.\d+\.\d+)", "apache"),
    (r"WordPress (\d+\.\d+\.\d+)", "wordpress"),
    (r"Drupal (\d+\.\d+\.\d+)", "drupal"),
    (r"Laravel Framework (\d+\.\d+\.\d+)", "laravel"),
    (r"Django/(\d+\.\d+)", "django"),
    (r"Express", "express"),
    (r"WebLogic Server/(\d+\.\d+\.\d+)", "weblogic"),
    (r"ThinkPHP/V(\d+\.\d+\.\d+)", "thinkphp"),
    (r"X-Powered-By:\s*Express", "express"),
    (r"X-AspNet-Version:\s*(\d+\.\d+\.\d+)", "aspnet"),
    (r"X-AspNetMvc-Version:\s*(\d+\.\d+)", "aspnet_mvc"),
    (r"Server:\s*Microsoft-IIS/(\d+\.\d+)", "iis"),
    (r"OpenResty/(\d+\.\d+\.\d+)", "openresty"),
    (r"Caddy", "caddy"),
    (r"LiteSpeed/(\d+\.\d+\.\d+)", "litespeed"),
    (r"HAPROXY/(\d+\.\d+)", "haproxy"),
    (r"Varnish/(\d+\.\d+)", "varnish"),
    (r"Jetty\((\d+\.\d+\.\d+)", "jetty"),
    (r"Undertow/(\d+\.\d+\.\d+)", "undertow"),
    (r"Gunicorn/(\d+\.\d+\.\d+)", "gunicorn"),
    (r"uWSGI/(\d+\.\d+\.\d+)", "uwsgi"),
    (r"MongoDB (\d+\.\d+\.\d+)", "mongodb"),
    (r"PostgreSQL (\d+\.\d+)", "postgresql"),
    (r"MySQL (\d+\.\d+\.\d+)", "mysql"),
    (r"Redis v=(\d+\.\d+\.\d+)", "redis"),
    (r"Elasticsearch (\d+\.\d+\.\d+)", "elasticsearch"),
    (r"Solr/(\d+\.\d+\.\d+)", "solr"),
]

ERROR_VERSION_PATTERNS = [
    (r"Apache Tomcat/(\d+\.\d+\.\d+)", "tomcat"),
    (r"PHP (\d+\.\d+\.\d+) .* on line (\d+)", "php"),
    (r"Microsoft OLE DB Provider for (\w+) (\d+\.\d+)", "mssql"),
    (r"PostgreSQL (\d+\.\d+\.\d+)", "postgresql"),
    (r"MySQL (\d+\.\d+\.\d+)-MariaDB", "mariadb"),
    (r"MySQL (\d+\.\d+\.\d+)", "mysql"),
    (r"SQLite (\d+\.\d+\.\d+)", "sqlite"),
    (r"ThinkPHP.*V(\d+\.\d+\.\d+)", "thinkphp"),
    (r"Laravel.*?v?(\d+\.\d+\.\d+)", "laravel"),
    (r"WebLogic.*?(\d+\.\d+\.\d+)", "weblogic"),
    (r"Apache Struts/(\d+\.\d+\.\d+)", "struts"),
    (r"JBoss/(\d+\.\d+\.\d+)", "jboss"),
    (r"WildFly/(\d+\.\d+\.\d+)", "wildfly"),
]

# 显式受影响版本区间；区间两端均为闭区间，版本按三段数值比较。
# 不把主版本号当成年份猜测 CVE，避免“Tomcat 9 / Spring 5 永远无漏洞”的漏报。
VERSION_CVE_RANGES = {
    "spring": [
        ((5, 3, 0), (5, 3, 17), ["CVE-2022-22965"]),
        ((5, 2, 0), (5, 2, 19), ["CVE-2022-22965"]),
    ],
    "tomcat": [
        ((9, 0, 0), (9, 0, 30), ["CVE-2020-1938"]),
        ((8, 5, 0), (8, 5, 50), ["CVE-2020-1938"]),
        ((7, 0, 0), (7, 0, 99), ["CVE-2020-1938"]),
    ],
    "laravel": [
        ((6, 0, 0), (8, 4, 2), ["CVE-2021-3129"]),
    ],
    "struts": [
        ((2, 3, 5), (2, 3, 31), ["CVE-2017-5638"]),
        ((2, 5, 0), (2, 5, 10), ["CVE-2017-5638"]),
    ],
    "drupal": [
        ((7, 0, 0), (7, 57, 0), ["CVE-2018-7600"]),
        ((8, 0, 0), (8, 3, 8), ["CVE-2018-7600"]),
        ((8, 4, 0), (8, 4, 5), ["CVE-2018-7600"]),
    ],
}


@dataclass
class VersionInfo:
    product: str
    version: str
    source: str
    confidence: float = 0.9
    cve_matches: List[str] = field(default_factory=list)
    risk_level: str = "unknown"


class VersionFingerprint:
    def __init__(self):
        self.versions: List[VersionInfo] = []
        self._matched = set()

    def extract_from_headers(self, headers: Dict[str, str]) -> List[VersionInfo]:
        results = []
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        for pattern, product in VERSION_PATTERNS:
            m = re.search(pattern, header_str, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else "detected"
                key = f"{product}:{version}"
                if key not in self._matched:
                    self._matched.add(key)
                    info = VersionInfo(product=product, version=version, source="header")
                    self._match_cve(info)
                    results.append(info)
                    self.versions.append(info)
        return results

    def extract_from_body(self, body: str) -> List[VersionInfo]:
        results = []
        for pattern, product in ERROR_VERSION_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else "detected"
                key = f"{product}:{version}"
                if key not in self._matched:
                    self._matched.add(key)
                    info = VersionInfo(product=product, version=version, source="body/error")
                    self._match_cve(info)
                    results.append(info)
                    self.versions.append(info)
        return results

    def extract_from_path(self, path_content: str) -> List[VersionInfo]:
        results = []
        for pattern, product in VERSION_PATTERNS:
            m = re.search(pattern, path_content, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex else "detected"
                key = f"{product}:{version}"
                if key not in self._matched:
                    self._matched.add(key)
                    info = VersionInfo(product=product, version=version, source="path_response")
                    self._match_cve(info)
                    results.append(info)
                    self.versions.append(info)
        return results

    def _match_cve(self, info: VersionInfo):
        product = info.product.lower()
        ranges = VERSION_CVE_RANGES.get(product)
        if not ranges:
            return

        parts = re.findall(r"\d+", info.version)
        if len(parts) < 2:
            return
        version = tuple(int(part) for part in parts[:3])
        version = version + (0,) * (3 - len(version))

        matched = []
        for start, end, cves in ranges:
            if start <= version <= end:
                matched.extend(cves)
        if matched:
            info.cve_matches = sorted(set(matched))
            info.risk_level = "critical" if len(info.cve_matches) >= 2 else "high"

    def get_risk_summary(self) -> Dict:
        critical = [v for v in self.versions if v.risk_level == "critical"]
        high = [v for v in self.versions if v.risk_level == "high"]
        return {
            "total_versions": len(self.versions),
            "critical": len(critical),
            "high": len(high),
            "versions": [
                {
                    "product": v.product,
                    "version": v.version,
                    "source": v.source,
                    "risk": v.risk_level,
                    "cves": v.cve_matches,
                }
                for v in self.versions
            ],
            "critical_versions": [
                {"product": v.product, "version": v.version, "cves": v.cve_matches}
                for v in critical
            ],
        }


def fingerprint_target(target: str, sess, timeout: float = 10.0) -> Dict:
    fp = VersionFingerprint()

    try:
        resp = sess.get(target, timeout=timeout, verify=settings.verify_ssl, allow_redirects=True)
        fp.extract_from_headers(dict(resp.headers))
        fp.extract_from_body(resp.text[:5000])
    except Exception as e:
        logger.debug("fingerprint target: %s", e)

    probe_paths = [
        "/",
        "/index.php",
        "/login",
        "/wp-login.php",
        "/admin",
        "/actuator",
        "/api",
        "/graphql",
        "/.env",
        "/robots.txt",
        "/server-status",
        "/server-info",
        "/phpinfo.php",
    ]
    for path in probe_paths:
        try:
            r = sess.get(
                target.rstrip("/") + path, timeout=max(3, timeout * 0.5), verify=settings.verify_ssl
            )
            fp.extract_from_headers(dict(r.headers))
            fp.extract_from_body(r.text[:3000])
            if r.status_code == 200 and len(r.text) < 500:
                fp.extract_from_path(r.text)
        except Exception:
            continue

    return fp.get_risk_summary()
