import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from tools.log_utils import get_logger

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
    (r"Laravel.*v(\d+\.\d+\.\d+)", "laravel"),
    (r"WebLogic.*?(\d+\.\d+\.\d+)", "weblogic"),
    (r"Apache Struts/(\d+\.\d+\.\d+)", "struts"),
    (r"JBoss/(\d+\.\d+\.\d+)", "jboss"),
    (r"WildFly/(\d+\.\d+\.\d+)", "wildfly"),
]

YEAR_CVE_MAP = {
    "spring": {
        (2022, 2023): ["CVE-2022-22965", "CVE-2022-22950", "CVE-2023-20861", "CVE-2023-20863"],
        (2021, 2022): ["CVE-2022-22965", "CVE-2021-22118", "CVE-2022-22950"],
        (2020, 2021): ["CVE-2021-22118", "CVE-2020-5421"],
        (2019, 2020): ["CVE-2020-5421", "CVE-2019-3774"],
    },
    "thinkphp": {
        (2018, 2019): ["CVE-2018-20062", "CVE-2019-9082"],
        (2019, 2020): ["CVE-2019-9082"],
        (2020, 2022): ["ThinkPHP-RCE-5.0.23", "ThinkPHP-RCE-5.1.31"],
    },
    "weblogic": {
        (2017, 2020): ["CVE-2017-10271", "CVE-2019-2725", "CVE-2019-2729", "CVE-2020-14882"],
        (2020, 2023): ["CVE-2020-14882", "CVE-2020-14883", "CVE-2021-2109"],
    },
    "laravel": {
        (2021, 2022): ["CVE-2021-3129"],
        (2022, 2023): ["CVE-2021-3129"],
    },
    "tomcat": {
        (2020, 2023): ["CVE-2020-1938", "CVE-2020-13935", "CVE-2021-25329"],
    },
    "struts": {
        (2017, 2018): ["CVE-2017-5638", "CVE-2017-9805", "CVE-2017-9804"],
        (2018, 2020): ["CVE-2018-11776"],
    },
    "drupal": {
        (2018, 2019): ["CVE-2018-7600"],
        (2019, 2020): ["CVE-2019-6341"],
    },
    "wordpress": {
        (2019, 2023): ["WP-Plugin-Vulns"],
    },
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
        version = info.version

        if product not in YEAR_CVE_MAP:
            return

        try:
            parts = version.split(".")
            major = int(parts[0])
            year_range = None

            for (start, end), cves in YEAR_CVE_MAP[product].items():
                if start <= 2024:
                    year_range = (start, end)
                    break

            if year_range:
                info.cve_matches = YEAR_CVE_MAP[product][year_range]
                if len(info.cve_matches) >= 2:
                    info.risk_level = "critical"
                elif info.cve_matches:
                    info.risk_level = "high"
        except (ValueError, IndexError):
            pass

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
        resp = sess.get(target, timeout=timeout, verify=False, allow_redirects=True)
        fp.extract_from_headers(dict(resp.headers))
        fp.extract_from_body(resp.text[:5000])
    except Exception as e:
        logger.debug("fingerprint target: %s", e)

    probe_paths = [
        "/", "/index.php", "/login", "/wp-login.php", "/admin",
        "/actuator", "/api", "/graphql", "/.env", "/robots.txt",
        "/server-status", "/server-info", "/phpinfo.php",
    ]
    for path in probe_paths:
        try:
            r = sess.get(target.rstrip("/") + path, timeout=max(3, timeout * 0.5), verify=False)
            fp.extract_from_headers(dict(r.headers))
            fp.extract_from_body(r.text[:3000])
            if r.status_code == 200 and len(r.text) < 500:
                fp.extract_from_path(r.text)
        except Exception:
            continue

    return fp.get_risk_summary()
