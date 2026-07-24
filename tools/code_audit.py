import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("code_audit")


@dataclass
class AuditFinding:
    file: str
    line: int
    severity: str
    rule_id: str
    description: str
    code_snippet: str
    recommendation: str
    cwe: Optional[str] = None


LANG_CONFIGS = {
    ".php": {
        "name": "PHP",
        "rules": {
            "SQL_INJECTION": {
                "patterns": [
                    r'(?:mysql|mysqli|pgsql|sqlite|oci)_query\s*\(\s*\$',
                    r'\$.*->query\s*\(\s*\$',
                    r'SELECT\s+.*\s+FROM\s+.*\$\s*\{?\s*',
                    r'WHERE\s+.*=\s*\$_\s*(?:GET|POST|REQUEST|SERVER)',
                    r'exec\s*\(\s*\$',
                    r'pg_query\s*\(\s*\$',
                ],
                "severity": "critical",
                "cwe": "CWE-89",
                "rec": "Use prepared statements (PDO) instead of string concatenation",
            },
            "COMMAND_INJECTION": {
                "patterns": [
                    r'shell_exec\s*\(\s*\$',
                    r'exec\s*\(\s*\$',
                    r'system\s*\(\s*\$',
                    r'passthru\s*\(\s*\$',
                    r'popen\s*\(\s*\$',
                    r'`\s*\$',
                    r'eval\s*\(\s*\$',
                    r'assert\s*\(\s*\$',
                ],
                "severity": "critical",
                "cwe": "CWE-78",
                "rec": "Avoid shell functions with user input; use escapeshellarg() if unavoidable",
            },
            "FILE_OPERATION": {
                "patterns": [
                    r'include\s*\(\s*\$',
                    r'require\s*\(\s*\$',
                    r'include_once\s*\(\s*\$',
                    r'require_once\s*\(\s*\$',
                    r'fopen\s*\(\s*\$',
                    r'file_get_contents\s*\(\s*\$',
                    r'unlink\s*\(\s*\$',
                    r'file_put_contents\s*\(\s*\$',
                ],
                "severity": "high",
                "cwe": "CWE-98",
                "rec": "Validate and sanitize file paths; avoid direct user input in file operations",
            },
            "XSS": {
                "patterns": [
                    r'echo\s+\$_\s*(?:GET|POST|REQUEST|SERVER)',
                    r'print\s+\$_\s*(?:GET|POST|REQUEST|SERVER)',
                    r'echo\s+\$[a-z_]+\s*(?![;(])',
                ],
                "severity": "high",
                "cwe": "CWE-79",
                "rec": "Use htmlspecialchars() with ENT_QUOTES for all output",
            },
            "DESERIALIZATION": {
                "patterns": [
                    r'unserialize\s*\(\s*\$',
                ],
                "severity": "critical",
                "cwe": "CWE-502",
                "rec": "Use json_decode() instead of unserialize() for untrusted data",
            },
            "SSRF": {
                "patterns": [
                    r'curl_exec\s*\(\s*\$',
                    r'file_get_contents\s*\(\s*\$',
                    r'fsockopen\s*\(\s*\$',
                ],
                "severity": "high",
                "cwe": "CWE-918",
                "rec": "Validate URLs against allowlist; block internal IP ranges",
            },
        },
    },
    ".java": {
        "name": "Java",
        "rules": {
            "SQL_INJECTION": {
                "patterns": [
                    r'Statement\s+\w+\s*=\s*.*\+',
                    r'createStatement\s*\(\s*\)\s*.*execute',
                    r'\.exec(?:ute)?Query\s*\(\s*"[^"]*\+\s*\w',
                    r'@Query\s*\(\s*value\s*=\s*"[^"]*:\s*\)',
                ],
                "severity": "critical", "cwe": "CWE-89",
                "rec": "Use prepared statements (PreparedStatement) with parameterized queries",
            },
            "COMMAND_INJECTION": {
                "patterns": [
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'ProcessBuilder\s*\([^)]*\$?\w*\s*\+',
                ],
                "severity": "critical", "cwe": "CWE-78",
                "rec": "Avoid Runtime.exec() with user input; use ProcessBuilder with safe args",
            },
            "DESERIALIZATION": {
                "patterns": [
                    r'ObjectInputStream\s*',
                    r'readObject\s*\(',
                    r'XMLDecoder\s*\(',
                    r'SnakeYAML.*load\s*\(',
                    r'Jackson.*enableDefaultTyping',
                ],
                "severity": "critical", "cwe": "CWE-502",
                "rec": "Validate serialized data; use safe deserialization libraries",
            },
            "XXE": {
                "patterns": [
                    r'DocumentBuilderFactory\.newInstance\s*\(',
                    r'SAXParser',
                    r'SAXReader',
                    r'XMLReader',
                    r'javax\.xml\.parsers',
                ],
                "severity": "high", "cwe": "CWE-611",
                "rec": "Disable external entity processing: setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
            },
            "PATH_TRAVERSAL": {
                "patterns": [
                    r'new\s+File\s*\(\s*\$?\w*\s*\+',
                    r'getAbsolutePath\s*\(',
                    r'getCanonicalPath\s*\(',
                ],
                "severity": "high", "cwe": "CWE-22",
                "rec": "Canonicalize and validate paths; block '..' sequences",
            },
        },
    },
    ".py": {
        "name": "Python",
        "rules": {
            "COMMAND_INJECTION": {
                "patterns": [
                    r'os\.system\s*\(',
                    r'os\.popen\s*\(',
                    r'subprocess\.call\s*\(.*shell=True',
                    r'subprocess\.Popen\s*\(.*shell=True',
                    r'eval\s*\(',
                    r'exec\s*\(',
                    r'__import__\s*\(',
                    r'pickle\.loads?\s*\(',
                ],
                "severity": "critical", "cwe": "CWE-78",
                "rec": "Use subprocess.run() with shell=False and argument lists",
            },
            "SQL_INJECTION": {
                "patterns": [
                    r"execute\s*\(\s*f[" + "'" + r"]",
                    r"execute\s*\(\s*[" + "'" + r'][^"' + "'" + r"]*%[sd]",
                    r'\.format\s*\(.*\)\s*.*execute',
                    r"cursor\.execute\s*\(\s*[" + "'" + r'][^"' + "'" + r"]*\+",
                ],
                "severity": "critical", "cwe": "CWE-89",
                "rec": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
            },
            "SSRF": {
                "patterns": [
                    r'requests\.(?:get|post|put|patch)\s*\(\s*\w',
                    r'urllib.*request.*urlopen\s*\(',
                    r'httpx\.(?:get|post)\s*\(',
                ],
                "severity": "high", "cwe": "CWE-918",
                "rec": "Validate URLs; block access to internal IP ranges",
            },
            "PATH_TRAVERSAL": {
                "patterns": [
                    r'open\s*\(\s*\w+\s*\+',
                    r"open\s*\(\s*f[" + "'" + r"]",
                ],
                "severity": "high", "cwe": "CWE-22",
                "rec": "Use os.path.realpath() and validate resolved paths",
            },
        },
    },
    ".js": {
        "name": "JavaScript/Node",
        "rules": {
            "COMMAND_INJECTION": {
                "patterns": [
                    r'exec\s*\(\s*`',
                    r'execSync\s*\(\s*`',
                    r'spawn\s*\(\s*.*shell:\s*true',
                    r'eval\s*\(',
                    r'Function\s*\(',
                ],
                "severity": "critical", "cwe": "CWE-78",
                "rec": "Use execFile() instead of exec(); avoid shell: true",
            },
            "SQL_INJECTION": {
                "patterns": [
                    r'\.query\s*\(\s*`',
                    r"\.query\s*\(\s*[" + "'" + r'][^"' + "'" + r"]*\+",
                ],
                "severity": "critical", "cwe": "CWE-89",
                "rec": "Use parameterized queries with ? placeholders",
            },
            "SSRF": {
                "patterns": [
                    r'axios\.(?:get|post)\s*\(',
                    r'fetch\s*\(\s*\w',
                    r'request\s*\(\s*\{.*uri|url',
                    r'got\s*\(',
                ],
                "severity": "high", "cwe": "CWE-918",
                "rec": "Validate URLs against allowlist",
            },
            "PROTOTYPE_POLLUTION": {
                "patterns": [
                    r'merge\s*\(\s*\{',
                    r'assign\s*\(\s*\{\s*,\s*\w',
                    r'clone\s*\(\s*\w',
                    r'\["__proto__"\]',
                    r'\["constructor"\]',
                ],
                "severity": "high", "cwe": "CWE-1321",
                "rec": "Use Object.create(null) or Object.freeze() on prototypes",
            },
        },
    },
    ".cs": {
        "name": "C#",
        "rules": {
            "SQL_INJECTION": {
                "patterns": [
                    r'\.Query\s*<\s*>\s*\(\s*\$?\w+\s*\+',
                    r'SqlCommand\s*\([^)]*\+',
                    r'\.ExecuteQuery\s*\([^)]*\+',
                    r'\.FromSqlRaw\s*\(',
                ],
                "severity": "critical", "cwe": "CWE-89",
                "rec": "Use parameterized SQL (SqlCommand with Parameters.Add)",
            },
            "DESERIALIZATION": {
                "patterns": [
                    r'BinaryFormatter\.Deserialize',
                    r'SoapFormatter\.Deserialize',
                    r'JavaScriptSerializer\.Deserialize',
                    r'TypeNameHandling\.(?:All|Auto|Objects|Arrays)',
                ],
                "severity": "critical", "cwe": "CWE-502",
                "rec": "Use Newtonsoft.Json with SerializationBinder or System.Text.Json",
            },
            "XXE": {
                "patterns": [
                    r'XmlDocument\s*\(',
                    r'XPathDocument\s*\(',
                    r'XmlReader\.Create',
                ],
                "severity": "high", "cwe": "CWE-611",
                "rec": "Set XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit",
            },
            "PATH_TRAVERSAL": {
                "patterns": [
                    r'File\.ReadAllText\s*\([^)]*\+',
                    r'File\.WriteAllText\s*\([^)]*\+',
                    r'Path\.Combine\s*\([^)]*\+\s*\w',
                ],
                "severity": "high", "cwe": "CWE-22",
                "rec": "Use Path.GetFullPath() and verify it is within allowed directory",
            },
        },
    },
    ".jsp": {
        "name": "JSP",
        "rules": {
            "EXPRESSION_LANGUAGE": {
                "patterns": [
                    r'\$\{param',
                    r'\$\{request',
                    r'\$\{session',
                    r'\$\{cookie',
                    r'\$\{header',
                ],
                "severity": "high", "cwe": "CWE-917",
                "rec": "Use JSTL escape functions (fn:escapeXml) for user-controlled values in EL",
            },
        },
    },
}


class CodeAuditor:
    def __init__(self, paths: List[str], threads: int = 4):
        self.paths = paths
        self.threads = threads
        self.findings: List[AuditFinding] = []
        self._lock = threading.Lock()

    def _scan_file(self, filepath: str) -> List[AuditFinding]:
        findings = []
        ext = os.path.splitext(filepath)[1].lower()
        config = LANG_CONFIGS.get(ext)
        if not config:
            return findings

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for rule_id, rule in config["rules"].items():
            for pattern in rule["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append(AuditFinding(
                            file=filepath,
                            line=i,
                            severity=rule["severity"],
                            rule_id=rule_id,
                            description="[%s] %s in %s" % (config["name"], rule_id, os.path.basename(filepath)),
                            code_snippet=line.strip()[:150],
                            recommendation=rule["rec"],
                            cwe=rule.get("cwe"),
                        ))
                        break
        return findings

    def scan(self) -> Dict:
        all_files = []
        for path in self.paths:
            if os.path.isfile(path):
                all_files.append(path)
            else:
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if d not in ("node_modules", "vendor", ".git", "__pycache__")]
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in LANG_CONFIGS:
                            all_files.append(os.path.join(root, f))

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            batch_results = list(ex.map(self._scan_file, all_files))

        for batch in batch_results:
            self.findings.extend(batch)

        by_severity = {}
        by_type = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
            by_type.setdefault(f.rule_id, []).append(f)

        return {
            "files_scanned": len(all_files),
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "by_type": {k: len(v) for k, v in by_type.items()},
            "findings": [
                {"file": f.file, "line": f.line, "severity": f.severity,
                 "rule": f.rule_id, "snippet": f.code_snippet,
                 "cwe": f.cwe, "rec": f.recommendation}
                for f in self.findings
            ],
        }


def run_audit(paths: List[str], threads: int = 4) -> Dict:
    auditor = CodeAuditor(paths, threads)
    return auditor.scan()
