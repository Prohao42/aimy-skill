import os
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("mobile_scanner")


@dataclass
class MobileFinding:
    category: str
    severity: str
    title: str
    description: str
    recommendation: str
    cwe: Optional[str] = None
    file: Optional[str] = None


class AndroidScanner:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.findings: List[MobileFinding] = []
        self.manifest: Optional[ET.Element] = None
        self.manifest_xml: str = ""
        self.dex_files: List[str] = []
        self.resources: Dict = {}

    def scan(self) -> Dict:
        if not os.path.isfile(self.apk_path):
            return {"error": "APK not found: %s" % self.apk_path, "findings": []}

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                for name in zf.namelist():
                    if name == "AndroidManifest.xml":
                        try:
                            self.manifest_xml = zf.read(name).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    elif name.endswith(".dex"):
                        self.dex_files.append(name)
                    elif name.startswith("res/"):
                        self.resources[name] = len(zf.read(name))
        except zipfile.BadZipFile:
            return {"error": "Invalid APK file", "findings": []}

        self._check_manifest()
        self._check_backup()
        self._check_debuggable()
        self._check_exported_components()
        self._check_ssl()
        self._check_webview()
        self._check_permissions()
        self._check_network_security()
        self._check_dex_count()
        return self._result()

    def _check_manifest(self):
        if not self.manifest_xml:
            self.findings.append(MobileFinding(
                category="manifest", severity="medium",
                title="AndroidManifest.xml not readable",
                description="Could not decode AndroidManifest.xml; may be binary encoded",
                recommendation="Use apktool to decode the manifest",
            ))
            return
        lines = self.manifest_xml.split("\n")

    def _check_backup(self):
        if 'android:allowBackup="true"' in self.manifest_xml or "allowBackup=true" in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="backup", severity="high",
                title="Backup Allowed",
                description="android:allowBackup=true allows full app data backup via ADB",
                recommendation="Set android:allowBackup=false in AndroidManifest.xml",
                cwe="CWE-312",
            ))

    def _check_debuggable(self):
        if 'android:debuggable="true"' in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="debug", severity="high",
                title="Debuggable App",
                description="App is debuggable; debugger can attach and inspect runtime",
                recommendation="Remove android:debuggable or set to false for release builds",
                cwe="CWE-489",
            ))

    def _check_exported_components(self):
        exported_count = self.manifest_xml.count('android:exported="true"')
        if exported_count > 0:
            self.findings.append(MobileFinding(
                category="components", severity="medium",
                title="%d Exported Components" % exported_count,
                description="Components with exported=true can be launched by any app",
                recommendation="Set exported=false or implement proper permission checks",
                cwe="CWE-926",
            ))

    def _check_ssl(self):
        if "http://" in self.manifest_xml and "https://" not in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="network", severity="critical",
                title="Plain HTTP Usage",
                description="App uses HTTP without HTTPS; all traffic is unencrypted",
                recommendation="Use HTTPS for all network communications",
                cwe="CWE-319",
            ))
        if 'android:usesCleartextTraffic="true"' in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="network", severity="critical",
                title="Cleartext Traffic Allowed",
                description="usesCleartextTraffic=true allows unencrypted HTTP traffic",
                recommendation="Set android:usesCleartextTraffic=false",
                cwe="CWE-319",
            ))

    def _check_webview(self):
        if "setJavaScriptEnabled" in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="webview", severity="medium",
                title="JavaScript Enabled in WebView",
                description="WebView with JavaScript enabled may be vulnerable to XSS",
                recommendation="Disable JavaScript unless absolutely necessary; sanitize input",
                cwe="CWE-79",
            ))

    def _check_permissions(self):
        dangerous = [
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
            "READ_CONTACTS", "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "GET_TASKS", "SYSTEM_ALERT_WINDOW",
            "BIND_ACCESSIBILITY_SERVICE",
        ]
        found = []
        for perm in dangerous:
            if 'android.permission.%s"' % perm in self.manifest_xml:
                found.append(perm)
        if found:
            self.findings.append(MobileFinding(
                category="permissions", severity="medium",
                title="Dangerous Permissions: %s" % ", ".join(found[:5]),
                description="App requests %d dangerous permissions" % len(found),
                recommendation="Review each permission; use runtime permission model",
                cwe="CWE-250",
            ))

    def _check_network_security(self):
        ns_files = [k for k in self.resources if "network_security" in k]
        if not ns_files and 'android:networkSecurityConfig' not in self.manifest_xml:
            self.findings.append(MobileFinding(
                category="network", severity="info",
                title="No Network Security Config",
                description="No network_security_config.xml found; default allows all CAs",
                recommendation="Add network_security_config.xml with certificate pinning",
                cwe="CWE-295",
            ))

    def _check_dex_count(self):
        if len(self.dex_files) > 3:
            self.findings.append(MobileFinding(
                category="obfuscation", severity="info",
                title="Multi-Dex App (%d .dex files)" % len(self.dex_files),
                description="Multiple DEX files may indicate code obfuscation/packing",
                recommendation="Verify with dex2jar or jadx",
            ))

    def _result(self) -> Dict:
        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
        return {
            "apk_path": self.apk_path,
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "findings": [
                {"category": f.category, "severity": f.severity,
                 "title": f.title, "description": f.description,
                 "recommendation": f.recommendation, "cwe": f.cwe}
                for f in self.findings
            ],
            "dex_count": len(self.dex_files),
            "resource_count": len(self.resources),
        }


class IOSScanner:
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.findings: List[MobileFinding] = []
        self.plist: str = ""
        self.frameworks: List[str] = []

    def scan(self) -> Dict:
        if not os.path.isfile(self.ipa_path):
            return {"error": "IPA not found: %s" % self.ipa_path, "findings": []}

        try:
            with zipfile.ZipFile(self.ipa_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".plist") and "Info" in name:
                        try:
                            self.plist = zf.read(name).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                    if name.startswith("Payload/") and "/Frameworks/" in name:
                        fn = name.split("/")[-1]
                        if fn not in self.frameworks:
                            self.frameworks.append(fn)
        except zipfile.BadZipFile:
            return {"error": "Invalid IPA file", "findings": []}

        self._check_ats()
        self._check_encryption()
        self._check_frameworks()
        self._check_uiwebview()
        return self._result()

    def _check_ats(self):
        if "NSAppTransportSecurity" in self.plist:
            if "NSAllowsArbitraryLoads" in self.plist and "true" in self.plist.split("NSAllowsArbitraryLoads")[1][:10]:
                self.findings.append(MobileFinding(
                    category="network", severity="critical",
                    title="ATS Disabled (NSAllowsArbitraryLoads=true)",
                    description="App Transport Security bypassed; allows HTTP connections",
                    recommendation="Remove NSAllowsArbitraryLoads or set specific exception domains",
                    cwe="CWE-319",
                ))

    def _check_encryption(self):
        if "NSFileProtection" not in self.plist:
            self.findings.append(MobileFinding(
                category="data_storage", severity="high",
                title="No File Protection",
                description="NSFileProtection not configured; app data may be accessible on locked device",
                recommendation="Set NSFileProtection to NSFileProtectionComplete",
                cwe="CWE-312",
            ))

    def _check_frameworks(self):
        dangerous = ["JSPatch", "ReactNativeDev", "FLEX", "Cycript", "SSLKillSwitch"]
        for fw in self.frameworks:
            for d in dangerous:
                if d.lower() in fw.lower():
                    self.findings.append(MobileFinding(
                        category="framework", severity="high",
                        title="%s Detected" % d,
                        description="%s framework found; may indicate jailbreak detection bypass or debug tools" % d,
                        recommendation="Remove debug frameworks from release builds",
                    ))

    def _check_uiwebview(self):
        if "UIWebView" in self.plist or "UIWebView" in str(self.frameworks):
            self.findings.append(MobileFinding(
                category="webview", severity="high",
                title="UIWebView Usage",
                description="UIWebView is deprecated and lacks WKWebView security features",
                recommendation="Migrate from UIWebView to WKWebView",
                cwe="CWE-79",
            ))

    def _result(self) -> Dict:
        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)
        return {
            "ipa_path": self.ipa_path,
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "findings": [
                {"category": f.category, "severity": f.severity,
                 "title": f.title, "description": f.description,
                 "recommendation": f.recommendation, "cwe": f.cwe}
                for f in self.findings
            ],
            "framework_count": len(self.frameworks),
        }


def scan_android(apk_path: str) -> Dict:
    scanner = AndroidScanner(apk_path)
    return scanner.scan()


def scan_ios(ipa_path: str) -> Dict:
    scanner = IOSScanner(ipa_path)
    return scanner.scan()
