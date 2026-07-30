import os
import re
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from tools.log_utils import get_logger

logger = get_logger("binary_analyzer")


@dataclass
class BinaryInfo:
    filepath: str
    file_size: int
    arch: str = ""
    format_type: str = ""
    os_type: str = ""
    protections: Dict = field(default_factory=dict)
    suspicious_imports: List[str] = field(default_factory=list)
    strings_found: List[Dict] = field(default_factory=list)
    sections: List[Dict] = field(default_factory=list)
    is_packed: bool = False
    entropy: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "filepath": self.filepath,
            "size": self.file_size,
            "arch": self.arch,
            "format": self.format_type,
            "os": self.os_type,
            "protections": self.protections,
            "suspicious_imports": self.suspicious_imports[:10],
            "string_count": len(self.strings_found),
            "sections": self.sections,
            "packed": self.is_packed,
            "entropy": round(self.entropy, 2),
        }


DANGEROUS_IMPORTS = {
    "kernel32.dll": [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "SetWindowsHookEx", "CreateToolhelp32Snapshot", "OpenProcess",
        "ReadProcessMemory", "QueueUserAPC", "NtUnmapViewOfSection",
    ],
    "ntdll.dll": [
        "NtCreateThreadEx", "NtQueryInformationProcess",
        "NtOpenProcess", "NtAllocateVirtualMemory",
    ],
    "ws2_32.dll": ["socket", "connect", "send", "recv", "WSAStartup"],
    "wininet.dll": ["InternetOpen", "InternetConnect", "HttpOpenRequest", "InternetReadFile"],
    "urlmon.dll": ["URLDownloadToFile", "URLDownloadToCacheFile"],
    "advapi32.dll": [
        "CreateService", "StartService", "OpenSCManager",
        "RegSetValueEx", "CryptAcquireContext",
    ],
    "libc.so": ["system", "execve", "popen", "fork", "ptrace"],
    "libcrypto.so": ["RSA_private_decrypt", "EVP_DecryptFinal"],
}

SUSPICIOUS_STRING_PATTERNS = [
    (r"http[s]?://\d+\.\d+\.\d+\.\d+", "hardcoded_ip_url"),
    (r"(?:cmd|powershell|bash|sh)\s+-[ec]", "shell_command"),
    (r"(?:SELECT|INSERT|UPDATE|DELETE)\s+", "sql_query"),
    (r"(?:AAAA(?:A{62}|.{60}))", "base64_shellcode"),
    (r"(?:www\.|http://|https://)[a-z0-9.-]+\.(?:ru|cn|tk|ml|ga|cf)", "suspicious_domain"),
    (r"['\"](?:admin|root|toor|backup)['\"]\s*[:=]", "credential_pattern"),
    (r"\\\\[\w.]+\\[a-zA-Z]", "unc_path"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+", "ip_port"),
]

KNOWN_PACKERS = ["UPX", "ASPACK", "MPRESS", "THEMIDA", "VMProtect", "Enigma",
                 "Armadillo", "Obsidium", "EXECryptor", "ASProtect"]


class BinaryAnalyzer:
    def __init__(self, paths: List[str], threads: int = 4):
        self.paths = paths
        self.threads = threads
        self.results: List[Dict] = []
        self._lock = threading.Lock()

    def _calc_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x.bit_length() - 1)
        return entropy

    def _extract_strings(self, data: bytes, min_len: int = 6) -> List[Dict]:
        strings = []
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        for m in pattern.finditer(data):
            s = m.group().decode("ascii", errors="replace")
            strings.append({"text": s[:200], "offset": m.start()})
        return strings

    def _check_pe(self, filepath: str, data: bytes) -> BinaryInfo:
        info = BinaryInfo(filepath=filepath, file_size=len(data))
        info.format_type = "PE"

        if len(data) < 64:
            return info
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if pe_offset + 4 > len(data):
            return info

        sig = data[pe_offset:pe_offset+4]
        if sig != b"PE\x00\x00":
            return info

        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
        arch_map = {0x14c: "x86", 0x8664: "x64", 0x1c4: "ARM", 0xaa64: "ARM64"}
        info.arch = arch_map.get(machine, "unknown")
        info.os_type = "Windows"

        chars = struct.unpack("<H", data[pe_offset+22:pe_offset+24])[0]
        info.protections = {
            "dll": bool(chars & 0x2000),
            "system": bool(chars & 0x1000),
            "relocs_stripped": bool(chars & 0x0001),
            "executable": bool(chars & 0x0002),
            "large_address": bool(chars & 0x0020),
        }

        opt_header_offset = pe_offset + 24
        if opt_header_offset + 2 <= len(data):
            magic = struct.unpack("<H", data[opt_header_offset:opt_header_offset+2])[0]
            if magic == 0x10b:
                size_of_headers = struct.unpack("<I", data[pe_offset+84:pe_offset+88])[0]
                image_size = struct.unpack("<I", data[opt_header_offset+56:opt_header_offset+60])[0]
                info.protections["aslr"] = bool(chars & 0x0040)
                info.protections["nx"] = bool(struct.unpack("<I", data[opt_header_offset+68:opt_header_offset+72])[0] & 0x100000)
                info.protections["size_of_headers"] = size_of_headers
                info.protections["image_size"] = image_size

        section_offset = pe_offset + 24 + struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]
        num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
        for i in range(num_sections):
            off = section_offset + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack("<I", data[off+8:off+12])[0]
            vaddr = struct.unpack("<I", data[off+12:off+16])[0]
            raw_size = struct.unpack("<I", data[off+16:off+20])[0]
            raw_off = struct.unpack("<I", data[off+20:off+24])[0]
            sec_chars = struct.unpack("<I", data[off+36:off+40])[0]
            info.sections.append({
                "name": name, "virtual_size": vsize, "virtual_address": hex(vaddr),
                "raw_size": raw_size, "raw_offset": hex(raw_off),
                "executable": bool(sec_chars & 0x20000000),
                "writable": bool(sec_chars & 0x80000000),
            })

        # Imports
        struct.unpack("<I", data[pe_offset+24+104:pe_offset+24+108])[0] if magic in (0x10b, 0x20b) else 0
        for dll_name, apis in DANGEROUS_IMPORTS.items():
            dll_pattern = dll_name.lower().encode()
            if dll_pattern in data.lower():
                for api in apis:
                    if api.lower().encode() in data.lower():
                        info.suspicious_imports.append("%s!%s" % (dll_name, api))

        strings = self._extract_strings(data)
        for s in strings:
            for pat, label in SUSPICIOUS_STRING_PATTERNS:
                if re.search(pat, s["text"]):
                    info.strings_found.append({"label": label, "text": s["text"][:100]})

        for packer in KNOWN_PACKERS:
            if packer.lower() in data.lower():
                info.is_packed = True
                info.protections["packer"] = packer

        info.entropy = self._calc_entropy(data)
        return info

    def _check_elf(self, filepath: str, data: bytes) -> BinaryInfo:
        info = BinaryInfo(filepath=filepath, file_size=len(data))
        info.format_type = "ELF"

        elf_class = data[4]
        data[5]
        arch_map = {1: "x86", 2: "x64"}
        info.arch = arch_map.get(elf_class, "unknown")
        os_map = {0: "System V", 3: "Linux", 97: "ARM"}
        info.os_type = os_map.get(data[7], "unknown")

        elf_bits = 32 if elf_class == 1 else 64
        ei = 36 if elf_bits == 32 else 48
        phoff = struct.unpack("<I" if elf_bits == 32 else "<Q", data[28:28+ei-28])[0]
        phnum = struct.unpack("<H", data[44:46] if elf_bits == 32 else data[56:58])[0]

        for i in range(phnum):
            off = phoff + i * (32 if elf_bits == 32 else 56)
            if off + 4 > len(data):
                break
            ptype = struct.unpack("<I", data[off:off+4])[0]
            if ptype == 2:  # PT_LOAD
                flags = struct.unpack("<I", data[off+4:off+8] if elf_bits == 32 else data[off+4:off+8])[0]
                info.protections["nx"] = not bool(flags & 1)

        for dll_name, apis in DANGEROUS_IMPORTS.items():
            if dll_name.endswith(".so"):
                dll_base = dll_name.split(".")[0]
                if dll_base.encode() in data.lower():
                    for api in apis:
                        if api.encode() in data:
                            info.suspicious_imports.append("%s!%s" % (dll_name, api))

        strings = self._extract_strings(data)
        for s in strings:
            for pat, label in SUSPICIOUS_STRING_PATTERNS:
                if re.search(pat, s["text"]):
                    info.strings_found.append({"label": label, "text": s["text"][:100]})

        if b"GCC: (" in data:
            pass
        for packer in KNOWN_PACKERS:
            if packer.lower() in data.lower():
                info.is_packed = True
                break

        info.entropy = self._calc_entropy(data)
        if info.entropy > 7.5:
            info.is_packed = info.is_packed or True

        info.protections["relro"] = "FULL" if b"__rela_iplt" in data else ("PARTIAL" if b"__rela" in data else "NONE")
        info.protections["canary"] = b"__stack_chk_fail" in data

        return info

    def _analyze_file(self, filepath: str) -> Optional[Dict]:
        try:
            with open(filepath, "rb") as f:
                data = f.read(1024 * 1024 * 4)
            if len(data) < 16:
                return None
            if data[:2] == b"MZ":
                info = self._check_pe(filepath, data)
            elif data[:4] == b"\x7fELF":
                info = self._check_elf(filepath, data)
            else:
                ext = os.path.splitext(filepath)[1].lower()
                if ext in (".exe", ".dll", ".sys", ".bin"):
                    info = self._check_pe(filepath, data)
                else:
                    return None
            return info.to_dict()
        except Exception as e:
            logger.debug("binary analyze %s: %s", filepath, e)
            return None

    def scan(self) -> Dict:
        all_files = []
        for path in self.paths:
            if os.path.isfile(path):
                all_files.append(path)
            else:
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "__pycache__")]
                    for f in files:
                        ext = os.path.splitext(f)[1].lower()
                        if ext in (".exe", ".dll", ".sys", ".elf", ".bin", ".so", ".o"):
                            all_files.append(os.path.join(root, f))

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            batch_results = list(ex.map(self._analyze_file, all_files))

        self.results = [r for r in batch_results if r]
        suspicious = [r for r in self.results if r.get("suspicious_imports") or r.get("packed")]
        return {
            "files_scanned": len(all_files),
            "binaries_analyzed": len(self.results),
            "suspicious_count": len(suspicious),
            "binaries": self.results,
            "suspicious": suspicious[:10],
            "summary": {
                "packed": sum(1 for r in self.results if r.get("packed")),
                "has_suspicious_imports": sum(1 for r in self.results if r.get("suspicious_imports")),
                "high_entropy": sum(1 for r in self.results if r.get("entropy", 0) > 7.0),
            },
        }


def run_binary_scan(paths: List[str], threads: int = 4) -> Dict:
    analyzer = BinaryAnalyzer(paths, threads)
    return analyzer.scan()
