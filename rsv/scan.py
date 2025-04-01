import os
import re
import json
import binascii
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import *
from ropgadget.core import Core as ROPGadgetCore
# from ropgadget import Core as ROPGadgetCore
import math

# Known unsafe functions (expanded list)
UNSAFE_FUNCTIONS = [
    "strcpy", "strncpy", "gets", "sprintf", "vsprintf", "strcat", "strncat",
    "system", "exec", "popen", "memcpy", "memset", "scanf", "sscanf"
]

# Architecture configurations for disassembly
ARCHITECTURES = [
    (CS_ARCH_ARM, CS_MODE_ARM, "ARM"),
    (CS_ARCH_ARM, CS_MODE_THUMB, "ARM Thumb"),
    (CS_ARCH_MIPS, CS_MODE_MIPS32, "MIPS32"),
    (CS_ARCH_X86, CS_MODE_32, "x86"),
    (CS_ARCH_X86, CS_MODE_64, "x86-64")
]

# Load local vulnerability database from vuln_db.json
try:
    with open("vuln_db.json", "r") as f:
        KNOWN_VULNS = json.load(f).get("vulnerabilities", {})
except FileNotFoundError:
    KNOWN_VULNS = {
        "OpenSSL 1.0.1": ["CVE-2014-0160", "Heartbleed vulnerability"],
        "BusyBox 1.21.0": ["CVE-2013-1813", "Command injection"]
    }
    print("Warning: vuln_db.json not found. Using default database.")

def calculate_entropy(data):
    """Calculate Shannon entropy to detect encrypted or compressed data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def scan_vulnerabilities(extracted_dir, deep=False):
    if not extracted_dir or not os.path.exists(extracted_dir):
        return {"error": "No extracted firmware to scan"}

    findings = []
    scanned_files = set()
    quick_limit = 10240  # 10KB limit for quick mode

    for root, _, files in os.walk(extracted_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path in scanned_files:
                continue
            scanned_files.add(file_path)

            # 1. Text and Config File Analysis
            try:
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()
                    if re.search(r"(admin|root|user|guest):[a-zA-Z0-9]+", content, re.IGNORECASE):
                        findings.append({
                            "file": file_path,
                            "issue": "Hardcoded credentials detected",
                            "severity": "High",
                            "component": "configuration"
                        })
                    if re.search(r"(password|key|secret|token)=[a-zA-Z0-9]+", content, re.IGNORECASE):
                        findings.append({
                            "file": file_path,
                            "issue": "Potential unencrypted sensitive data",
                            "severity": "Medium",
                            "component": "configuration",
                            "unknown": True
                        })
                    for vuln, cve_info in KNOWN_VULNS.items():
                        if vuln in content:
                            findings.append({
                                "file": file_path,
                                "issue": f"Known vulnerable component: {vuln}",
                                "severity": "Critical",
                                "component": "software",
                                "cve": cve_info[0],
                                "description": cve_info[1]
                            })
            except:
                pass

            # 2. Binary File Analysis
            try:
                with open(file_path, "rb") as f:
                    binary_data = f.read(quick_limit if not deep else None)  # Full file in deep mode
                    strings = re.findall(b"[ -~]{4,}", binary_data)
                    for s in strings:
                        s_decoded = s.decode("ascii", errors="ignore")
                        if re.search(r"(admin|root|user|guest):[a-zA-Z0-9]+", s_decoded):
                            findings.append({
                                "file": file_path,
                                "issue": "Hardcoded credentials in binary",
                                "severity": "High",
                                "component": "binary"
                            })
                        if re.search(r"(password|key|secret|token)=[a-zA-Z0-9]+", s_decoded, re.IGNORECASE):
                            findings.append({
                                "file": file_path,
                                "issue": "Potential unencrypted sensitive data in binary",
                                "severity": "Medium",
                                "component": "binary",
                                "unknown": True
                            })
                        for vuln, cve_info in KNOWN_VULNS.items():
                            if vuln in s_decoded:
                                findings.append({
                                    "file": file_path,
                                    "issue": f"Known vulnerable component: {vuln}",
                                    "severity": "Critical",
                                    "component": "binary",
                                    "cve": cve_info[0],
                                    "description": cve_info[1]
                                })

                    # Entropy check (deep mode only)
                    if deep:
                        entropy = calculate_entropy(binary_data)
                        if entropy > 7.5:
                            findings.append({
                                "file": file_path,
                                "issue": "High entropy data (potentially encrypted or compressed)",
                                "severity": "Low",
                                "component": "binary",
                                "unknown": True
                            })

            except Exception as e:
                print(f"Binary read failed for {file_path}: {e}")

            # 3. ELF File Analysis
            if file.endswith(".elf"):
                try:
                    with open(file_path, 'rb') as f:
                        elf = ELFFile(f)
                        for section in elf.iter_sections():
                            if section.name == '.rodata':
                                data = section.data()
                                if any(x in data for x in [b"password", b"key", b"secret"]):
                                    findings.append({
                                        "file": file_path,
                                        "issue": "Potential hardcoded sensitive data in .rodata",
                                        "severity": "Medium",
                                        "component": "binary"
                                    })
                            if section.name == '.bss' and section.header.sh_size > 1024 * 10:
                                findings.append({
                                    "file": file_path,
                                    "issue": "Large uninitialized data section (potential buffer overflow)",
                                    "severity": "Medium",
                                    "component": "binary",
                                    "unknown": True
                                })
                except ELFError as e:
                    print(f"ELF parsing failed for {file_path}: {e}")

                # ROP Gadgets (deep mode only)
                if deep:
                    try:
                        rop = ROPGadgetCore(file_path)
                        gadgets = rop.gadgets()
                        if gadgets:
                            findings.append({
                                "file": file_path,
                                "issue": f"Found {len(gadgets)} ROP gadgets",
                                "severity": "High",
                                "component": "binary"
                            })
                    except Exception as e:
                        print(f"ROP gadget analysis failed for {file_path}: {e}")

            # 4. Disassembly Analysis
            try:
                with open(file_path, "rb") as f:
                    code = f.read(quick_limit if not deep else None)  # Full file in deep mode
                    for arch, mode, arch_name in ARCHITECTURES:
                        md = Cs(arch, mode)
                        md.detail = True
                        disassembled = list(md.disasm(code, 0x1000))
                        for i in disassembled:
                            if i.mnemonic in UNSAFE_FUNCTIONS:
                                findings.append({
                                    "file": file_path,
                                    "issue": f"Unsafe function ({i.mnemonic}) detected [{arch_name}]",
                                    "severity": "Critical",
                                    "component": "binary"
                                })
                            if deep:  # Heuristics in deep mode only
                                if "mov" in i.mnemonic and any(op.type == CS_OP_IMM and op.value > 0x1000 for op in i.operands):
                                    findings.append({
                                        "file": file_path,
                                        "issue": f"Large immediate value in {i.mnemonic} (potential overflow) [{arch_name}]",
                                        "severity": "Medium",
                                        "component": "binary",
                                        "unknown": True
                                    })
                                if i.mnemonic.startswith("b") and any(op.type == CS_OP_REG for op in i.operands):
                                    findings.append({
                                        "file": file_path,
                                        "issue": f"Suspicious control flow ({i.mnemonic} to register) [{arch_name}]",
                                        "severity": "Medium",
                                        "component": "binary",
                                        "unknown": True
                                    })
                        if not deep and findings:  # Quick mode: stop after first findings per file
                            break
            except Exception as e:
                print(f"Disassembly failed for {file_path}: {e}")

    return findings if findings else {"message": "No vulnerabilities found"}