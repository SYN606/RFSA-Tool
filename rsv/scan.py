import os
import json
import logging

try:
    from pyelftools.elf.elffile import ELFFile
    from capstone import *
    ELF_AVAILABLE = True
except ImportError as e:
    logging.warning(f"ELF parsing tools unavailable: {e}. Skipping binary analysis.")
    ELF_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("rfvs.log"), logging.StreamHandler()]
)

DEFAULT_VULN_DB = {
    "vulnerable_functions": {
        "generic": [{"name": "strcpy", "description": "Buffer overflow risk", "severity": "high"}],
        "architecture_specific": {}
    },
    "known_cves": {
        "OpenSSL": {
            "versions": ["1.0.1"],
            "cves": [{"id": "CVE-2014-0160", "description": "Heartbleed", "severity": "critical"}]
        }
    }
}

def scan_vulnerabilities(extracted_dir, deep=False):
    logger = logging.getLogger(__name__)
    vulnerabilities = []
    vuln_db = load_vuln_db(logger)

    if not os.path.isdir(extracted_dir):
        logger.error(f"{extracted_dir} is not a valid directory.")
        return vulnerabilities

    for root, _, files in os.walk(extracted_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path) and not file.endswith(('.txt', '.conf')):
                vulns = scan_binary(file_path, vuln_db, deep, logger)
                if vulns:
                    vulnerabilities.extend(vulns)
    return vulnerabilities

def load_vuln_db(logger):
    vuln_db_path = "vuln_db.json"
    if os.path.exists(vuln_db_path):
        try:
            with open(vuln_db_path, "r") as f:
                logger.info(f"Loaded vulnerability database from {vuln_db_path}")
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {vuln_db_path}: {e}. Using default database.")
            return DEFAULT_VULN_DB
    else:
        logger.warning("vuln_db.json not found. Using default database.")
        return DEFAULT_VULN_DB

def scan_binary(file_path, vuln_db, deep, logger):
    vulnerabilities = []

    # Fallback if ELF tools are unavailable
    if not ELF_AVAILABLE:
        logger.info(f"Skipping ELF analysis for {file_path} due to missing pyelftools/capstone.")
        # Check for known CVEs based on filename only
        for component, details in vuln_db["known_cves"].items():
            if component.lower() in file_path.lower():
                for version in details["versions"]:
                    if version in file_path:
                        vulnerabilities.extend([
                            {"file": file_path, "issue": f"Known vulnerable component: {component} {version}", "cve": [cve["id"]], "severity": cve["severity"]}
                            for cve in details["cves"]
                        ])
        return vulnerabilities

    # Normal ELF-based scanning
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            arch = detect_architecture(elf, logger)
            for section in elf.iter_sections():
                if section.name == ".text":
                    data = section.data()
                    md = Cs(CS_ARCH_ARM if arch == "arm" else CS_ARCH_MIPS, CS_MODE_ARM if arch == "arm" else CS_MODE_MIPS)
                    for insn in md.disasm(data, 0x1000):
                        for func in vuln_db["vulnerable_functions"]["generic"]:
                            if func["name"] in insn.mnemonic:
                                vulnerabilities.append({
                                    "file": file_path,
                                    "issue": f"Unsafe function ({func['name']}) detected",
                                    "description": func["description"],
                                    "severity": func["severity"]
                                })
                        if arch in vuln_db["vulnerable_functions"]["architecture_specific"]:
                            for func in vuln_db["vulnerable_functions"]["architecture_specific"][arch]:
                                if func["name"] in insn.mnemonic:
                                    vulnerabilities.append({
                                        "file": file_path,
                                        "issue": f"Unsafe function ({func['name']}) detected",
                                        "description": func["description"],
                                        "severity": func["severity"]
                                    })
    except Exception as e:
        logger.debug(f"Failed to scan {file_path} as ELF: {e}")

    # Check for known CVEs regardless of ELF success
    for component, details in vuln_db["known_cves"].items():
        if component.lower() in file_path.lower():
            for version in details["versions"]:
                if version in file_path:
                    vulnerabilities.extend([
                        {"file": file_path, "issue": f"Known vulnerable component: {component} {version}", "cve": [cve["id"]], "severity": cve["severity"]}
                        for cve in details["cves"]
                    ])
    return vulnerabilities

def detect_architecture(elf, logger):
    machine = elf.header["e_machine"]
    if machine == "EM_ARM":
        return "arm"
    elif machine == "EM_MIPS":
        return "mips"
    logger.debug(f"Unknown architecture for {elf}, defaulting to ARM")
    return "arm"

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        vulnerabilities = scan_vulnerabilities(sys.argv[1], deep="--deep" in sys.argv)
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print("Usage: python scan.py <extracted_dir> [--deep]")