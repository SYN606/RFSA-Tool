import os
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rfvs.log"),
        logging.StreamHandler()
    ]
)

def generate_report(findings, output_file="report.txt", verbose=False):
    logger = logging.getLogger(__name__)
    if not verbose:
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.removeHandler(handler)

    logger.info(f"Generating report to {output_file}")
    file_ext = os.path.splitext(output_file)[1].lower()
    if file_ext not in [".txt", ".json"]:
        logger.warning(f"Unsupported file extension '{file_ext}'. Defaulting to .txt")
        output_file = output_file + ".txt"
        file_ext = ".txt"

    report_content = build_report_content(findings, logger)
    if not report_content:
        logger.error("No content to generate report from findings.")
        return False

    try:
        if file_ext == ".txt":
            save_text_report(report_content, output_file, logger)
        elif file_ext == ".json":
            save_json_report(report_content, output_file, logger)
        logger.info(f"Report successfully saved to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to save report to {output_file}: {e}")
        return False

def build_report_content(findings, logger):
    report = {"timestamp": datetime.now().isoformat(), "findings": {}}
    if "extracted_dir" in findings:
        report["findings"]["extraction"] = {
            "directory": findings["extracted_dir"],
            "associated_ip": findings.get("target_ip", "Not specified")
        }
        logger.debug("Added extraction details to report")
    if "targets" in findings:
        report["findings"]["targets"] = [{"ip": t["ip"], "mac": t["mac"]} for t in findings["targets"]]
        logger.debug(f"Added {len(findings['targets'])} targets to report")
    if "vulnerabilities" in findings:
        report["findings"]["vulnerabilities"] = findings["vulnerabilities"]
        logger.debug(f"Added {len(findings['vulnerabilities'])} vulnerabilities to report")
    if "exploit_results" in findings:
        report["findings"]["exploits"] = findings["exploit_results"]
        logger.debug(f"Added {len(findings['exploit_results'])} exploit results to report")
    if "network_results" in findings:
        report["findings"]["network_tests"] = findings["network_results"]
        logger.debug(f"Added {len(findings['network_results'])} network test results to report")
    return report if report["findings"] else None

def save_text_report(report_content, output_file, logger):
    with open(output_file, "w") as f:
        f.write("Router Firmware Vulnerability Scanner (RFVS) Report\n")
        f.write(f"Generated: {report_content['timestamp']}\n")
        f.write("=" * 50 + "\n\n")
        if "extraction" in report_content["findings"]:
            f.write("Extraction Details:\n")
            f.write(f"  Directory: {report_content['findings']['extraction']['directory']}\n")
            f.write(f"  Associated IP: {report_content['findings']['extraction']['associated_ip']}\n")
            f.write("\n")
        if "targets" in report_content["findings"]:
            f.write("Discovered Targets:\n")
            for target in report_content["findings"]["targets"]:
                f.write(f"  IP: {target['ip']}, MAC: {target['mac']}\n")
            f.write("\n")
        if "vulnerabilities" in report_content["findings"]:
            f.write("Vulnerabilities Found:\n")
            for vuln in report_content["findings"]["vulnerabilities"]:
                f.write(f"  File: {vuln.get('file', 'Unknown')}\n")
                f.write(f"  Issue: {vuln.get('issue', 'N/A')}\n")
                if "description" in vuln:
                    f.write(f"    Description: {vuln['description']}\n")
                if "cve" in vuln:
                    f.write(f"    CVEs: {', '.join(vuln['cve'])}\n")
                if "severity" in vuln:
                    f.write(f"    Severity: {vuln['severity']}\n")
                f.write("\n")
        if "exploits" in report_content["findings"]:
            f.write("Exploit Test Results:\n")
            for result in report_content["findings"]["exploits"]:
                f.write(f"  Vulnerability: {result.get('vuln', 'Unknown')}\n")
                f.write(f"  Status: {result.get('status', 'N/A')}\n")
                if "post" in result:
                    f.write(f"    Post-Exploitation: {result['post']}\n")
                f.write("\n")
        if "network_tests" in report_content["findings"]:
            f.write("Network Test Results:\n")
            for test in report_content["findings"]["network_tests"]:
                f.write(f"  Test: {test.get('test', 'Unknown')}\n")
                f.write(f"  Status: {test.get('status', 'N/A')}\n")
                f.write("\n")

def save_json_report(report_content, output_file, logger):
    with open(output_file, "w") as f:
        json.dump(report_content, f, indent=4)

if __name__ == "__main__":
    sample_findings = {
        "extracted_dir": "extracted_firmware.bin",
        "target_ip": "192.168.1.1",
        "targets": [{"ip": "192.168.1.2", "mac": "00:11:22:33:44:55"}],
        "vulnerabilities": [{"file": "lib.so", "issue": "Unsafe function (strcpy)", "cve": ["CVE-2020-1234"]}],
        "exploit_results": [{"vuln": "Unsafe function", "status": "Exploit successful"}],
        "network_results": [{"test": "Port 80 scan", "status": "open"}]
    }
    generate_report(sample_findings, "test_report.txt", verbose=True)