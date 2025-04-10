import argparse
import sys
import os
import subprocess
import logging
import paramiko
from scp import SCPClient  # Now resolved with pip install scp
from getpass import getpass
from extract import *  # e.g., extract_firmware
from rsv.scan import *  # e.g., scan_vulnerabilities
from report import *   # e.g., generate_report
from rsv.exploit import *  # e.g., test_exploits
from pycvesearch import CVESearch
from scapy.all import srp, IP, TCP, Ether, ARP
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rfvs.log"),
        logging.StreamHandler()
    ]
)

def banner():
    print(Fore.RED + Style.BRIGHT + r'''
    ____          ______        _____         ___ 
   / __ \        / ____/       / ___/        /   |
  / /_/ /       / /_           \__ \        / /| |
 / _, _/  _    / __/    _     ___/ /  _    / ___ |
/_/ |_|  (_)  /_/      (_)   /____/  (_)  /_/  |_|

ROUTER      FIRMWARE        SECURITY        ANALYSIS
''' + Style.RESET_ALL)
    logger = logging.getLogger(__name__)
    logger.info("Welcome to RFVS - Router Firmware Vulnerability Scanner")
    logger.info("Type 'exit' to quit the tool at any prompt.")

def parse_args(input_string):
    parser = argparse.ArgumentParser(description="Router Firmware Vulnerability Scanner (RFVS)")
    parser.add_argument("-f", "--file", help="Path to the firmware file (e.g., firmware.bin)")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract firmware contents from file")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan firmware for vulnerabilities")
    parser.add_argument("-d", "--deep", action="store_true", help="Perform deep vulnerability scan")
    parser.add_argument("-c", "--cve", action="store_true", help="Perform CVE lookup")
    parser.add_argument("-x", "--exploit", action="store_true", help="Test exploits")
    parser.add_argument("-n", "--network", action="store_true", help="Perform network tests")
    parser.add_argument("-t", "--targets", action="store_true", help="Scan for network targets")
    parser.add_argument("-i", "--ip", help="Target IP address (e.g., 192.168.1.1)")
    parser.add_argument("-r", "--report", action="store_true", help="Generate a report")
    parser.add_argument("-o", "--output", default="report.txt", help="Output file for report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-X", "--extract-from-router", action="store_true", help="Extract firmware from router via SSH")
    parser.add_argument("--use-sample", action="store_true", help="Use DVRF sample firmware for testing")
    args = parser.parse_args(input_string.split())
    return args

def extract_from_router(ip, username=None, password=None, output_file="router_firmware.bin"):
    logger = logging.getLogger(__name__)
    logger.info(f"Attempting SSH firmware extraction from {ip}")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if username and password:
            ssh.connect(ip, username=username, password=password, timeout=10)
        else:
            logger.warning("No credentials provided; trying default or open access")
            ssh.connect(ip, timeout=10)  # Try without credentials

        stdin, stdout, stderr = ssh.exec_command("cat /proc/mtd")
        mtd_output = stdout.read().decode().strip()
        if not mtd_output:
            logger.error("SSH connected but no MTD info; access may be restricted")
            return None
        logger.info(f"MTD partitions:\n{mtd_output}")

        firmware_partition = None
        for line in mtd_output.splitlines():
            if "firmware" in line.lower() or "rootfs" in line.lower():
                firmware_partition = line.split(":")[0].strip()
                break
        if not firmware_partition:
            logger.error("No firmware partition found")
            return None

        dump_cmd = f"dd if=/dev/{firmware_partition} of=/tmp/firmware.bin"
        stdin, stdout, stderr = ssh.exec_command(dump_cmd)
        if stdout.channel.recv_exit_status() != 0:
            logger.error(f"Dump failed: {stderr.read().decode()}")
            return None

        with SCPClient(ssh.get_transport()) as scp:
            scp.get("/tmp/firmware.bin", output_file)
        ssh.exec_command("rm /tmp/firmware.bin")
        ssh.close()
        logger.info(f"Firmware extracted to {output_file}")
        return output_file
    except Exception as e:
        logger.error(f"SSH extraction failed: {e}")
        logger.info("Try default credentials, reset the router, or use --use-sample for DVRF.")
        return None

def main():
    logger = logging.getLogger(__name__)
    banner()
    findings = {}

    if not sys.argv.__contains__("-v"):
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.removeHandler(handler)

    while True:
        try:
            command = input("\nRFVS> ").strip()
            if command.lower() == "exit":
                logger.info("Exiting RFVS. Goodbye!")
                break
            if not command:
                logger.warning("Please enter a command. Use '-h' for help.")
                continue

            args = parse_args(command)
            if args.verbose:
                if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in logger.handlers):
                    logger.addHandler(logging.StreamHandler())

            # Use DVRF sample firmware if specified
            if args.use_sample:
                sample_path = "samples/DVRF/Firmware/DVRF_v03.bin"
                if os.path.exists(sample_path):
                    args.file = sample_path
                    logger.info(f"Using DVRF sample firmware: {sample_path}")
                else:
                    logger.error(f"DVRF sample not found at {sample_path}. Please download it.")
                    continue

            # Extract firmware from router if requested
            if args.extract_from_router:
                if not args.ip:
                    logger.error("Router IP (-i/--ip) required for extraction")
                    continue
                firmware_file = extract_from_router(args.ip)
                if firmware_file:
                    args.file = firmware_file
                else:
                    continue

            if not args.file and any([args.extract, args.scan, args.cve]):
                logger.error("Firmware file (-f/--file), extraction (-X), or sample (--use-sample) required")
                continue

            if args.file and not os.path.exists(args.file):
                logger.error(f"File '{args.file}' not found.")
                continue

            if args.targets:
                logger.info("Scanning for targets...")
                targets = scan_targets("192.168.1.0/24")
                findings["targets"] = targets
                logger.info(f"Found {len(targets)} targets: {[t['ip'] for t in targets]}")

            if args.extract:
                logger.info(f"Extracting firmware: {args.file}")
                extracted_dir = extract_firmware(args.file, verbose=args.verbose, overwrite=True, cleanup=False)
                if extracted_dir:
                    findings["extracted_dir"] = extracted_dir
                    if args.ip:
                        findings["target_ip"] = args.ip
                    logger.info(f"Extracted to: {extracted_dir}")
                else:
                    logger.error("Extraction failed.")

            if args.scan:
                if "extracted_dir" not in findings:
                    logger.error("Must extract firmware (-e/--extract) first")
                    continue
                logger.info("Scanning vulnerabilities..." + (" (deep)" if args.deep else ""))
                vulnerabilities = scan_vulnerabilities(findings["extracted_dir"], deep=args.deep)
                findings["vulnerabilities"] = vulnerabilities
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

            if args.cve:
                if "vulnerabilities" not in findings:
                    logger.error("Must scan (-s/--scan) first")
                    continue
                logger.info("Performing CVE lookup...")
                cve = CVESearch()
                for vuln in findings["vulnerabilities"]:
                    if "component" in vuln:
                        vuln["cve"] = [r["id"] for r in cve.search(vuln["component"])[:3]]
                logger.info("CVE lookup completed")

            if args.exploit:
                if "vulnerabilities" not in findings:
                    logger.error("Must scan (-s/--scan) first")
                    continue
                logger.info("Testing exploits...")
                targets = [{"ip": args.ip}] if args.ip else findings.get("targets", [{"ip": "192.168.1.1"}])
                exploit_results = test_exploits(findings["vulnerabilities"], args.verbose, targets, timeout=5)
                findings["exploit_results"] = exploit_results
                logger.info(f"Exploit results: {len(exploit_results)}")

            if args.network:
                target_ip = args.ip or findings.get("target_ip", "192.168.1.1")
                logger.info(f"Network tests on {target_ip}...")
                network_results = network_test(target_ip)
                findings["network_results"] = network_results
                logger.info(f"Network results: {len(network_results)}")

            if args.report:
                if not (args.scan or args.targets) or not (findings.get("vulnerabilities") or findings.get("targets")):
                    logger.error("Must scan (-s) or find targets (-t) first")
                    continue
                logger.info(f"Generating report: {args.output}")
                if generate_report(findings, args.output, verbose=args.verbose):
                    logger.info(f"Report saved to {args.output}")
                else:
                    logger.error("Report generation failed")

        except Exception as e:
            logger.error(f"Unexpected error: {e}")

def scan_targets(subnet):
    logger = logging.getLogger(__name__)
    results = []
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=0)
        for _, received in ans:
            results.append({"ip": received.psrc, "mac": received.hwsrc})
    except Exception as e:
        logger.error(f"Target scanning failed: {e}")
    return results

def network_test(target_ip):
    logger = logging.getLogger(__name__)
    results = []
    packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
    response = sr1(packet, timeout=2, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 18:
        results.append({"test": "Port 80 scan", "status": "open"})
    try:
        cmd = f"hping3 {target_ip} --flood --frag -c 100"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results.append({"test": "Firewall bypass", "status": "Attempted"})
    except Exception as e:
        logger.error(f"Firewall bypass failed: {e}")
        results.append({"test": "Firewall bypass", "status": "Failed"})
    return results

if __name__ == "__main__":
    main()