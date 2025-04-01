# import os
# import sys
# import argparse
# import importlib
# import importlib.util
# from colorama import Fore, Style, init
# from functions import bruteforce

# # Initialize Colorama for colored output
# init(autoreset=True)

# ROOT_DIR = "functions"

# import importlib

# def load_function(module_name):
#     """Dynamically loads and executes a function from the functions package."""
#     try:
#         module = importlib.import_module(f"functions.{module_name}")

#         if hasattr(module, module_name):
#             print(f"[+] Running {module_name}...")
#             getattr(module, module_name)()  # Calls the function dynamically
#         else:
#             print(f"[ERROR] Function {module_name} not found in functions/{module_name}.py")
#     except Exception as e:
#         print(f"[ERROR] Failed to execute {module_name}: {e}")


# # def load_function(module_name):
# #     """Dynamically loads and executes a function from the functions directory."""
    
#     # try:
#     #     module_path = os.path.join(ROOT_DIR, f"{module_name}.py")

#     #     if not os.path.exists(module_path):
#     #         print(Fore.RED +
#     #               f"[ERROR] Function {module_name} not found in {ROOT_DIR}/")
#     #         return

#     #     # Load the module dynamically
#     #     spec = importlib.util.spec_from_file_location(module_name, module_path)
#     #     module = importlib.util.module_from_spec(spec)  # type: ignore
#     #     spec.loader.exec_module(module)  # type: ignore

#     #     # Check if the function exists and execute it
#     #     if hasattr(module, module_name):
#     #         print(Fore.GREEN + f"[+] Running {module_name}...")
#     #         getattr(module, module_name)()  # Calls scan(), bruteforce(), etc.
#     #     else:
#     #         print(
#     #             Fore.RED +
#     #             f"[ERROR] Function {module_name} not found in {module_name}.py"
#     #         )

#     # except Exception as e:
#     #     print(Fore.RED + f"[ERROR] Failed to execute {module_name}: {e}")

        


# def display_help():
#     """Displays help information about the tool."""
#     help_text = """
#     Router Exploit Tool - A Python-based tool for router penetration testing.
    
#     Usage:
#         python main.py [options]

#     Options:
#         -s, --scan          Scan the network for available routers.
#         -b, --bruteforce    Perform brute-force attack on the router login page.
#         -m, --mitm          Launch a Man-in-the-Middle (MITM) attack.
#         -d, --dns           Perform DNS spoofing attack.
#         -h, --help          Show this help message.

#     Examples:
#         python main.py --scan
#         python main.py --bruteforce -t 192.168.1.1
#         python main.py --mitm -v 192.168.1.2 -g 192.168.1.1

#     Notes:
#     - Use this tool **only for educational and ethical purposes**.
#     - Ensure you have permission before testing any network.
#     """
#     print(help_text)


# # Argument parser setup
# parser = argparse.ArgumentParser(
#     description="Router Exploit Tool - Ethical Hacking Utility")
# parser.add_argument("-s",
#                     "--scan",
#                     help="Scan the network for routers",
#                     action="store_true")
# parser.add_argument("-b",
#                     "--bruteforce",
#                     help="Perform brute-force attack",
#                     action="store_true")
# parser.add_argument("-m",
#                     "--mitm",
#                     help="Launch a Man-in-the-Middle attack",
#                     action="store_true")
# parser.add_argument("-d",
#                     "--dns",
#                     help="Perform DNS spoofing",
#                     action="store_true")
# parser.add_argument("-t", "--target", help="Specify target router IP")
# parser.add_argument("-v",
#                     "--victim",
#                     help="Specify victim IP (for MITM attack)")
# parser.add_argument("-g",
#                     "--gateway",
#                     help="Specify gateway IP (for MITM attack)")
# parser.add_argument("-H",
#                     "--help-module",
#                     help="Display help information",
#                     action="store_true")

# args = parser.parse_args()

# if args.help_module:
#     display_help()
#     exit()

# RED = "\033[91m"
# GREEN = "\033[92m"
# YELLOW = "\033[93m"
# BLUE = "\033[94m"
# CYAN = "\033[96m"
# RESET = "\033[0m"  # Resets color to default


# def banner():
#     print(Fore.RED + Style.BRIGHT + r'''
#     ____          ______        _____         ___ 
#    / __ \        / ____/       / ___/        /   |
#   / /_/ /       / /_           \__ \        / /| |
#  / _, _/  _    / __/    _     ___/ /  _    / ___ |
# /_/ |_|  (_)  /_/      (_)   /____/  (_)  /_/  |_|

# ROUTER      FIRMWARE        SECURITY        ANALYSIS

# ''' + Style.RESET_ALL)


# def main():
#     banner()
#     while True:  # Infinite loop until user exits
#         cmd = input(Fore.YELLOW + Style.BRIGHT + "Router Exploit Tool> " +
#                     Style.RESET_ALL).strip().lower()

#         if cmd == "exit":
#             print(Fore.GREEN + "[+] Exiting...")
#             sys.exit(0)  # Exits the program safely

#         elif cmd == "help":
#             display_help()

#         elif cmd == "scan":
#             load_function("scan")

#         elif cmd == "bruteforce":
#             load_function("bruteforce")

#         elif cmd == "mitm":
#             load_function("mitm")

#         elif cmd == "dns":
#             load_function("dns")

#         else:
#             print(Fore.RED +
#                   "[-] Unknown command. Type 'help' for available commands.")


# if __name__ == "__main__":
#     main()

import argparse
import sys
import os
import subprocess
from extract import extract_firmware
from rsv.scan import scan_vulnerabilities
from report import generate_report
from exploit import test_exploits
from pycvesearch import CVESearch
from scapy.all import *
from colorama import *

def banner():
    print(Fore.RED + Style.BRIGHT + r'''
    ____          ______        _____         ___ 
   / __ \        / ____/       / ___/        /   |
  / /_/ /       / /_           \__ \        / /| |
 / _, _/  _    / __/    _     ___/ /  _    / ___ |
/_/ |_|  (_)  /_/      (_)   /____/  (_)  /_/  |_|

ROUTER      FIRMWARE        SECURITY        ANALYSIS

''' + Style.RESET_ALL)
    
def parse_args(input_string):
    """Parse arguments from a string input."""
    parser = argparse.ArgumentParser(description="Router Firmware Vulnerability Scanner (RFVS)")
    parser.add_argument("-f", "--file", help="Path to the firmware file (e.g., firmware.bin)")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract firmware contents")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan firmware for vulnerabilities")
    parser.add_argument("-d", "--deep", action="store_true", help="Perform deep vulnerability scan (slower, more thorough)")
    parser.add_argument("-c", "--cve", action="store_true", help="Perform CVE lookup on firmware components")
    parser.add_argument("-x", "--exploit", action="store_true", help="Test exploits on detected vulnerabilities")
    parser.add_argument("-n", "--network", action="store_true", help="Perform network-based tests (e.g., port scanning, firewall bypass)")
    parser.add_argument("-t", "--targets", action="store_true", help="Scan for potential targets on the network")
    parser.add_argument("-r", "--report", action="store_true", help="Generate a report")
    parser.add_argument("-o", "--output", default="report.txt", help="Output file for the report (default: report.txt)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # Allow parsing from string input
    args = parser.parse_args(input_string.split())
    return args

def main():
    banner()
    findings = {}  # Persistent findings across commands

    while True:
        try:
            command = input("\nRFVS> ").strip()
            if command.lower() == "exit":
                print("Exiting RFVS. Goodbye!")
                break
            if not command:
                print("Please enter a command. Use '-h' for help.")
                continue

            # Parse the command as arguments
            args = parse_args(command)

            # Check if firmware file is provided when required
            if not args.file and any([args.extract, args.scan, args.cve, args.exploit, args.report]):
                print("Error: Firmware file (-f/--file) is required for this operation.")
                continue

            if args.file and not os.path.exists(args.file):
                print(f"Error: File '{args.file}' not found.")
                continue

            # Process commands
            if args.targets:
                if args.verbose:
                    print("Scanning for potential targets...")
                targets = scan_targets("192.168.1.0/24")  # Adjust subnet as needed
                findings["targets"] = targets
                print(f"Found {len(targets)} targets.")

            if args.extract:
                if args.verbose:
                    print(f"Extracting firmware: {args.file}")
                extracted_dir = extract_firmware(args.file)
                if extracted_dir:
                    findings["extracted_dir"] = extracted_dir
                    print(f"Extracted to: {extracted_dir}")
                else:
                    print("Extraction failed.")

            if args.scan:
                if "extracted_dir" not in findings:
                    print("Error: Must extract firmware (-e/--extract) before scanning.")
                    continue
                if args.verbose:
                    print("Scanning for vulnerabilities..." + (" (deep mode)" if args.deep else " (quick mode)"))
                vulnerabilities = scan_vulnerabilities(findings["extracted_dir"], deep=args.deep)
                findings["vulnerabilities"] = vulnerabilities
                print(f"Found {len(vulnerabilities) if isinstance(vulnerabilities, list) else 0} vulnerabilities.")

            if args.cve:
                if "vulnerabilities" not in findings:
                    print("Error: Must scan firmware (-s/--scan) before CVE lookup.")
                    continue
                if args.verbose:
                    print("Performing CVE lookup...")
                cve = CVESearch()
                for vuln in findings["vulnerabilities"]:
                    if "component" in vuln:
                        results = cve.search(vuln["component"])
                        vuln["cve"] = [r["id"] for r in results[:3]]
                print("CVE lookup completed.")

            if args.exploit:
                if "vulnerabilities" not in findings:
                    print("Error: Must scan firmware (-s/--scan) before exploiting.")
                    continue
                if args.verbose:
                    print("Testing exploits...")
                exploit_results = test_exploits(findings["vulnerabilities"], args.verbose)
                findings["exploit_results"] = exploit_results
                print(f"Exploit tests completed: {len(exploit_results)} results.")

            if args.network:
                if args.verbose:
                    print("Performing network tests...")
                network_results = network_test("192.168.1.1")  # Replace with target IP
                findings["network_results"] = network_results
                print(f"Network tests completed: {len(network_results)} results.")

            if args.report:
                if not (args.scan or args.targets) or ("vulnerabilities" not in findings and "targets" not in findings):
                    print("Error: Must scan (-s/--scan) or find targets (-t/--targets) before generating a report.")
                    continue
                if args.verbose:
                    print(f"Generating report: {args.output}")
                generate_report(findings, args.output)
                print(f"Report saved to {args.output}")

            if not any([args.extract, args.scan, args.cve, args.exploit, args.network, args.targets, args.report]):
                print("No valid operations specified. Use '-h' for help.")

        except KeyboardInterrupt:
            print("\nInterrupted by user. Type 'exit' to quit or continue with a new command.")
        except Exception as e:
            print(f"Error: {e}. Please try again.")

def scan_targets(subnet):
    """Scan the network for potential router targets."""
    results = []
    conf.verb = 0  # Suppress Scapy output
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2)
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        results.append({"ip": ip, "mac": mac})
    return results

def network_test(target_ip):
    """Perform network tests including port scan and firewall bypass."""
    results = []
    packet = IP(dst=target_ip)/TCP(dport=80, flags="S")
    response = sr1(packet, timeout=2, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == 18:  # SYN-ACK
        results.append({"test": "Port 80 scan", "status": "open"})
    try:
        cmd = f"hping3 {target_ip} --flood --frag -c 100"  # Limited to 100 packets
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        results.append({"test": "Firewall bypass (fragmented flood)", "status": "Attempted"})
    except:
        results.append({"test": "Firewall bypass", "status": "Failed"})
    return results

if __name__ == "__main__":
    main()