import os
import sys
import argparse
import importlib
import importlib.util
from colorama import Fore, Style, init
from functions import bruteforce

# Initialize Colorama for colored output
init(autoreset=True)

ROOT_DIR = "functions"

import importlib

def load_function(module_name):
    """Dynamically loads and executes a function from the functions package."""
    try:
        module = importlib.import_module(f"functions.{module_name}")

        if hasattr(module, module_name):
            print(f"[+] Running {module_name}...")
            getattr(module, module_name)()  # Calls the function dynamically
        else:
            print(f"[ERROR] Function {module_name} not found in functions/{module_name}.py")
    except Exception as e:
        print(f"[ERROR] Failed to execute {module_name}: {e}")


# def load_function(module_name):
#     """Dynamically loads and executes a function from the functions directory."""
    
    # try:
    #     module_path = os.path.join(ROOT_DIR, f"{module_name}.py")

    #     if not os.path.exists(module_path):
    #         print(Fore.RED +
    #               f"[ERROR] Function {module_name} not found in {ROOT_DIR}/")
    #         return

    #     # Load the module dynamically
    #     spec = importlib.util.spec_from_file_location(module_name, module_path)
    #     module = importlib.util.module_from_spec(spec)  # type: ignore
    #     spec.loader.exec_module(module)  # type: ignore

    #     # Check if the function exists and execute it
    #     if hasattr(module, module_name):
    #         print(Fore.GREEN + f"[+] Running {module_name}...")
    #         getattr(module, module_name)()  # Calls scan(), bruteforce(), etc.
    #     else:
    #         print(
    #             Fore.RED +
    #             f"[ERROR] Function {module_name} not found in {module_name}.py"
    #         )

    # except Exception as e:
    #     print(Fore.RED + f"[ERROR] Failed to execute {module_name}: {e}")

        


def display_help():
    """Displays help information about the tool."""
    help_text = """
    Router Exploit Tool - A Python-based tool for router penetration testing.
    
    Usage:
        python main.py [options]

    Options:
        -s, --scan          Scan the network for available routers.
        -b, --bruteforce    Perform brute-force attack on the router login page.
        -m, --mitm          Launch a Man-in-the-Middle (MITM) attack.
        -d, --dns           Perform DNS spoofing attack.
        -h, --help          Show this help message.

    Examples:
        python main.py --scan
        python main.py --bruteforce -t 192.168.1.1
        python main.py --mitm -v 192.168.1.2 -g 192.168.1.1

    Notes:
    - Use this tool **only for educational and ethical purposes**.
    - Ensure you have permission before testing any network.
    """
    print(help_text)


# Argument parser setup
parser = argparse.ArgumentParser(
    description="Router Exploit Tool - Ethical Hacking Utility")
parser.add_argument("-s",
                    "--scan",
                    help="Scan the network for routers",
                    action="store_true")
parser.add_argument("-b",
                    "--bruteforce",
                    help="Perform brute-force attack",
                    action="store_true")
parser.add_argument("-m",
                    "--mitm",
                    help="Launch a Man-in-the-Middle attack",
                    action="store_true")
parser.add_argument("-d",
                    "--dns",
                    help="Perform DNS spoofing",
                    action="store_true")
parser.add_argument("-t", "--target", help="Specify target router IP")
parser.add_argument("-v",
                    "--victim",
                    help="Specify victim IP (for MITM attack)")
parser.add_argument("-g",
                    "--gateway",
                    help="Specify gateway IP (for MITM attack)")
parser.add_argument("-H",
                    "--help-module",
                    help="Display help information",
                    action="store_true")

args = parser.parse_args()

if args.help_module:
    display_help()
    exit()

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"  # Resets color to default


def banner():
    print(Fore.RED + Style.BRIGHT + r'''
    ____          ______        _____         ___ 
   / __ \        / ____/       / ___/        /   |
  / /_/ /       / /_           \__ \        / /| |
 / _, _/  _    / __/    _     ___/ /  _    / ___ |
/_/ |_|  (_)  /_/      (_)   /____/  (_)  /_/  |_|

ROUTER      FIRMWARE        SECURITY        ANALYSIS

''' + Style.RESET_ALL)


def main():
    banner()
    while True:  # Infinite loop until user exits
        cmd = input(Fore.YELLOW + Style.BRIGHT + "Router Exploit Tool> " +
                    Style.RESET_ALL).strip().lower()

        if cmd == "exit":
            print(Fore.GREEN + "[+] Exiting...")
            sys.exit(0)  # Exits the program safely

        elif cmd == "help":
            display_help()

        elif cmd == "scan":
            load_function("scan")

        elif cmd == "bruteforce":
            load_function("bruteforce")

        elif cmd == "mitm":
            load_function("mitm")

        elif cmd == "dns":
            load_function("dns")

        else:
            print(Fore.RED +
                  "[-] Unknown command. Type 'help' for available commands.")


if __name__ == "__main__":
    main()
