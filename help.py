import argparse

def display_help():
    """Displays help information about the tool"""
    help_text = """
    Router Exploit Tool - A Python-based tool for router penetration testing.
    
    Usage:
        python exploit_tool.py [options]

    Options:
        -s, --scan          Scan the network for available routers.
        -b, --bruteforce    Perform brute-force attack on the router login page.
        -m, --mitm          Launch a Man-in-the-Middle (MITM) attack.
        -d, --dns           Perform DNS spoofing attack.
        -h, --help          Show this help message.

    Examples:
        python exploit_tool.py --scan
        python exploit_tool.py --bruteforce -t 192.168.1.1
        python exploit_tool.py --mitm -v 192.168.1.2 -g 192.168.1.1

    Notes:
    - Use this tool **only for educational and ethical purposes**.
    - Ensure you have permission before testing any network.
    """
    print(help_text)

# Argument parser setup
parser = argparse.ArgumentParser(description="Router Exploit Tool - Ethical Hacking Utility")
parser.add_argument("-s", "--scan", help="Scan the network for routers", action="store_true")
parser.add_argument("-b", "--bruteforce", help="Perform brute-force attack", action="store_true")
parser.add_argument("-m", "--mitm", help="Launch a Man-in-the-Middle attack", action="store_true")
parser.add_argument("-d", "--dns", help="Perform DNS spoofing", action="store_true")
parser.add_argument("-t", "--target", help="Specify target router IP")
parser.add_argument("-v", "--victim", help="Specify victim IP (for MITM attack)")
parser.add_argument("-g", "--gateway", help="Specify gateway IP (for MITM attack)")
parser.add_argument("-H", "--help-module", help="Display help information", action="store_true")

args = parser.parse_args()

if args.help_module:
    display_help()
    exit()

if args.help_module:
    display_help()