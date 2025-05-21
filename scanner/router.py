import requests
import urllib3
from config.settings import CONFIG
from utils.helper import get_default_gateway
from utils.logger import log_warn
from scanner.network_scanner import NetworkScanner
from colorama import Fore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_router():
    """
    Attempt to contact router and retrieve vendor info.
    """
    router_ip = get_default_gateway() or CONFIG.get('default_router_ip')
    if not router_ip:
        log_warn("No router IP found.")
        return None

    print(Fore.CYAN + f"\n🌐 Attempting to connect to router at {router_ip}")
    try:
        response = requests.get(f"http://{router_ip}", timeout=CONFIG['timeout'], verify=False)
        print(Fore.GREEN + f"✅ HTTP connection succeeded with status {response.status_code}")
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ HTTP connection failed: {e}")

    # Use ARP scan to detect router vendor info
    subnet = f"{router_ip}/24"
    scanner = NetworkScanner(network_range=subnet)
    scanner.scan_devices()

    for device in scanner.devices:
        if device['ip'] == router_ip:
            return {
                'ip': device['ip'],
                'mac': device['mac'],
                'vendor': device['vendor']
            }

    return None
