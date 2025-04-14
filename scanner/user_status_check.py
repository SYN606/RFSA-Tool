import requests
import time
import re
import urllib3
from colorama import Fore
from config.settings import CONFIG
from utils.helper import get_default_gateway
from utils.logger import log_info, log_warn, log_error
from scanner.network_scanner import NetworkScanner
from ipaddress import ip_address, ip_network

# Suppress SSL warnings if verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_router_accessible(ip, retries=3):
    """
    Attempts HTTP/HTTPS access to the router IP. Returns (bool, content).
    """

    def try_request(protocol="http"):
        try:
            url = f"{protocol}://{ip}"
            response = requests.get(url,
                                    timeout=CONFIG['timeout'],
                                    verify=False)
            status = response.status_code
            if status in [200, 401, 403]:
                print(
                    Fore.GREEN +
                    f"✅ {protocol.upper()} access succeeded (Status: {status})"
                )
                return True, response.text
            elif status in [301, 302]:
                print(Fore.YELLOW +
                      f"➡️ {protocol.upper()} redirected (Status: {status})")
                return True, f"Redirect ({status})"
            else:
                print(
                    Fore.RED +
                    f"⚠️ Unexpected status code {status} on {protocol.upper()}"
                )
                return False, f"Unexpected status code: {status}"
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"❌ {protocol.upper()} access error: {e}")
            return False, str(e)

    for attempt in range(1, retries + 1):
        for proto in ("http", "https"):
            accessible, result = try_request(proto)
            if accessible:
                return True, result
        if attempt < retries:
            print(Fore.CYAN + f"🔁 Retry attempt {attempt}/{retries}...")
            time.sleep(2)

    print(
        Fore.RED +
        f"❌ All access attempts to router ({ip}) failed after {retries} retries."
    )
    return False, "Max retries reached"


def analyze_admin_possibility(page_text):
    """
    Detects admin panel signs in page content.
    """
    patterns = [
        r"admin\s?login", r"router\s?settings", r"login\s?form",
        r"authentication", r"admin\s?panel", r"change\s?password",
        r"system\s?settings", r"firmware\s?update", r"user\s?management"
    ]
    return any(re.search(p, page_text, re.IGNORECASE) for p in patterns)


def check_user_level():
    """
    Detects whether the current user has admin access to the router.
    If admin, attempts to identify router vendor, model, and version.
    """
    print(Fore.CYAN + "\n🔍 Checking for router admin access...")

    router_ip = get_default_gateway() or CONFIG.get('default_router_ip')
    if not router_ip:
        log_error("No router IP found.")
        return "unknown", None

    log_info(f"Router IP: {router_ip}")

    try:
        ip_address(router_ip)  # Validate format
    except ValueError:
        log_error(f"Invalid router IP: {router_ip}")
        return "unknown", None

    accessible, page_text = is_router_accessible(router_ip)

    if not accessible:
        log_warn("Router access failed, assuming normal user.")
        return "normal", None

    if CONFIG.get("debug"):
        print(Fore.LIGHTBLACK_EX + "\n📄 Response snippet:\n" + page_text[:250])

    if analyze_admin_possibility(page_text):
        print(Fore.GREEN + "✅ Admin interface likely accessible.")
        log_info("Admin panel detected via login page analysis.")

        # Scan network for router info
        print(Fore.CYAN + "🔍 Scanning local network for router details...")
        subnet_guess = f"{router_ip}/24"
        scanner = NetworkScanner(network_range=subnet_guess)
        devices = scanner.perform_scan()

        for device in devices:  # type: ignore
            if device.get("ip") == router_ip:
                vendor = device.get("vendor", "Unknown")
                model = device.get("model", "Unknown")
                version = device.get("version", "Unknown")
                print(
                    Fore.MAGENTA +
                    f"📦 Router Info → Vendor: {vendor}, Model: {model}, Version: {version}"
                )
                return "admin", {
                    "vendor": vendor,
                    "model": model,
                    "version": version
                }

        return "admin", None

    print(Fore.YELLOW +
          "⚠️ Router is reachable, but no clear admin interface detected.")
    log_warn("No admin markers found on router page.")
    return "normal", None


# For testing/debugging
if __name__ == "__main__":
    user_level, router_info = check_user_level()
    if user_level == "admin" and router_info:
        print(Fore.GREEN +
              f"\n🎉 Admin access confirmed. Router info: {router_info}")
    elif user_level == "admin":
        print(Fore.GREEN +
              "\n✅ Admin access confirmed. No detailed router info retrieved.")
    else:
        print(Fore.YELLOW + "\n👤 Normal user or insufficient router access.")
