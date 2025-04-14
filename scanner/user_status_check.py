import requests
import time
import re
import urllib3
from colorama import Fore, Style
from config.settings import CONFIG
from utils.helper import get_default_gateway
from utils.logger import log_info, log_warn, log_error
from scanner.network_scanner import NetworkScanner

# Suppress HTTPS warnings if verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def is_router_accessible(ip, retries=3):
    """
    Tries to access the router's login page using HTTP (fallback to HTTPS).
    Retries in case of failure.
    """

    def try_request(protocol="http"):
        try:
            url = f"{protocol}://{ip}"
            r = requests.get(url, timeout=CONFIG['timeout'], verify=False)
            if r.status_code in [200, 401, 403]:
                print(
                    Fore.GREEN +
                    f"✅ {protocol.upper()} access to router successful (Status: {r.status_code})"
                )
                return True, r.text
            elif r.status_code in [301, 302]:
                print(
                    Fore.YELLOW +
                    f"➡️ {protocol.upper()} redirected (Status: {r.status_code})"
                )
                return True, f"Redirected ({r.status_code})"
            else:
                print(
                    Fore.RED +
                    f"⚠️ {protocol.upper()} access failed: Unexpected status code {r.status_code}"
                )
                return False, f"Unexpected status code: {r.status_code}"
        except requests.exceptions.RequestException as e:
            print(Fore.RED + f"❌ {protocol.upper()} access failed: {e}")
            return False, str(e)

    attempt = 0
    while attempt < retries:
        accessible, response = try_request("http")
        if accessible:
            return accessible, response

        accessible, response = try_request("https")
        if accessible:
            return accessible, response

        attempt += 1
        if attempt < retries:
            print(Fore.CYAN +
                  f"🔁 Retrying router access... ({attempt}/{retries})")
            time.sleep(2)
        else:
            print(
                Fore.RED +
                f"❌ Failed to access router at {ip} after {retries} attempts.")
            return False, response

    return False, "Max retries reached"


def analyze_admin_possibility(page_text):
    """
    Analyzes page content for possible admin login signs using regex.
    """
    patterns = [
        r"admin\s?login", r"router\s?settings", r"login\s?form",
        r"authentication", r"admin\s?panel", r"change\s?password",
        r"system\s?settings", r"firmware\s?update", r"user\s?management"
    ]
    for pattern in patterns:
        if re.search(pattern, page_text, re.IGNORECASE):
            return True
    return False


def check_user_level():
    """
    Determines user access level by attempting to reach the router's login interface.
    Also fetches vendor, model, and version information if possible.
    """
    print("🔍 Checking router access level...")

    # Get the router IP
    router_ip = get_default_gateway() or CONFIG['default_router_ip']
    log_info(f"Router IP detected: {router_ip}")

    # Try accessing router
    accessible, page_text = is_router_accessible(router_ip)

    if not accessible:
        print("❌ Cannot access router login page. Assuming normal user.")
        log_warn("Cannot access router login page. Assuming normal user.")
        return "normal", None  # Returning 'None' as we won't scan for vendor/model/version

    # Optional: print trimmed response for debugging
    if CONFIG.get("debug"):
        print("📄 Response snippet:\n" + page_text[:200])

    # Analyze for signs of admin login
    if analyze_admin_possibility(page_text):
        print("✅ Router login page detected. You may have admin access.")
        log_info("Router login page detected, potential admin access.")

        # If admin, perform a network scan to get router details
        print("🔍 Performing network scan to detect router details...")
        network_scanner = NetworkScanner(
            network_range=f"{router_ip}/24"
        )  # Assuming the /24 subnet for the router
        devices = network_scanner.perform_scan()

        # Attempt to extract router's vendor, model, and version
        for device in devices: # type: ignore
            if device["ip"] == router_ip:
                vendor = device["vendor"]
                model = device["model"]
                version = device["version"]
                print(
                    f"🔍 Found router details: Vendor: {vendor}, Model: {model}, Version: {version}"
                )
                return "admin", {
                    "vendor": vendor,
                    "model": model,
                    "version": version
                }
        return "admin", None

    print("⚠️ Router is reachable but no clear admin access detected.")
    log_warn("Router is reachable but no clear admin access detected.")
    return "normal", None  # If no admin access, return normal and no details


# Example usage
user_level, router_info = check_user_level()
if user_level == "admin" and router_info:
    print(f"Admin access confirmed. Router info: {router_info}")
else:
    print("Normal user or no router details found.")
