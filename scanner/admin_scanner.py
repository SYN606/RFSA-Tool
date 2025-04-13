from network_scanner import NetworkScanner
from wifi_monitor import WiFiMonitor
from user_status_check import check_user_level
from config.settings import CONFIG
from utils.logger import log_info, log_warn
import sys


def perform_admin_scan():
    """
    Perform a full scan for admin users.
    Includes network scanning and Wi-Fi scanning.
    """
    print("🔍 Performing admin scan...")

    # Step 1: Perform a full network scan
    network_scanner = NetworkScanner(
        network_range=CONFIG['default_network_range'])
    network_scanner.perform_scan()  # Scan devices and services

    # Step 2: Perform a Wi-Fi scan (since user has admin access)
    wifi_scanner = WiFiMonitor(interface=CONFIG['monitor_interface'])
    wifi_scanner.scan(duration=30)  # Scan for nearby Wi-Fi networks


if __name__ == "__main__":
    user_access_level = check_user_level(
    )  # Check if the user has admin access

    if user_access_level == "admin":
        perform_admin_scan()  # Perform the scan as an admin
    else:
        print("❌ Access denied: User does not have admin privileges.")
        sys.exit(1)
