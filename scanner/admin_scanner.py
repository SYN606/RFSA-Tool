from scanner.network_scanner import NetworkScanner
from scanner.wifi_monitor import WiFiMonitor
from scanner.user_status_check import check_user_level
from config.settings import CONFIG
from utils.logger import log_info, log_warn
import sys
import json
import os
from datetime import datetime


def save_admin_scan_report(report, filename="admin_scan_report.json"):
    """
    Saves the admin scan report to a file.
    """
    output_dir = CONFIG.get("report_output_path", "reporting/output")
    os.makedirs(output_dir, exist_ok=True)
    full_path = os.path.join(output_dir, filename)

    with open(full_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"✅ Admin scan report saved at: {full_path}")


def perform_admin_scan():
    """
    Perform a full scan for admin users:
    - Network scan
    - Wi-Fi scan (if monitor interface is configured)
    """
    print("🔍 Performing admin scan...")
    report = {
        "timestamp": str(datetime.now()),
        "network_scan": [],
        "wifi_scan": [],
    }

    try:
        # Step 1: Network scan
        network_range = CONFIG.get("default_network_range", "192.168.1.0/24")
        network_scanner = NetworkScanner(network_range=network_range)
        network_results = network_scanner.perform_scan()
        report["network_scan"] = network_results or []
        log_info(f"Scanned {len(network_results)} network devices.") # type: ignore
    except Exception as e:
        log_warn(f"⚠️ Network scan failed: {e}")

    try:
        # Step 2: Wi-Fi scan
        monitor_interface = CONFIG.get("monitor_interface")
        if monitor_interface:
            wifi_scanner = WiFiMonitor(interface=monitor_interface)
            wifi_results = wifi_scanner.scan(duration=30)
            report["wifi_scan"] = wifi_results or []
            log_info(f"Captured {len(wifi_results)} Wi-Fi signals.")
        else:
            log_warn(
                "⚠️ Monitor interface not configured. Skipping Wi-Fi scan.")
    except Exception as e:
        log_warn(f"⚠️ Wi-Fi scan failed: {e}")

    save_admin_scan_report(report)


if __name__ == "__main__":
    user_access_level, _ = check_user_level()

    if user_access_level == "admin":
        perform_admin_scan()
    else:
        print("❌ Access denied: User does not have admin privileges.")
        sys.exit(1)
