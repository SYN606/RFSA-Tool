from scanner.user_status_check import check_user_level
from scanner.network_scanner import NetworkScanner
from scanner.wifi_monitor import WiFiMonitor
from config.settings import CONFIG
from utils.helper import get_default_gateway, NetworkScanner
from utils.logger import log_info, log_warn
from analysis.sync import sync_nvd_feed
from analysis.firmware_checker import check_firmware
import json
import os
from datetime import datetime


def save_report(data, filename="report.json"):
    os.makedirs(CONFIG["report_output_path"], exist_ok=True)
    path = os.path.join(CONFIG["report_output_path"], filename)

    # Sort services by criticality if available
    def sort_key(entry):
        return entry.get("criticality", 0)

    data["network_scan"] = sorted(data.get("network_scan", []),
                                  key=sort_key,
                                  reverse=True)

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

    print(f"✅ Report saved to: {path}")


def main():
    # Sync the CVE database if needed
    sync_nvd_feed()

    report = {
        "timestamp": str(datetime.now()),
        "router_ip": None,
        "network_scan": [],
        "wifi_scan": [],
        "firmware_check": None,
    }

    # Detect router IP dynamically
    router_ip = get_default_gateway()
    if router_ip:
        log_info(f"Detected router IP: {router_ip}")
        report["router_ip"] = router_ip
    else:
        log_warn("Failed to detect router IP. Falling back to default.")

    # Firmware CVE check
    # Instead of manually inputting vendor, model, and version, we use automatic scanning
    vendor = model = version = None

    # Perform network scan and get device info
    network_range = input(
        "📍 Enter the network range to scan (default is 192.168.1.0/24): "
    ).strip()
    network_range = network_range or CONFIG.get("default_network_range",
                                                "192.168.1.0/24")

    scanner = NetworkScanner(network_range=network_range)
    devices = scanner.perform_scan()

    if devices:
        # Automatically take the first device details (assuming this is the router)
        first_device = devices[0]
        vendor = first_device["vendor"]
        model = first_device["model"]
        version = first_device["version"]

        print(
            f"✅ Detected router details from scan: Vendor={vendor}, Model={model}, Version={version}"
        )
    else:
        log_warn(
            "No devices found in the network scan. Please check the network configuration."
        )

    if vendor and model and version:
        print("🔍 Checking firmware CVEs...")
        check_firmware(vendor, model, version)
        report["firmware_check"] = {
            "vendor": vendor,
            "model": model,
            "version": version,
        }

    # Determine user access level
    user_access_level = check_user_level()

    if user_access_level == "admin":
        print("⚡ Admin detected. Proceeding with full network scan...")

        services = input(
            "🧰 Enter comma-separated services to filter (e.g., ssh,http): "
        ).strip()
        service_filter = services.split(",") if services else None

        scanner = NetworkScanner(network_range=network_range,
                                 service_filter=service_filter)
        result = scanner.perform_scan()
        report["network_scan"] = result or []

    else:
        print("⚠️ Normal user detected. Checking for monitor mode dongle...")

        use_monitor = input(
            "🔌 Do you have a monitor mode dongle (Y/N)? ").strip().lower()
        if use_monitor == 'y':
            interface = input(
                "   Enter monitor interface name (e.g., wlan1mon): ").strip()
            if interface:
                monitor = WiFiMonitor(interface=interface)
                wifi_result = monitor.scan()
                report["wifi_scan"] = wifi_result or []
            else:
                print(
                    "⚠️ No interface name provided. Skipping monitor mode scan."
                )
        else:
            print("🔍 Doing a basic user scan...")
            scanner = NetworkScanner(network_range=network_range,
                                     service_filter=None)
            result = scanner.perform_scan()
            report["network_scan"] = result or []

    # Save report
    save_report(report)


if __name__ == "__main__":
    main()
