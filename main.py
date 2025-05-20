import os
import sys
from datetime import datetime
from scanner.user_status_check import check_user_level
from scanner.network_scanner import NetworkScanner
from scanner.wifi_monitor import WiFiMonitor
from config.settings import CONFIG
from utils.helper import get_default_gateway
from utils.logger import log_info, log_warn
from analysis.sync import sync_nvd_feed
from analysis.firmware_checker import check_firmware
from reporting.report_writer import save_report
import ipaddress

def validate_network_range(network_range):
    try:
        ipaddress.ip_network(network_range)
        return True
    except ValueError:
        return False

def prompt_network_range():
    default_range = CONFIG.get("default_network_range", "192.168.1.0/24")
    while True:
        user_input = input(f"📍 Enter network range (default: {default_range}): ").strip()
        network_range = user_input or default_range
        if validate_network_range(network_range):
            return network_range
        else:
            print("❌ Invalid network range. Please enter a valid CIDR (e.g., 192.168.1.0/24).")

def prompt_service_filter():
    services = input("🧰 Enter comma-separated services to filter (e.g., ssh,http), or press Enter for all: ").strip()
    if services:
        return [s.strip() for s in services.split(",") if s.strip()]
    return None

def select_device(devices):
    if not devices:
        return None
    if len(devices) == 1:
        return devices[0]
    print("\nMultiple devices found. Select the router device for firmware check:")
    for idx, dev in enumerate(devices, 1):
        desc = f"{dev.get('ip', 'unknown')} | {dev.get('vendor', 'unknown')} {dev.get('model', '')} {dev.get('version', '')}"
        print(f"  [{idx}] {desc}")
    while True:
        choice = input(f"Enter device number (1-{len(devices)}), or press Enter to skip: ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            return devices[int(choice) - 1]
        print("❌ Invalid selection.")

def main():
    try:
        # Step 1: Sync CVE database
        sync_nvd_feed()

        # Step 2: Initialize report structure
        report = {
            "timestamp": str(datetime.now()),
            "router_ip": None,
            "network_scan": [],
            "wifi_scan": [],
            "firmware_check": None,
        }

        # Step 3: Detect router IP
        router_ip = get_default_gateway()
        if router_ip:
            log_info(f"Detected router IP: {router_ip}")
            report["router_ip"] = router_ip
        else:
            log_warn("Failed to detect router IP. Continuing without router IP.")

        # Step 4: Ask for network range
        network_range = prompt_network_range()

        # Step 5: Perform initial scan to attempt firmware CVE lookup
        base_scanner = NetworkScanner(network_range=network_range)
        scanned_devices = base_scanner.perform_scan()

        device_for_firmware = select_device(scanned_devices)
        if device_for_firmware:
            vendor = device_for_firmware.get("vendor")
            model = device_for_firmware.get("model")
            version = device_for_firmware.get("version")
            if vendor and model and version:
                print(f"✅ Selected device: Vendor={vendor}, Model={model}, Version={version}")
                print("🔍 Checking firmware CVEs...")
                check_firmware(vendor, model, version)
                report["firmware_check"] = {
                    "vendor": vendor,
                    "model": model,
                    "version": version,
                }
            else:
                log_warn("⚠️ Incomplete device info — skipping firmware CVE check.")
        else:
            log_warn("⚠️ No device selected for firmware check.")

        # Step 6: Check user access level
        user_level, router_info = check_user_level()

        if user_level == "admin":
            print("🛠 Admin access confirmed. Running advanced scan.")
            service_filter = prompt_service_filter()
            scanner = NetworkScanner(network_range=network_range, service_filter=service_filter)
            report["network_scan"] = scanner.perform_scan() or []
        else:
            print("👤 Normal user detected.")
            use_monitor = input("📡 Do you have a monitor mode dongle? (Y/N): ").strip().lower()
            if use_monitor == "y":
                interface = input("🔌 Enter monitor interface (press Enter to use default): ").strip()
                interface = interface or CONFIG.get("monitor_interface")
                if interface:
                    wifi_scanner = WiFiMonitor(interface)
                    report["wifi_scan"] = wifi_scanner.scan() or []
                else:
                    print("⚠️ No monitor interface provided. Skipping Wi-Fi scan.")
            else:
                print("🔍 Performing fallback basic network scan...")
                fallback_scanner = NetworkScanner(network_range)
                report["network_scan"] = fallback_scanner.perform_scan() or []

        # Step 7: Save the full report
        report_path = save_report(report)
        print(f"✅ Report saved to: {report_path}")

    except Exception as e:
        log_warn(f"Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
