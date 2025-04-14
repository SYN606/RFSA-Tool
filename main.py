import os
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


def main():
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
    network_range = input(
        "📍 Enter network range (default: 192.168.1.0/24): ").strip()
    network_range = network_range or CONFIG.get("default_network_range",
                                                "192.168.1.0/24")

    # Step 5: Perform initial scan to attempt firmware CVE lookup
    base_scanner = NetworkScanner(network_range=network_range)
    scanned_devices = base_scanner.perform_scan()

    if scanned_devices:
        first_device = scanned_devices[0]
        vendor = first_device.get("vendor")
        model = first_device.get("model")
        version = first_device.get("version")

        if vendor and model and version:
            print(
                f"✅ Found device: Vendor={vendor}, Model={model}, Version={version}"
            )
            print("🔍 Checking firmware CVEs...")
            check_firmware(vendor, model, version)
            report["firmware_check"] = {
                "vendor": vendor,
                "model": model,
                "version": version,
            }
        else:
            log_warn(
                "⚠️ Incomplete device info — skipping firmware CVE check.")
    else:
        log_warn("⚠️ No devices found during scan.")

    # Step 6: Check user access level
    user_level, router_info = check_user_level()

    if user_level == "admin":
        print("🛠 Admin access confirmed. Running advanced scan.")
        services = input(
            "🧰 Enter comma-separated services to filter (e.g., ssh,http): "
        ).strip()
        service_filter = [s.strip()
                          for s in services.split(",")] if services else None

        scanner = NetworkScanner(network_range=network_range,
                                 service_filter=service_filter)
        report["network_scan"] = scanner.perform_scan() or []

    else:
        print("👤 Normal user detected.")
        use_monitor = input(
            "📡 Do you have a monitor mode dongle? (Y/N): ").strip().lower()

        if use_monitor == "y":
            interface = input(
                "🔌 Enter monitor interface (press Enter to use default): "
            ).strip()
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
    save_report(report)


if __name__ == "__main__":
    main()
