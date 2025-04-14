from scanner.user_status_check import check_user_level
from scanner.network_scanner import NetworkScanner
from scanner.wifi_monitor import WiFiMonitor
from config.settings import CONFIG
from utils.helper import get_default_gateway
from utils.logger import log_info, log_warn


def main():
    """
    Main function to run RFSA based on user access level.
    Dynamically adapts scan based on whether the user has admin privileges,
    monitor mode dongle, or is a regular user.
    """
    # Detect router IP dynamically
    router_ip = get_default_gateway()
    if router_ip:
        log_info(f"Detected router IP: {router_ip}")
    else:
        log_warn(
            "Failed to detect router IP. Falling back to default if needed.")

    # Determine user's access level
    user_access_level = check_user_level()

    if user_access_level == "admin":
        print("⚡ Admin detected. Proceeding with full network scan...")

        network_range = input(
            "📍 Enter the network range to scan (default is 192.168.1.0/24): "
        ).strip()
        service_filter_input = input(
            "🧰 Enter comma-separated services to filter (e.g., ssh,http) or leave empty for all: "
        ).strip()

        network_range = network_range or CONFIG.get("default_network_range",
                                                    "192.168.1.0/24")
        service_filter = service_filter_input.split(
            ",") if service_filter_input else None

        scanner = NetworkScanner(network_range=network_range,
                                 service_filter=service_filter)
        scanner.perform_scan()

    else:
        print("⚠️ Normal user detected. Checking for monitor mode dongle...")

        monitor_mode_dongle = input(
            "🔌 Do you have a monitor mode dongle (Y/N)? ").strip().lower()

        if monitor_mode_dongle == 'y':
            monitor_interface = input(
                "   Enter the name of the monitor mode dongle interface (e.g., wlan1mon): "
            ).strip()

            if monitor_interface:
                print(
                    f"📡 Monitor mode dongle '{monitor_interface}' detected. Starting Wi-Fi scan..."
                )
                monitor = WiFiMonitor(interface=monitor_interface)
                monitor.scan()
            else:
                print(
                    "⚠️ No interface name provided. Aborting monitor mode scan."
                )
        else:
            print(
                "❌ No monitor mode dongle found. Proceeding with basic scan..."
            )

            network_range = input(
                "📍 Enter the network range to scan (default is 192.168.1.0/24): "
            ).strip()
            service_filter_input = input(
                "🧰 Enter comma-separated services to filter (e.g., ssh,http) or leave empty for all: "
            ).strip()

            network_range = network_range or CONFIG.get(
                "default_network_range", "192.168.1.0/24")
            service_filter = service_filter_input.split(
                ",") if service_filter_input else None

            scanner = NetworkScanner(network_range=network_range,
                                     service_filter=service_filter)
            scanner.perform_scan()


if __name__ == "__main__":
    main()
