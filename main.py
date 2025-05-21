from scanner.network_scanner import NetworkScanner
from scanner.wifi_monitor import WiFiMonitor
from config.settings import CONFIG
from colorama import Fore, init

init(autoreset=True)

def start_lan_scan():
    network_range = input(
        "🌐 Enter network range to scan (default is 192.168.1.0/24): ").strip()
    service_input = input(
        "⚙️ Filter by services (e.g., ssh,http) or leave empty: ").strip()

    service_filter = service_input.split(",") if service_input else None
    network_range = network_range or CONFIG.get("default_network_range", "192.168.1.0/24")

    scanner = NetworkScanner(network_range=network_range, service_filter=service_filter)
    results = scanner.perform_scan()

    if results:
        print(Fore.GREEN + f"\n✅ Scan complete. {len(results)} devices found.")
    else:
        print(Fore.YELLOW + "\n⚠️ No results to display.")

def start_wifi_monitor_scan():
    interface = input("📡 Enter monitor mode interface (default as per config): ").strip()
    monitor = WiFiMonitor(interface=interface or CONFIG.get("monitor_interface"))
    results = monitor.scan(duration=20)

    if results:
        print(Fore.GREEN + f"\n✅ Wi-Fi scan complete. {len(results)} networks found.")
    else:
        print(Fore.YELLOW + "\n⚠️ No Wi-Fi networks found.")

def main():
    print(Fore.CYAN + "\n📡 Choose Scan Type:")
    print("1. LAN Device + Service Scan (via ARP/Nmap)")
    print("2. Wi-Fi Monitor Mode Scan (requires external dongle)")

    choice = input("\n👉 Enter choice [1/2]: ").strip()

    if choice == "1":
        start_lan_scan()
    elif choice == "2":
        start_wifi_monitor_scan()
    else:
        print(Fore.RED + "\n❌ Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
