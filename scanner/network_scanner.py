import nmap
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
from mac_vendor_lookup import MacLookup
from utils.logger import log_info, log_warn
from config.settings import CONFIG
from colorama import Fore, init

init(autoreset=True)


class NetworkScanner:

    def __init__(self, network_range=None, service_filter=None):
        """
        Initialize NetworkScanner with a target range and optional service filter.
        """
        self.network_range = network_range or CONFIG.get(
            "default_network_range", "192.168.1.0/24")
        self.service_filter = service_filter
        self.devices = []
        self.nm = nmap.PortScanner()
        self.mac_lookup = MacLookup()

    def scan_devices(self):
        """
        Discover active devices using ARP scan.
        """
        print(Fore.CYAN + f"\n🔍 Scanning network range: {self.network_range}")

        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=self.network_range)
        packet = ether / arp

        answered_list, _ = srp(packet, timeout=3, verbose=False)

        if not answered_list:
            print(Fore.RED + "❌ No devices responded.")
            log_warn("No devices discovered during ARP scan.")
            return

        self.devices = []
        seen_macs = set()

        for _, received in answered_list:
            mac = received.hwsrc
            ip = received.psrc
            if mac in seen_macs:
                continue
            seen_macs.add(mac)

            try:
                vendor = self.mac_lookup.lookup(mac)
            except Exception:
                vendor = "Unknown"

            device_info = {
                'ip': ip,
                'mac': mac,
                'vendor': vendor,
                'services': []
            }
            self.devices.append(device_info)

            print(Fore.GREEN + f"📡 Device: {ip} ({mac}) → {vendor}")

        log_info(f"Found {len(self.devices)} devices.")

    def scan_services(self):
        """
        Use nmap to identify open services on each device.
        """
        if not self.devices:
            print(Fore.YELLOW + "\n⚠️ No devices to scan for services.")
            return

        print(Fore.CYAN +
              "\n🔍 Scanning discovered devices for open services...")

        for device in self.devices:
            ip = device['ip']
            try:
                print(Fore.YELLOW +
                      f"\n🔧 Scanning {ip} ({device['vendor']})...")
                self.nm.scan(ip, '1-1024')

                if 'tcp' not in self.nm[ip]:
                    print(Fore.RED + "  ❌ No open TCP ports found.")
                    continue

                for port in self.nm[ip]['tcp']:
                    service = self.nm[ip]['tcp'][port]['name']
                    if not self.service_filter or service in self.service_filter:
                        device['services'].append({
                            'port': port,
                            'service': service
                        })
                        print(Fore.BLUE + f"  ✅ Port {port} open → {service}")

            except Exception as e:
                log_warn(f"Error scanning {ip}: {e}")
                print(Fore.RED + f"❌ Error scanning {ip}: {e}")

    def perform_scan(self):
        """
        Perform full device + service scan. Returns structured results.
        """
        self.scan_devices()
        self.scan_services()
        return self.devices


if __name__ == "__main__":
    network_range = input(
        "🌐 Enter network range to scan (default is 192.168.1.0/24): ").strip()
    service_input = input(
        "⚙️  Filter by services (e.g., ssh,http) or leave empty: ").strip()

    service_filter = service_input.split(",") if service_input else None
    network_range = network_range or CONFIG.get("default_network_range",
                                                "192.168.1.0/24")

    scanner = NetworkScanner(network_range=network_range,
                             service_filter=service_filter)
    result = scanner.perform_scan()

    if result:
        print(Fore.GREEN + f"\n✅ Scan complete. {len(result)} devices found.")
    else:
        print(Fore.YELLOW + "\n⚠️ No results to display.")
