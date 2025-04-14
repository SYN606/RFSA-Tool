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
        Initialize the NetworkScanner class with optional custom network range and service filter.

        :param network_range: Network range to scan (e.g., "192.168.1.0/24")
        :param service_filter: List of services to filter (e.g., ["ssh", "http"])
        """
        self.network_range = network_range or CONFIG['default_network_range']
        self.service_filter = service_filter
        self.devices = []
        self.nm = nmap.PortScanner()
        self.mac_lookup = MacLookup()

    def scan_devices(self):
        """
        Scans the network for active devices using ARP requests.
        It sends ARP requests to the entire network range and listens for responses.
        """
        print(
            Fore.CYAN +
            f"🔍 Scanning the network ({self.network_range}) for active devices..."
        )

        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=self.network_range)
        packet = ether / arp

        answered_list, _ = srp(packet, timeout=3, verbose=False)

        if answered_list:
            self.devices = []
            for sent, received in answered_list:
                mac = received.hwsrc
                ip = received.psrc
                try:
                    vendor = self.mac_lookup.lookup(mac)
                except Exception:
                    vendor = "Unknown"

                device_info = {'ip': ip, 'mac': mac, 'vendor': vendor}
                self.devices.append(device_info)

                print(Fore.GREEN + f"📡 Device: {ip} ({mac}) → {vendor}")

            log_info(f"Found {len(self.devices)} devices on the network.")
        else:
            print(Fore.RED + "❌ No devices found.")
            log_warn("No devices found in the network scan.")

    def scan_services(self):
        """
        Scans for open ports and services running on discovered devices using nmap.
        Filters services based on the provided service_filter list (if any).
        """
        if not self.devices:
            print(Fore.YELLOW + "⚠️ No devices found to scan for services.")
            return

        print(Fore.CYAN +
              "\n🔍 Scanning for open services on discovered devices...")

        for device in self.devices:
            ip = device['ip']
            try:
                print(Fore.YELLOW + f"🔧 Scanning {ip} ({device['vendor']})...")

                self.nm.scan(ip, '1-1024')

                if 'tcp' in self.nm[ip]:
                    for port in self.nm[ip]['tcp']:
                        service = self.nm[ip]['tcp'][port]['name']
                        if not self.service_filter or service in self.service_filter:
                            print(Fore.BLUE +
                                  f"  ✅ Port {port} open: {service}")
                else:
                    print(Fore.RED + f"  ❌ No open TCP ports found for {ip}.")
            except Exception as e:
                print(Fore.RED + f"Error scanning {ip}: {str(e)}")
                log_warn(f"Error scanning {ip}: {str(e)}")

    def perform_scan(self):
        """
        Performs a full network scan: discovers devices and scans for open services.
        """
        self.scan_devices()
        self.scan_services()


if __name__ == "__main__":
    # Take user input for custom scan range and services filter
    network_range = input(
        "Enter the network range to scan (default is 192.168.1.0/24): ")
    service_filter_input = input(
        "Enter comma-separated services to filter (e.g., ssh,http,https) or leave empty for all: "
    )

    # Parse service filter input
    service_filter = service_filter_input.split(
        ",") if service_filter_input else None
    network_range = network_range or "192.168.1.0/24"

    # Initialize and perform the scan
    scanner = NetworkScanner(network_range=network_range,
                             service_filter=service_filter)
    scanner.perform_scan()
