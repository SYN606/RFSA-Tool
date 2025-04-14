import netifaces
import nmap
import requests


def get_default_gateway():
    """
    Returns the default gateway IP address (usually the router's IP).
    """
    try:
        gws = netifaces.gateways()
        default_gateway = gws['default'][netifaces.AF_INET][0]
        return default_gateway
    except Exception as e:
        print(f"[!] Failed to detect default gateway: {e}")
        return None


class NetworkScanner:
    def __init__(self, network_range, service_filter=None):
        self.network_range = network_range
        self.service_filter = service_filter
        self.scanner = nmap.PortScanner()

    def perform_scan(self):
        """
        Perform a network scan on the provided network range to gather device info.
        """
        print(f"🔍 Scanning network range: {self.network_range}")
        self.scanner.scan(hosts=self.network_range, arguments='-sn')  # Ping scan

        devices = []
        for host in self.scanner.all_hosts():
            addresses = self.scanner[host].get('addresses', {})
            ip = addresses.get('ipv4', host)
            mac = addresses.get('mac', None)

            device = {
                "ip": ip,
                "vendor": self.get_vendor_from_mac(mac) if mac else "Unknown Vendor",
                "model": self.get_model_info(ip),
                "version": self.get_version_info(ip),
            }
            devices.append(device)

        return devices

    def get_banner_info(self, host, port):
        """
        Attempts to grab banner info via HTTP GET.
        """
        try:
            response = requests.get(f"http://{host}:{port}", timeout=3)
            if response.status_code == 200:
                return response.text
        except requests.exceptions.RequestException:
            return None
        return None

    def get_model_info(self, host):
        """
        Extract model info from a banner.
        """
        banner = self.get_banner_info(host, 80)
        if banner:
            return self.extract_model_from_banner(banner)
        return "Unknown Model"

    def get_version_info(self, host):
        """
        Extract version info from a banner.
        """
        banner = self.get_banner_info(host, 80)
        if banner:
            return self.extract_version_from_banner(banner)
        return "Unknown Version"

    def extract_model_from_banner(self, banner):
        """
        Naive model extraction from HTTP banner.
        You should improve this with regex patterns or HTML parsing.
        """
        if "Model" in banner:
            return banner.split("Model")[1].split()[0].strip(":<>/#\\\"'")
        return "Unknown Model"

    def extract_version_from_banner(self, banner):
        """
        Naive version extraction from HTTP banner.
        """
        if "Version" in banner:
            return banner.split("Version")[1].split()[0].strip(":<>/#\\\"'")
        return "Unknown Version"

    def get_vendor_from_mac(self, mac):
        """
        Very basic vendor detection using static OUI lookup.
        Extend with a full MAC-to-vendor database in real apps.
        """
        # Normalize prefix to first 3 bytes (OUI)
        prefix = mac.upper().replace(":", "")[:6]
        oui_dict = {
            "001A2B": "Cisco",
            "003E1F": "TP-Link",
            "F8FF30": "Netgear"
        }
        return oui_dict.get(prefix, "Unknown Vendor")
