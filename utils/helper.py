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
        Perform a network scan on the provided network range to gather information.
        """
        print(f"🔍 Scanning network range: {self.network_range}")

        # Perform the scan
        self.scanner.scan(hosts=self.network_range,
                          arguments="-sP")  # Ping scan

        devices = []
        for host in self.scanner.all_hosts():
            device = {
                "ip": host,
                "vendor": self.get_vendor_info(host),
                "model": self.get_model_info(host),
                "version": self.get_version_info(host),
            }
            devices.append(device)

        return devices

    def get_vendor_info(self, host):
        """
        Try to get vendor information using MAC address or other methods.
        """
        if 'mac' in self.scanner[host]['addresses']:
            mac = self.scanner[host]['addresses']['mac']
            vendor = self.get_vendor_from_mac(mac)
            return vendor
        return "Unknown Vendor"

    def get_model_info(self, host):
        """
        Try to get model information from the device (e.g., via banner grabbing).
        """
        # Example for grabbing the banner for HTTP services
        try:
            http_banner = self.get_banner_info(host, 80)
            if http_banner:
                return self.extract_model_from_banner(http_banner)
        except Exception as e:
            print(f"Error getting model info from {host}: {e}")
        return "Unknown Model"

    def get_version_info(self, host):
        """
        Try to get version information from the device (e.g., via banner grabbing).
        """
        try:
            http_banner = self.get_banner_info(host, 80)
            if http_banner:
                return self.extract_version_from_banner(http_banner)
        except Exception as e:
            print(f"Error getting version info from {host}: {e}")
        return "Unknown Version"

    def get_banner_info(self, host, port):
        """
        Attempts to grab the banner information for a specific port.
        """
        try:
            response = requests.get(f'http://{host}:{port}', timeout=5)
            if response.status_code == 200:
                return response.text
        except requests.exceptions.RequestException:
            return None

    def extract_model_from_banner(self, banner):
        """
        Extract model information from the banner text.
        """
        # Placeholder: Extract model based on known patterns
        if "Model" in banner:
            return banner.split("Model")[1].strip()
        return "Unknown Model"

    def extract_version_from_banner(self, banner):
        """
        Extract version information from the banner text.
        """
        # Placeholder: Extract version based on known patterns
        if "Version" in banner:
            return banner.split("Version")[1].strip()
        return "Unknown Version"

    def get_vendor_from_mac(self, mac):
        """
        Get vendor name from the MAC address (use MAC address lookup service).
        """
        # Placeholder: You can use a database like the IEEE OUI to match MAC to vendor
        # Example vendor list lookup (in a real application, you'd fetch this from an OUI database)
        oui_dict = {
            "00:1A:2B": "Cisco",
            "00:3E:1F": "TP-Link",
            "F8:FF:30": "Netgear"
        }
        prefix = mac[:8].upper()
        return oui_dict.get(prefix, "Unknown Vendor")
