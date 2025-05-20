from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Elt
from config.settings import CONFIG
from utils.logger import log_info
from colorama import Fore, init
import os

init(autoreset=True)


class WiFiMonitor:

    def __init__(self, interface=None):
        self.interface = interface or CONFIG.get("monitor_interface")
        self.networks = {}

    def scan(self, duration=20):
        """
        Scans for Wi-Fi networks in monitor mode for a specified duration.
        Returns a list of detected networks with key info.
        """
        if not self.interface:
            print(Fore.RED + "❌ No monitor mode interface specified.")
            return []
        if not os.geteuid() == 0:
            print(Fore.RED + "❌ Root privileges required for Wi-Fi scanning.")
            return []
        if not os.path.exists(f"/sys/class/net/{self.interface}"):
            print(Fore.RED + f"❌ Interface '{self.interface}' does not exist.")
            return []

        print(
            Fore.CYAN +
            f"🔍 Scanning for networks in monitor mode on '{self.interface}'...\n"
        )
        try:
            sniff(iface=self.interface, prn=self.packet_handler, timeout=duration)
        except Exception as e:
            print(Fore.RED + f"❌ Error during sniffing: {e}")
            return []

        result = []

        if self.networks:
            print(Fore.GREEN +
                  f"\n✅ {len(self.networks)} Wi-Fi networks found:\n")
            for ssid, data in self.networks.items():
                print(Fore.YELLOW + f"SSID: {ssid}")
                print(Fore.BLUE + f"  Encryption: {data['encryption']}")
                print(Fore.MAGENTA +
                      f"  Signal Strength: {data['signal_strength']} dBm")
                print(Fore.CYAN + f"  Channel: {data['channel']}")
                print(Fore.RED +
                      f"  Hidden: {'Yes' if data['hidden'] else 'No'}\n")

                result.append({
                    "ssid": ssid,
                    "encryption": data["encryption"],
                    "signal_strength": data["signal_strength"],
                    "channel": data["channel"],
                    "hidden": data["hidden"]
                })
        else:
            print(Fore.RED + "❌ No networks detected.")

        return result

    def packet_handler(self, pkt):
        """
        Handles captured packets to extract Wi-Fi network info.
        """
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode(errors="ignore") if pkt.info else "Hidden"
            bssid = pkt.addr2
            signal_strength = getattr(pkt, 'dBm_AntSignal', 'N/A')

            # Extract channel
            channel = None
            if pkt.haslayer(Dot11Elt):
                elements = pkt[Dot11Elt]
                while isinstance(elements, Dot11Elt):
                    if elements.ID == 3:  # DS Parameter Set
                        channel = int.from_bytes(elements.info, "little")
                        break
                    elements = elements.payload

            encryption = self.get_encryption(pkt)

            if ssid not in self.networks:
                self.networks[ssid] = {
                    'encryption': encryption,
                    'signal_strength': signal_strength,
                    'channel': channel or "Unknown",
                    'hidden': (ssid == "Hidden")
                }

                log_info(f"Detected network: {ssid} ({encryption})")

    def get_encryption(self, pkt):
        """
        Determines encryption type from Dot11Elt fields.
        """
        capabilities = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                   "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if "privacy" not in capabilities.lower():
            return "Open"

        enc = "WEP"
        if pkt.haslayer(Dot11Elt):
            el = pkt[Dot11Elt]
            while isinstance(el, Dot11Elt):
                if el.ID == 48:
                    return "WPA/WPA2"
                elif el.ID == 221 and el.info.startswith(b'\x50\x6f\x9a\x0c'):
                    return "WPA3"
                el = el.payload

        return enc


if __name__ == "__main__":
    monitor = WiFiMonitor()
    monitor.scan()
