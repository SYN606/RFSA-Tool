from scapy.all import ARP, Ether, srp  # type: ignore
import netifaces


def get_default_gateway():
    """Retrieves the default gateway IP of the current network."""
    gateway = netifaces.gateways()
    return gateway['default'].get(netifaces.AF_INET, [None])[0]  # type: ignore


def scan_network(ip_range):
    """Scans the given IP range for active devices."""
    print(f"[+] Scanning network: {ip_range}")

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = [{
        'ip': received.psrc,
        'mac': received.hwsrc
    } for sent, received in result]

    return devices


def scan():
    """Main function to scan for routers on the network."""
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("[-] Could not determine the default gateway.")
        return

    print(f"[DEBUG] Default Gateway: {gateway_ip}")  # Debugging line

    network_prefix = ".".join(gateway_ip.split('.')[:-1]) + ".0/24"
    devices = scan_network(network_prefix)

    print("[+] Detected Devices:")
    for device in devices:
        print(f"    IP: {device['ip']}, MAC: {device['mac']}")

    routers = [
        device for device in devices
        if device['ip'].endswith('.1') or device['mac'].startswith("00:")
    ]

    print("\n[+] Possible Routers:")
    for router in routers:
        print(f"    IP: {router['ip']}, MAC: {router['mac']}")
