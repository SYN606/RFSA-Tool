from scapy.all import ARP, Ether, srp
import netifaces


def get_default_gateway():
    """Retrieves the default gateway IP of the current network."""
    gateway = netifaces.gateways()
    return gateway['default'][
        netifaces.
        AF_INET][0] if 'default' in gateway and netifaces.AF_INET in gateway[
            'default'] else None


def scan_network(ip_range):
    """Scans the given IP range for active devices."""
    print(f"[+] Scanning network: {ip_range}")

    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def scan():
    """Main function to scan for routers on the network."""
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("[-] Could not determine the default gateway.")
        return

    network_prefix = ".".join(gateway_ip.split('.')[:-1]) + ".1/24"
    devices = scan_network(network_prefix)

    print("[+] Detected Devices:")
    for device in devices:
        print(f"    IP: {device['ip']}, MAC: {device['mac']}")

    # Identifying possible routers
    routers = [
        device for device in devices
        if device['ip'].endswith('.1') or device['mac'].startswith('00:')
    ]  # 00: is common for routers

    print("\n[+] Possible Routers:")
    for router in routers:
        print(f"    IP: {router['ip']}, MAC: {router['mac']}")


if __name__ == "__main__":
    scan()
