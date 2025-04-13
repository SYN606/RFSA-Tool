import netifaces

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
