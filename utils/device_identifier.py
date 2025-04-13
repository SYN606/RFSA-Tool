from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()

def identify_device(mac):
    try:
        vendor = mac_lookup.lookup(mac).lower()
        # Fake version/model for now, in reality we'd need more info
        model = "unknown"
        version = "unknown"
        return vendor, model, version
    except:
        return None, None, None
