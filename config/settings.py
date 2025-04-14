CONFIG = {
    # General
    "timeout": 3,
    "default_router_ip": "192.168.1.1",
    "default_network_range": "192.168.1.0/24",
    "wifi_monitor_enabled": True,
    "monitor_interface": "wlan0mon"
    # Port Scanning
    "scan_ports": [21, 22, 23, 53, 80, 139, 443, 445, 8080],
    "max_threads": 50,

    # Banner Grabbing
    "http_user_agent": "RouterSecAssist/1.0",

    # Reporting
    "report_output_path": "reporting/output",
    "report_format": "json", 
    "include_wifi_in_report": True,

    # Logging
    "log_level": "INFO",
    "log_to_file": True,
    "log_file_path": "logs/assistant.log",

    # Fingerprint DB
    "fingerprint_db_path": "data/fingerprints.json"
}


# URL for the NVD CVE feed
NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"

TARGET_VENDORS = [
    "tplink", "netgear", "dlink", "asus", "huawei", "mikrotik", "linksys"
]

FEED_FILE_PATH = "nvd_recent.json.gz"
