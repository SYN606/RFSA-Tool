Router Firmware Security Assistant (RFSA)
=========================================

Enhancing network security through comprehensive router and Wi-Fi analysis

🔍 Overview
-----------

RFSA is a powerful Python-based tool designed for network security analysis and Wi-Fi monitoring. It provides a comprehensive suite of features for identifying routers, detecting security vulnerabilities, and performing in-depth network scans. Whether you're an administrator looking to monitor your network or a security researcher, RFSA helps you understand and secure your wireless network.


🚀 Key Features
---------------

*   **Router Access Level Detection:** Detect if you have admin or normal user access to a router's login page. Performs security checks based on access level.
*   **Wi-Fi Network Scanning (Monitor Mode):** Scan Wi-Fi networks in monitor mode, identify hidden SSIDs, channel frequencies, encryption types, and signal strength.
*   **Port & Service Scanning:** Scan for open ports and detect available services on devices within a specified network range.
*   **Security Checks:** Perform firmware vulnerability checks based on device vendor, model, and version. Cross-check firmware against the CVE database for known vulnerabilities.
*   **Logging & Reporting:** Log results of Wi-Fi scans, network scans, and firmware checks. Generate detailed JSON reports that include scan results, device information, and security findings.

📦 Project Structure
--------------------
```
  .
  ├── main.py               # Main entry point for running the tool
  ├── config/               # Configuration files
  │   └── settings.py       # Configuration settings (e.g., network ranges, monitor interface)
  ├── scanner/              # Scan modules
  │   ├── wifi\_monitor.py   # Monitor mode Wi-Fi scanner
  │   ├── network\_scanner.py# Network scanner (IP, services, ports)
  │   └── user\_status\_check.py # User access level detection (admin/normal)
  ├── utils/                # Utility functions
  │   ├── helper.py         # Helper functions (e.g., gateway detection)
  │   └── logger.py         # Logging functions for info/warning/error logs
  ├── reporting.py          # Report generation (saves JSON reports)
  └── requirements.txt      # Python dependencies
  
```
🛠️ Requirements
----------------

*   Python 3.8+ (for compatibility and performance)
*   Linux system with root privileges (for network interface access and monitor mode scanning)
*   Required Python packages (listed in `requirements.txt`)


💻 Running the Tool
-------------------

Run the tool with root privileges to enable network operations:

    sudo env "PATH=$PATH" python3 main.py

This is necessary for raw socket operations and for scanning Wi-Fi networks in monitor mode.

🧠 How It Works
---------------

*   **Router Detection:** The tool first identifies the router's IP address by detecting the default gateway on your network. It attempts to access the router's login page via HTTP/HTTPS to check for admin access.
*   **Router Access Level:** If admin access is detected, the tool performs a full IP and service scan to discover connected devices and services. If normal user access is detected, the tool asks whether you have a monitor mode dongle.
*   **Wi-Fi Scanning:** If you have a monitor mode dongle, the tool will scan for nearby Wi-Fi networks in monitor mode, identifying hidden SSIDs, encryption methods, and signal strength.
*   **Network Scanning:** The tool performs a network scan on the specified IP range to detect open ports and services. Results are logged and saved in a JSON report.
*   **Firmware Security Check:** If a router or device is found, its firmware version is checked for vulnerabilities by cross-referencing known CVE (Common Vulnerabilities and Exposures) entries.

📄 License
----------

This project is intended for educational and research purposes only. Use at your own risk. The developer is not responsible for any misuse of the tool.


📜 Example Report
-----------------
```
  {
    "timestamp": "2025-04-15 12:00:00",
    "router\_ip": "192.168.1.1",
    "network\_scan": \[
      {
        "ip": "192.168.1.10",
        "hostname": "Device1",
        "vendor": "TP-Link",
        "model": "Archer A7",
        "version": "1.2.0",
        "services": \["http", "ssh"\],
        "criticality": 5
      },
      {
        "ip": "192.168.1.20",
        "hostname": "Device2",
        "vendor": "Netgear",
        "model": "R7000",
        "version": "V1.0.9",
        "services": \["http"\],
        "criticality": 3
      }
    \],
    "wifi\_scan": \[
      {
        "ssid": "Network\_1",
        "encryption": "WPA2",
        "signal\_strength": -50,
        "channel": 6,
        "hidden": false
      },
      {
        "ssid": "Hidden\_Network",
        "encryption": "WEP",
        "signal\_strength": -70,
        "channel": 11,
        "hidden": true
      }
    \],
    "firmware\_check": {
      "vendor": "TP-Link",
      "model": "Archer A7",
      "version": "1.2.0",
      "vulnerabilities": \["CVE-2023-1234", "CVE-2024-5678"\]
    }
  }
```

