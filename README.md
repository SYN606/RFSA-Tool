📡 RFSA - Router & Frequency Security Analyzer
==============================================

**RFSA** is a Python-based tool for analyzing wireless networks, identifying routers, and performing security checks including monitor-mode Wi-Fi scanning, port analysis, and router login detection.

🚀 Features
-----------

*   Detects router access level (admin/normal)
*   Scans Wi-Fi networks (monitor mode)
*   Performs port and service scans
*   Logs and filters results by service type
*   Detects hidden SSIDs and signal strength

📦 Project Structure
--------------------

    .
    ├── main.py
    ├── config/
    │   └── settings.py
    ├── scanner/
    │   ├── wifi_monitor.py
    │   ├── network_scanner.py
    │   └── user_status_check.py
    ├── utils/
    │   ├── helper.py
    │   └── logger.py
    └── requirements.txt
    

🛠️ Requirements
----------------

*   Python 3.8+
*   Linux system with network interface access
*   Root privileges for network scans

⚙️ Setup
--------

    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt
    

💻 Running the Tool
-------------------

    sudo env "PATH=$PATH" python3 main.py

Root privileges are needed for raw socket operations and monitor-mode scanning.

🧠 How It Works
---------------

1.  Detects default gateway (router IP)
2.  Tries to access HTTP/HTTPS login page
3.  Checks for admin login signs in HTML content
4.  If admin, performs full IP/service scan
5.  If normal user, asks about monitor dongle and performs appropriate scan
 ___

 This will updated soon


📄 License
----------

This project is for educational and research purposes only.

🤝 Contributing
---------------

Pull requests are welcome! Feel free to suggest new ideas or raise issues.