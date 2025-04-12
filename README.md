# RFSA-Tool

Router-Firmware-Security-Analysis

A router firmware security analysis tool that analyse routers for possibe exploitable vulnarabilities present.

# Features

Router Firmware Vulnerability Scanner (RFVS)

RFVS is a Python-based tool designed to analyze router firmware for vulnerabilities, perform network tests, and generate detailed security reports. It supports extracting firmware from local files or routers via SSH, scanning for vulnerabilities, testing exploits, and conducting network reconnaissance. RFVS is ideal for security researchers and penetration testers working on embedded devices, with built-in support for the Damn Vulnerable Router Firmware (DVRF) sample.
Features

 1.  Firmware Extraction:
        Extracts firmware from local files (e.g., DVRF_v03.bin) using binwalk to unpack SquashFS or other formats.
        Supports SSH-based firmware extraction from live routers, dumping partitions like /dev/mtd and transferring via SCP.
        Outputs extracted contents to extracted_firmware.bin/ for further analysis.
  2. Vulnerability Scanning:
        Scans extracted firmware for vulnerabilities in ELF binaries (e.g., unsafe functions like strcpy) using pyelftools.
        Supports deep scanning mode for more thorough analysis (optional).
        Integrates with pycvesearch to look up CVEs for identified components.
  3. Exploit Testing:
        Tests vulnerabilities for exploitability using pwntools, simulating attacks like buffer overflows or format string exploits.
        Configurable for specific targets (e.g., router IP) or defaults to extracted firmware components.
  4. Network Testing:
        Performs ARP-based target discovery on local subnets (e.g., 192.168.1.0/24) using scapy.
        Conducts TCP port scans and firewall bypass tests with hping3 to assess router security.
  5. Reporting:
        Generates detailed reports (report.txt) summarizing vulnerabilities, exploit results, and network findings.
        Customizable output file path for reports.
  6. DVRF Support:
        Built-in support for the Damn Vulnerable Router Firmware (DVRF) sample, enabling easy testing without a live router.
        Automatically uses samples/DVRF/Firmware/DVRF_v03.bin with the --use-sample flag.
  7. Interactive Shell:
        Provides an interactive command-line interface (RFVS>) for flexible operation.
        Supports verbose logging for debugging and detailed output.
  8. Logging:
        Logs all operations to rfvs.log for traceability.
        Optional verbose mode to display logs in the console.

# Installation

  Clone the Repository:
  bash

git clone https://github.com/yourusername/RFSA-Tool.git
cd RFSA-Tool
Set Up Virtual Environment:
bash
python3 -m venv env
source env/bin/activate
Install Dependencies:
bash
pip install binwalk==2.3.4 pyelftools capstone pycvesearch scapy colorama pwntools paramiko scp impacket nmap ropgadget requests
sudo apt-get install squashfs-tools p7zip-full unzip tar hping3
Download DVRF Sample:
bash

  mkdir -p samples/DVRF/Firmware
  wget https://github.com/praetorian-inc/DVRF/raw/master/Firmware/DVRF_v03.bin -P samples/DVRF/Firmware/

# Usage

Run RFVS with sudo due to scapy’s network requirements:
bash
sudo python main.py

This starts the interactive shell (RFVS>). Enter commands with flags to perform tasks. Type exit to quit.
Commands and Flags
Flag	Long Form	Description	Usage Example
-f	--file	Specifies a firmware file to analyze.	-f firmware.bin
-e	--extract	Extracts firmware contents to extracted_firmware.bin/. Requires -f or --use-sample.	-e
-s	--scan	Scans extracted firmware for vulnerabilities. Requires -e.	-s
-d	--deep	Enables deep vulnerability scanning (more thorough). Used with -s.	-s -d
-c	--cve	Performs CVE lookup for vulnerabilities. Requires -s.	-s -c
-x	--exploit	Tests exploits on vulnerabilities. Requires -s.	-x
-n	--network	Runs network tests (e.g., port scans, firewall bypass) on a target IP. Requires -i or prior target discovery.	-n -i 192.168.1.1
-t	--targets	Scans subnet for devices via ARP.	-t
-i	--ip	Specifies target router IP for extraction or network tests.	-i 192.168.1.1
-r	--report	Generates a report of findings. Requires -s or -t.	-r
-o	--output	Sets output file for report (default: report.txt).	-o myreport.txt
-v	--verbose	Enables verbose logging to console.	-v
-X	--extract-from-router	Extracts firmware from a router via SSH. Requires -i. Prompts for credentials.	-X -i 192.168.1.1
--use-sample	N/A	Uses DVRF sample firmware (samples/DVRF/Firmware/DVRF_v03.bin).	--use-sample
Example Commands

  # Analyze DVRF Sample:
  bash

RFVS> --use-sample -e -s -x -r -v

  Extracts DVRF_v03.bin, scans for vulnerabilities, tests exploits, and saves a report to report.txt.

# Analyze Local Firmware:
bash
RFVS> -f firmware.bin -e -s -d -c -x -r -o report.txt -v

  Extracts firmware.bin, performs deep scanning with CVE lookup, tests exploits, and saves a custom report.

# Extract from Router:
bash
RFVS> -X -i 192.168.1.1 -e -s -r -v

  Extracts firmware via SSH from 192.168.1.1, scans, and reports.

# Network Scan and Test:
bash
RFVS> -t -n -i 192.168.1.1 -r -v

  Discovers devices, tests network services on 192.168.1.1, and reports findings.

# Project Structure
text
RFSA-Tool/
├── main.py              # Core script with interactive shell
├── extract.py           # Handles firmware extraction
├── rsv/
│   ├── scan.py         # Scans for vulnerabilities
│   ├── exploit.py      # Tests exploits
│   └── __init__.py
├── report.py            # Generates reports
├── samples/
│   └── DVRF/
│       └── Firmware/
│           └── DVRF_v03.bin  # DVRF sample
├── extracted_firmware.bin/  # Extracted contents
├── rfvs.log             # Logs
├── report.txt           # Report output
└── env/                 # Virtual environment

# Notes

   1. Dependencies: Ensure squashfs-tools is installed for DVRF’s SquashFS filesystem.
   2. Root Access: Use sudo for network operations (scapy, hping3).
   3. DVRF: Ideal for testing without a live router. Download from DVRF GitHub.
   4. Verbose Mode: Use -v to debug issues (logs to rfvs.log and console).
   5. Limitations: SSH extraction (-X) requires router credentials and compatible firmware layout.

# Troubleshooting

   Extraction Fails: Verify binwalk and squashfs-tools are installed. Test manually:
   bash

binwalk -e samples/DVRF/Firmware/DVRF_v03.bin

No Vulnerabilities Found: Ensure pyelftools is installed for ELF analysis:

bash

pip install pyelftools

Network Errors: Run with sudo and check target IP reachability (ping 192.168.1.1).
