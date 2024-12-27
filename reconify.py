import os
import socket
import requests
from scapy.all import sr1, IP, ICMP
from tabulate import tabulate

from scapy.layers.inet import IP, ICMP

def ping_sweep(target_ip):
    """Check if the target is alive using ICMP ping."""
    print(f"Pinging {target_ip}...")
    try:
        icmp_request = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
        if icmp_request:
            print(f"[+] {target_ip} is reachable.")
            return True
        else:
            print(f"[-] {target_ip} is not reachable.")
            return False
    except Exception as e:
        print(f"[-] Error during ping sweep: {e}")
        return False

from scapy.layers.inet import IP

def os_detection(target_ip, open_ports=None):
    """Detect the target OS using TTL analysis and service banners."""
    print("\nRunning OS detection...")
    ttl_guess = {64: "Linux/Unix", 128: "Windows", 255: "Cisco/Networking Device"}

    # Detect TTL and determine OS
    try:
        icmp_request = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
        if icmp_request:
            ttl = icmp_request.ttl
            os_type = ttl_guess.get(ttl, "Unknown")
            print(f"[+] Detected OS from TTL: {os_type} (TTL={ttl})")
        else:
            print("[-] ICMP request failed; OS detection inconclusive.")
    except Exception as e:
        print(f"[-] OS detection error: {e}")
        return "Unknown"

    # Use open ports for banner detection if provided
    if open_ports:
        print("[+] Checking service banners for OS clues...")
        for port in open_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    sock.connect((target_ip, port))
                    sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = sock.recv(1024).decode().strip()
                    print(f"[+] Detected banner on port {port}: {banner}")
                    if "Ubuntu" in banner:
                        os_type = "Linux/Ubuntu"
                    elif "Windows" in banner or "Microsoft" in banner:
                        os_type = "Windows"
            except Exception as e:
                print(f"[-] Failed to retrieve banner on port {port}: {e}")
    else:
        print("[-] No open ports to analyze banners.")

    return os_type


import re
import threading

def port_scan(target_ip, start_port=1, end_port=1024):
    """Perform a port scan with threading and optional banner grabbing."""
    print(f"\nScanning ports {start_port}-{end_port} on {target_ip}...")
    open_ports = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    banner = "Unknown"
                    try:
                        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode().strip()
                        if "Server" in banner or "SSH" in banner:
                            match = re.search(r"Server: (.+)", banner)
                            if match:
                                service = match.group(1)
                                print(f"[+] Port {port}: {service}")
                                open_ports.append({"port": port, "service": service})
                            else:
                                print(f"[+] Port {port}: {banner}")
                        else:
                            print(f"[+] Port {port}: Open (no banner)")
                            open_ports.append({"port": port, "service": "Unknown"})
                    except Exception:
                        print(f"[+] Port {port}: Open (no banner)")
                        open_ports.append({"port": port, "service": "Unknown"})
        except Exception:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\n[+] Port Scan Results:")
    for result in open_ports:
        print(f"    Port {result['port']}: {result['service']}")
    return open_ports


import requests
from bs4 import BeautifulSoup

import time
from bs4 import BeautifulSoup

def search_cves(service_name, version, output_file="cve_results.txt"):
    """Search for CVEs using the CVE Details website."""
    print(f"\nSearching CVEs for {service_name} {version}...")
    base_url = "https://www.cvedetails.com/vulnerability-search.php"
    params = {"q": f"{service_name} {version}"}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        if response.status_code == 403:
            print("[-] Request blocked by the CVE Details website. Please try again later.")
            return
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        cves = []
        table = soup.find("table", {"class": "searchresults"})
        if table:
            rows = table.find_all("tr")[1:]  # Skip the header row
            for row in rows:
                columns = row.find_all("td")
                if len(columns) >= 2:
                    cve_id = columns[0].text.strip()
                    description = columns[1].text.strip()
                    print(f"[CVE] {cve_id}: {description}")
                    cves.append({"id": cve_id, "description": description})

        # Save results to a file
        if cves:
            with open(output_file, "w") as file:
                for cve in cves:
                    file.write(f"{cve['id']}: {cve['description']}\n")
            print(f"[+] Results saved to {output_file}.")
        else:
            print("[+] No CVEs found.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error searching CVEs: {e}")


def menu():
    # ASCII art
    art = R"""
 /$$$$$$$                                          /$$  /$$$$$$          
| $$__  $$                                        |__/ /$$__  $$         
| $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$  /$$| $$  \__//$$   /$$
| $$$$$$$/ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$| $$| $$$$   | $$  | $$
| $$__  $$| $$$$$$$$| $$      | $$  \ $$| $$  \ $$| $$| $$_/   | $$  | $$
| $$  \ $$| $$_____/| $$      | $$  | $$| $$  | $$| $$| $$     | $$  | $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$| $$| $$     |  $$$$$$$
|__/  |__/ \_______/ \_______/ \______/ |__/  |__/|__/|__/      \____  $$
                                                                /$$  | $$
                                                               |  $$$$$$/
                                                                \______/ 
"""
    print(art)
    print("The recon toolbox.")

    while True:
        print("\nRecon Tool Menu")
        print("1. Ping Sweep")
        print("2. OS Detection")
        print("3. Port Scan")
        print("4. Search CVEs")
        print("5. Exit")
        
        choice = input("Enter your choice: ").strip()
        
        if choice == "1":
            target_ip = input("Enter the target IP address: ").strip()
            ping_sweep(target_ip)
        elif choice == "2":
            target_ip = input("Enter the target IP address: ").strip()
            os_detection(target_ip)
        elif choice == "3":
            target_ip = input("Enter the target IP address: ").strip()
            start_port = int(input("Enter the starting port (default 1): ") or 1)
            end_port = int(input("Enter the ending port (default 1024): ") or 1024)
            port_scan(target_ip, start_port, end_port)
        elif choice == "4":
            service_name = input("Enter the service name: ").strip()
            version = input("Enter the service version: ").strip()
            search_cves(service_name, version)
        elif choice == "5":
            print("Exiting the tool. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


def main():
    menu()

if __name__ == "__main__":
    main()
