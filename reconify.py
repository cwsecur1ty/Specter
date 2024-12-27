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


def os_detection(target_ip, open_ports=None):
    """Detect the target OS using TTL analysis and service banners."""
    print("\nRunning OS detection...")
    ttl_guess = {
        range(60, 65): "Linux/Unix",
        range(120, 130): "Windows",
        range(250, 256): "Cisco/Networking Device"
    }

    try:
        icmp_request = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
        if icmp_request:
            ttl = icmp_request.ttl
            os_type = "Unknown"
            for ttl_range, os_name in ttl_guess.items():
                if ttl in ttl_range:
                    os_type = os_name
                    break
            print(f"[+] Detected OS from TTL: {os_type} (TTL={ttl})")
        else:
            print("[-] ICMP request failed; OS detection inconclusive.")
    except Exception as e:
        print(f"[-] OS detection error: {e}")



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
                    except Exception:
                        banner = "Open (no banner)"
                    print(f"[+] Port {port}: {banner}")
                    open_ports.append({"port": port, "banner": banner})
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
        print(f"    Port {result['port']}: {result['banner']}")
    return open_ports



import requests
from bs4 import BeautifulSoup

import time

import requests


def search_cves_mitre(service_name, output_file="mitre_cve_results.txt"):
    """
    Search for CVEs using MITRE CVE (cve.org) with web scraping.
    """
    print(f"\nSearching CVEs for {service_name} using MITRE CVE...")
    base_url = "https://www.cve.org/Search"
    params = {"q": service_name}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Parse CVE results
        cves = []
        results = soup.find_all("div", class_="searchResultsContainer")
        if results:
            for result in results:
                cve_id = result.find("a").text.strip()
                description = result.find("p").text.strip()
                print(f"[CVE] {cve_id}: {description}")
                cves.append({"id": cve_id, "description": description})
        else:
            print("[-] No results found on MITRE CVE.")

        # Save results to a file
        if cves:
            with open(output_file, "w") as file:
                for cve in cves:
                    file.write(f"{cve['id']}: {cve['description']}\n")
            print(f"[+] Results saved to {output_file}.")
        else:
            print("[+] No CVEs found.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying MITRE CVE: {e}")



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
