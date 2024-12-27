import os
import socket
import requests
from scapy.all import sr1, IP, ICMP
from tabulate import tabulate

def ping_sweep(target_ip):
    """Check if the target is alive using ICMP ping."""
    print(f"Pinging {target_ip}...")
    icmp_request = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)
    if icmp_request:
        print(f"[+] {target_ip} is reachable.")
        return True
    else:
        print(f"[-] {target_ip} is not reachable.")
        return False

def os_detection(target_ip, open_ports=None):
    """Detect the target OS using TTL analysis and service banners."""
    print("\nRunning OS detection...")
    ttl_guess = {64: "Linux/Unix", 128: "Windows", 255: "Cisco/Networking Device"}
    icmp_request = sr1(IP(dst=target_ip)/ICMP(), timeout=2, verbose=0)

    if icmp_request:
        ttl = icmp_request.ttl
        os_type = ttl_guess.get(ttl, "Unknown")
        print(f"[+] Detected OS from TTL: {os_type} (TTL={ttl})")

    # Use open ports for banner detection if provided
    if open_ports:
        for port in open_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    sock.connect((target_ip, port))
                    sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = sock.recv(1024).decode().strip()
                    print(f"[+] Detected banner on port {port}: {banner}")
            except:
                pass
    else:
        print("[-] No open ports to check banners.")

    return os_type


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
                    try:
                        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode().strip()
                        print(f"[+] Port {port} is open: {banner}")
                    except:
                        print(f"[+] Port {port} is open (no banner).")
                    open_ports.append(port)
        except:
            pass

    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(f"\n[+] Open ports on {target_ip}: {open_ports}")
    return open_ports


def search_cves(service_name, version, output_file="cve_results.txt"):
    """Search for CVEs for a specific service and version using the NVD API."""
    print(f"\nSearching CVEs for {service_name} {version}...")
    api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {"keyword": f"{service_name} {version}", "resultsPerPage": 10}

    try:
        response = requests.get(api_url, params=params, timeout=10)
        response.raise_for_status()
        cve_data = response.json()

        with open(output_file, "w") as file:
            if 'result' in cve_data and 'CVE_Items' in cve_data['result']:
                for cve in cve_data['result']['CVE_Items']:
                    cve_id = cve['cve']['CVE_data_meta']['ID']
                    description = cve['cve']['description']['description_data'][0]['value']
                    severity = cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'Unknown')
                    print(f"[CVE] {cve_id}: {description} (Severity: {severity})")
                    file.write(f"{cve_id}: {description} (Severity: {severity})\n")
            else:
                print("[+] No CVEs found.")
                file.write("No CVEs found.\n")
        print(f"[+] Results saved to {output_file}.")
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

    """Interactive menu for the tool."""
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
