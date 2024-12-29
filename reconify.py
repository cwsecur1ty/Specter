import os
import csv
import socket
import json
import ipaddress
import requests
from scapy.all import sr1, IP, ICMP
from bs4 import BeautifulSoup
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import nmap
import threading
from datetime import datetime
from urllib.parse import urlparse
from queue import Queue

# Global variables for directory scanning
queue = Queue()
found_urls = []

# Directory scanning
def dirscan(base_url, wordlist_path, extensions=None, threads=10):
    """
    Perform directory scanning on the target URL.
    """
    if not os.path.isfile(wordlist_path):
        print(f"[-] Wordlist file '{wordlist_path}' does not exist.")
        return

    # Read the wordlist
    with open(wordlist_path, 'r') as f:
        directories = [line.strip() for line in f.readlines()]

    # Add directories to the queue
    for directory in directories:
        queue.put(directory)

    def scan_directory(base_url, directory, extensions):
        """
        Scans a single directory by making HTTP requests.
        """
        urls_to_test = [f"{base_url}/{directory}"]
        if extensions:
            urls_to_test += [f"{base_url}/{directory}{ext}" for ext in extensions]

        with requests.Session() as session:
            session.headers.update({"User-Agent": "DirHunter/1.0"})
            for url in urls_to_test:
                try:
                    response = session.get(url, allow_redirects=False, timeout=5)
                    if response.status_code in [200, 301, 302, 403]:
                        found_urls.append((url, response.status_code))
                        print(f"[+] Found: {url} (Status: {response.status_code})")
                        if url.endswith('/'):
                            queue.put(directory + '/')
                except requests.RequestException as e:
                    print(f"[-] Error: {e}")

    def worker():
        """
        Worker function for threading.
        """
        while not queue.empty():
            directory = queue.get()
            scan_directory(base_url, directory, extensions)
            queue.task_done()

    # Start threads
    thread_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker)
        thread.start()
        thread_list.append(thread)

    # Wait for all threads to complete
    queue.join()
    for thread in thread_list:
        thread.join()

    # Print results
    print("\n[+] Directory Scan Complete. Results:")
    for url, status in found_urls:
        print(f"{url} (Status: {status})")

    # Save results
    save_path = generate_save_path(base_url)
    save_results(save_path)

def generate_save_path(base_url):
    """
    Generate a default save path for results.
    """
    if not os.path.exists('results'):
        os.makedirs('results')
    parsed_url = urlparse(base_url)
    hostname = parsed_url.hostname
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    return f"results/{timestamp}-{hostname}-DirScan-report.txt"

def save_results(results_path):
    """
    Save scan results to a file.
    """
    with open(results_path, 'w') as f:
        for url, status in found_urls:
            f.write(f"{url} (Status: {status})\n")
    print(f"[+] Results saved to {results_path}")

# Get API Key
def get_api_key(file_path="settings.json"):
    """
    Retrieve the API key from the settings.json file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Settings file not found at {file_path}. Please create a settings.json file."
        )
    
    with open(file_path, "r") as file:
        settings = json.load(file)
    
    api_key = settings.get("nist_api_key")
    if not api_key or api_key == "your_api_key_here":
        raise ValueError(
            "API key not set in settings.json. Please add your API key."
        )
    
    return api_key

# Validate IP Address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Ping Sweep
def ping_sweep(target_ip):
    """Check if the target is alive using ICMP ping."""
    if not is_valid_ip(target_ip):
        print("[-] Invalid IP address. Please try again.")
        return False

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

# OS Detection
def os_detection(target_ip):
    """Detect the target OS using TTL analysis."""
    if not is_valid_ip(target_ip):
        print("[-] Invalid IP address. Please try again.")
        return

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

# Port Scan
import multiprocessing

max_threads = multiprocessing.cpu_count() * 2


import socket
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate

def nmap_port_scan(target_ip, start_port=1, end_port=65535):
    """
    Perform a port scan using nmap and output results in a clean, indented format.
    """
    if not is_valid_ip(target_ip):
        print("[-] Invalid IP address. Please try again.")
        return

    print(f"\n[*] Running Nmap scan on {target_ip} (ports {start_port}-{end_port})...")
    nm = nmap.PortScanner()

    try:
        # Run the Nmap scan
        nm.scan(
            hosts=target_ip,
            ports=f"{start_port}-{end_port}",
            arguments='-sV -sC --open'
        )

        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"\n[+] Host {host} is up\n")
                for protocol in nm[host].all_protocols():
                    for port in nm[host][protocol]:
                        port_info = nm[host][protocol][port]
                        print(f"Port: {port}")
                        print(f"  - State: {port_info.get('state', 'unknown')}")
                        print(f"  - Service: {port_info.get('name', 'unknown')}")
                        version = port_info.get('product', '') + " " + port_info.get('version', '')
                        if version.strip():
                            print(f"    - Version: {version.strip()}")
                        extra_info = port_info.get('extrainfo', '').strip()
                        if extra_info:
                            print(f"    - Extra Information: {extra_info}")
                        script_output = port_info.get('script', {})
                        if script_output:
                            print("    - Script Output:")
                            for script_name, script_result in script_output.items():
                                print(f"      - {script_name}: {script_result}")
                        print("-" * 40)

    except nmap.PortScannerError as e:
        print(f"[-] Nmap error: {e}")
    except Exception as e:
        print(f"[-] An error occurred during the scan: {e}")

def enhanced_port_scan(target_ip, start_port=1, end_port=65535, max_threads=100):
    """
    Perform a multi-threaded port scan with enhanced service detection.
    """
    if not is_valid_ip(target_ip):
        print("[-] Invalid IP address. Please try again.")
        return []

    print(f"\n[*] Scanning ports {start_port}-{end_port} on {target_ip}...")
    open_ports = []

    def detect_service_version(sock, port):
        """
        Detect service and version by sending generic probes and analyzing responses.
        """
        try:
            # Send generic probes
            sock.sendall(b"\r\n")
            response = sock.recv(1024).decode(errors="ignore").strip()
            if response:
                return response
        except Exception:
            pass
        return "Open (no banner)"

    def scan_port(port):
        """
        Scan a single port and attempt to identify the service and version.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Adjusted timeout for detailed responses
                if sock.connect_ex((target_ip, port)) == 0:
                    service_info = detect_service_version(sock, port)
                    open_ports.append({"Port": port, "Service/Version": service_info})
        except Exception:
            pass

    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, port)

    if open_ports:
        print("\n[+] Port Scan Results with Enhanced Service Detection:")
        print(tabulate(open_ports, headers="keys", tablefmt="grid"))
    else:
        print("\n[-] No open ports found.")

    return open_ports



import os
import shutil
import sys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium import webdriver
import urllib.parse

def search_cve_nist_expanded_minimal(query, max_results=100, output_file="nist_cve_results_minimal.txt"):
    """
    Search for CVEs using the NIST RESTful API, display minimal results, and save them to a file.
    """
    print(f"\nSearching NIST CVE database for keyword: '{query}' (Fetching up to {max_results} results)...")

    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        encoded_query = urllib.parse.quote(query)
        results = []
        start_index = 0
        results_per_page = 50

        while len(results) < max_results:
            api_url = f"{base_url}?keywordSearch={encoded_query}&resultsPerPage={results_per_page}&startIndex={start_index}"
            response = requests.get(api_url)
            response.raise_for_status()
            cve_data = response.json()

            if "vulnerabilities" not in cve_data or not cve_data["vulnerabilities"]:
                break

            for item in cve_data["vulnerabilities"]:
                cve_id = item["cve"]["id"]
                description = item["cve"]["descriptions"][0]["value"]
                truncated_description = (description[:75] + "...") if len(description) > 75 else description

                severity = (
                    item.get("cve", {})
                    .get("metrics", {})
                    .get("cvssMetricV2", [{}])[0]
                    .get("baseSeverity", "N/A")
                )
                exploitability_score = (
                    item.get("cve", {})
                    .get("metrics", {})
                    .get("cvssMetricV2", [{}])[0]
                    .get("exploitabilityScore", "N/A")
                )
                cwe = (
                    item.get("cve", {})
                    .get("weaknesses", [{}])[0]
                    .get("description", [{}])[0]
                    .get("value", "N/A")
                )

                cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # Append results to the table
                results.append([
                    cve_id, severity, exploitability_score, cwe,
                    truncated_description, cve_id  # Shortened link for display
                ])

            start_index += results_per_page

            if len(results) >= max_results:
                results = results[:max_results]
                break

        if results:
            headers = ["CVE ID", "Severity", "Exploitability", "CWE", "Description", "Link"]
            print("\n" + tabulate(results, headers=headers, tablefmt="fancy_grid"))

            # Save detailed results to a file
            with open(output_file, "w", encoding="utf-8") as file:
                for row in results:
                    file.write("\t".join(str(x) for x in row[:-1]) + f" ({cve_url})\n")

            print(f"\n[+] Found {len(results)} CVEs. Displaying the first {len(results)} above.")
            print(f"[+] All results have been saved to {output_file}.")
        else:
            print("[-] No CVEs found for the given query.")

    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred while querying the NIST API: {e}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

# Reconify Shell
def reconify_shell():
    """
    Reconify interactive command-line interface.
    """
    banner = r"""
 /$$$$$$$                                          /$$  /$$$$$$          
| $$__  $$                                        |__/ /$$__  $$         
| $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$  /$$| $$  \__//$$   /$$
| $$$$$$$/ /$$__  $$ /$$_____/ /$$__  $$| $$__  $$| $$| $$$$   | $$  | $$
| $$__  $$| $$$$$$$$| $$      | $$  \ $$| $$  \ $$| $$| $$_/   | $$  | $$
| $$  \ $$| $$_____/| $$      | $$  | $$| $$  | $$| $$| $$     | $$  | $$
| $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$  | $$| $$| $$     |  $$$$$$$
|__/  |__/ \_______/ \_______/ \______/ |__/  |__/|__/|__/      \____  $$                                                                     
"""
    print(banner)
    print("Welcome to Reconify CLI. Type 'help' for a list of commands.\n")

    commands = {
        "ping": ping_sweep,
        "osdetect": os_detection,
        "portscan": nmap_port_scan,
        "cvesearch": search_cve_nist_expanded_minimal,
        "dirscan": dirscan,
        "exit": None,
    }

    while True:
        try:
            user_input = input("\nReconify> ").strip()
            if not user_input:
                continue

            parts = user_input.split(maxsplit=1)
            command = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []

            if command == "help":
                print("\nAvailable Commands:")
                print("\n INITIAL ENUMERATION")
                print("  ping <IP>                   Perform a ping sweep on the specified IP.")
                print("  osdetect <IP>               Perform OS detection based on TTL analysis.")
                print("  portscan <IP> <start> <end> Scan ports on the specified IP within a range.")
                print("                              Default is 1 to 65,535.")
                print("  cvesearch <query>           Search the NIST CVE database for a query.")
                print("\n WEB RECON")
                print("  dirscan <URL> <WORDLIST> [EXTENSIONS] Perform directory scanning with optional")
                print("                                        file extensions.")
                print("\n OTHER")
                print("  exit                        Exit the tool.")

            elif command in commands:
                if command == "exit":
                    print("Exiting Reconify. Goodbye!")
                    break
                elif command == "dirscan":
                    if args:
                        parts = args[0].split()
                        if len(parts) < 2:
                            print("Usage: dirscan <URL> <WORDLIST> [EXTENSIONS]")
                        else:
                            base_url = parts[0]
                            wordlist_path = parts[1]
                            extensions = parts[2:] if len(parts) > 2 else None
                            dirscan(base_url, wordlist_path, extensions)
                    else:
                        print("Usage: dirscan <URL> <WORDLIST> [EXTENSIONS]")
                else:
                    func = commands[command]
                    if len(args) == 1:
                        func(args[0])
                    else:
                        print(f"Invalid arguments for '{command}'. Type 'help' for usage.")
            else:
                print(f"Unknown command: {command}. Type 'help' for a list of commands.")
        except Exception as e:
            print(f"Error: {e}")


# Main Function
def main():
    reconify_shell()

if __name__ == "__main__":
    main()
